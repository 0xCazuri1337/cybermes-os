"""The orchestrator: goal -> decomposable work -> executed waves -> next action.

This is the module that turns spec §58's eighteen required behaviours into
something executable rather than aspirational. It is deliberately thin: it owns
sequencing and bookkeeping, and delegates every decision it can to a module
that can be tested alone (dag for runnability, priority for ordering, agents
for dispatch, validate for gating).

Two properties matter more than features here:

  * Every iteration persists state BEFORE it acts, so a crash mid-wave resumes
    from a checkpoint instead of restarting and redoing work.
  * A run that accomplishes nothing still produces an artifact. "Nothing to do"
    and "never ran" must never look the same from the outside (invariants I10).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any, Callable

from wks import config as wks_config

from . import agents, dag, priority
from . import concurrency, store, validate

# The recovery ladder (spec §36). Each entry is a genuinely different strategy,
# in escalation order — never the same action repeated.
RECOVERY_LADDER = [
    "retry",
    "inspect_logs",
    "alt_method",
    "alt_tool",
    "delegate",
    "research",
    "decompose_further",
    "narrow_scope",
    "defer",
    "escalate",
]
RECOVERY_BUDGET = 10


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Goal decomposition (spec §4)
# ---------------------------------------------------------------------------

def decompose(con: sqlite3.Connection, goal: str, *,
              domain: str = "system", expected_artifact: str = "",
              evidence_req: str = "", prefix: str = "goal"
              ) -> list[str]:
    """Turn a goal into a dependency-aware task graph.

    Decomposition is rule-based and therefore inspectable, not clever. That is
    the correct trade for an unattended run: a decomposition nobody can explain
    cannot be corrected when it goes wrong at 04:00.
    """
    text = (goal or "").strip()
    if not text:
        raise ValueError("goal must not be empty")

    slug = "".join(c if c.isalnum() else "-" for c in text.lower())[:48].strip("-")
    steps = [
        ("audit", f"audit current state relevant to: {text}",
         "state/audit report naming what exists, works, is missing, is broken",
         "command output or query results"),
        ("build", f"build the missing capability for: {text}",
         expected_artifact or f"working implementation for {text}",
         evidence_req or "execution evidence that it runs"),
        ("test", f"test the capability built for: {text}",
         "test output with pass/fail per check", "test run output"),
        ("validate", f"independently validate: {text}",
         "validation vector L1-L6", "independent agent verdict"),
        ("report", f"report verified state of: {text}",
         "markdown report under state/", "report file path"),
    ]

    keys: list[str] = []
    prev: str | None = None
    for i, (kind, objective, artifact, evidence) in enumerate(steps, start=1):
        key = f"{prefix}.{slug}.{i}-{kind}"
        deps = [prev] if prev else []
        store.add_task(con, key, objective, priority=5, depends_on=deps,
                       expected_artifact=artifact, evidence_req=evidence)
        keys.append(key)
        prev = key
    con.commit()

    # Knowledge-gap decomposition: if the goal names a class, add a task to
    # close its evidence gap. This is what turns "learn XSS" into research work
    # rather than an audit that finds nothing and stops.
    gap_keys = []
    for cid in _classes_mentioned(con, text):
        k = f"{prefix}.{slug}.gap-{cid}"
        store.add_task(
            con, k,
            f"close the evidence gap for class {cid}",
            priority=3, class_id=cid,
            depends_on=[f"{prefix}.{slug}.1-audit"],
            expected_artifact=f"gated, cited items for class {cid}",
            evidence_req=">=2 distinct publisher hosts per promoted item")
        gap_keys.append(k)
    con.commit()
    dag.refresh_readiness(con)
    return keys + gap_keys


def _classes_mentioned(con: sqlite3.Connection, text: str) -> list[str]:
    """Map free text onto registered bug classes by name/alias match."""
    t = (text or "").lower()
    hits: list[str] = []
    for row in con.execute("SELECT id, name, aliases FROM bug_class"):
        terms = {row["id"].replace("_", " "), (row["name"] or "").lower()}
        if row["aliases"]:
            try:
                terms.update(a.lower() for a in json.loads(row["aliases"]))
            except (ValueError, TypeError):
                pass
        if any(term and term in t for term in terms):
            hits.append(row["id"])
    return sorted(set(hits))[:6]


# ---------------------------------------------------------------------------
# The loop (spec §8, §50)
# ---------------------------------------------------------------------------

def run(con: sqlite3.Connection, *,
        executor: Callable[[sqlite3.Row, dict], dict] | None = None,
        max_tasks: int = 25, max_waves: int = 10,
        checkpoint_scope: str = "system",
        checkpoint_label: str = "overnight",
        task_filter: Callable[[sqlite3.Row], bool] | None = None) -> dict[str, Any]:
    """Execute ready work until a stop condition. `executor` performs the work;
    without one this only advances the graph, which is how the loop stays
    testable and how a missing executor cannot be mistaken for a completed task.

    `task_filter` scopes execution to a subset of the backlog. Without it a run
    will execute whatever the priority engine ranks highest — correct in
    production, wrong in a test that means to prove one specific task ran.
    """
    started = _now()
    store.migrate_tasks(con)

    # Recover claims orphaned by a previous crash before doing anything else,
    # otherwise this run refuses to schedule work it could legitimately do.
    orphans = store.orphan_recovery(con)

    cycles = dag.break_cycles(con)
    executed: list[dict[str, Any]] = []
    caps: list[dict[str, Any]] = []
    stop_reason = "task_budget"

    for wave_no in range(max_waves):
        dag.refresh_readiness(con)
        pending = priority.rank(con)
        if task_filter is not None:
            rows = {r["task_key"]: r for r in store.all_tasks(con)}
            pending = [t for t in pending
                       if task_filter(rows.get(t["task_key"]))]
        if not pending:
            stop_reason = ("no_ready_tasks" if wave_no else "nothing_to_do")
            break

        # Run the top-parallelism slice of what is ranked highest. Taking the
        # global top-N ignores the DAG's own notion of concurrency and starves
        # everything below the cut.
        waves = dag.parallel_waves(con)
        top_wave = set(waves[0]) if waves else set()
        wave = [t for t in pending if t["task_key"] in top_wave] or pending

        # MEASURED (audit 2026-10-02): the "waves of 2" limit existed only in
        # CONTROL/OPERATOR.md. `grep -rn "waves of 2" --include=*.py` returned
        # zero hits, so nothing enforced it and any agent or plugin that had
        # not read the doc could overshoot silently. It is now a bound in the
        # execution path, and the deferred tasks are REPORTED rather than
        # dropped, so a cap never looks like a completed wave.
        wave_full = wave[:max_tasks]
        wave = concurrency.cap(wave_full)
        deferred = concurrency.dropped(wave_full)
        if deferred:
            caps.append({"wave": wave_no, "deferred": [t["task_key"] for t in deferred]})

        store.save_checkpoint(con, checkpoint_scope, checkpoint_label, {
            "wave": wave_no, "started_at": started,
            "queued": [t["task_key"] for t in wave],
            "executed": [e["task_key"] for e in executed],
        })

        for entry in wave:
            if len(executed) >= max_tasks:
                stop_reason = "task_budget"
                break
            row = store.get_task(con, entry["task_key"])
            if not row:
                continue
            executed.append(_execute_one(con, row, executor, len(wave)))

        dag.refresh_readiness(con)
        if len(executed) >= max_tasks:
            stop_reason = "task_budget"
            break
    else:
        stop_reason = "wave_budget"

    report = {
        "started_at": started,
        "finished_at": _now(),
        "executed": executed,
        "orphans_recovered": orphans["recovered"],
        "cycles_repaired": cycles["fixed"],
        "graph": dag.graph_report(con),
        "stop_reason": stop_reason,
        "concurrency": {**concurrency.describe(), "capped_waves": caps},
        "stats": agents.run_stats(con),
    }
    store.save_checkpoint(con, checkpoint_scope, checkpoint_label, report)
    return report


def _execute_one(con: sqlite3.Connection, row: sqlite3.Row,
                 executor: Callable[[sqlite3.Row, dict], dict] | None,
                 wave_size: int = 1) -> dict[str, Any]:
    task_key = row["task_key"]
    run_key = f"run-{task_key}"

    # Second, independent enforcement point. `run()` already caps the wave;
    # this refuses to execute inside an over-cap wave even if that call site is
    # refactored. A limit enforced at exactly one place is one refactor away
    # from being decorative.
    allowed = concurrency.budget()
    if wave_size > allowed:
        return {"task_key": task_key, "status": "capped",
                "detail": (f"wave of {wave_size} exceeds the "
                           f"{allowed}-task cap ({concurrency.ENV_VAR}); "
                           f"task left {row['status']!r} for the next wave")}

    if executor is None:
        # No executor means no work happened. Marking the task done here would
        # be the single most damaging lie this system could tell.
        store.set_status(con, task_key, "running",
                         result="dispatched but no executor bound")
        return {"task_key": task_key, "status": "no_executor",
                "detail": "no executor bound; task left running, not completed"}

    con.execute(
        "INSERT OR IGNORE INTO agent_role(role_key, domain, capabilities,"
        " max_depth, rationale, created_at) VALUES ('executor','system',?,1,?,?)",
        (json.dumps(["READ", "ANALYZE", "WRITE"]),
         "default executor for autonomous work", _now()))
    con.commit()

    dis = agents.dispatch(con, run_key, "executor", row["objective"],
                          task_key=task_key)
    if not dis.get("dispatched"):
        # A refused claim is usually NOT a failure: `pending` was computed once
        # at the top of the wave, so a task listed there may have been claimed
        # or completed by an earlier task in the SAME wave (or a concurrent
        # run) before we reached it. Reporting that as `failed` is a false
        # negative — it was reproduced as a task that was really `superseded`
        # with a valid artifact being printed as FAIL.
        current = store.get_task(con, task_key)
        now_status = current["status"] if current else "gone"
        if now_status in store.TERMINAL_STATES:
            return {"task_key": task_key, "status": "already_done",
                    "detail": (f"already {now_status} when reached; the wave "
                               f"listing was stale, not a failure")}
        return {"task_key": task_key, "status": "not_dispatched",
                "detail": dis.get("reason")}

    try:
        result = executor(row, {"run_key": run_key, "task_key": task_key})
    except Exception as e:  # noqa: BLE001 - a crashing executor is data, not a bug
        result = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    out = agents.complete_run(con, run_key, result, task_key=task_key)
    return {"task_key": task_key, "status": "completed" if out.get("ok")
            else "failed", "gate": out.get("gate"),
            "detail": result.get("summary") or result.get("error")}


# ---------------------------------------------------------------------------
# Event-driven activation (spec §41)
# ---------------------------------------------------------------------------

RELEVANCE_THRESHOLD = 0.5


def triage_events(con: sqlite3.Connection, *,
                  threshold: float = RELEVANCE_THRESHOLD,
                  limit: int = 25) -> dict[str, Any]:
    """Turn relevant events into work; dismiss the rest with a recorded reason.

    Every event ends in exactly one of `worked` / `dismissed`, so the event
    table cannot accumulate a backlog that silently grows forever.
    """
    events = store.open_events(con, min_relevance=0.0, limit=limit)
    worked, dismissed = [], []
    for ev in events:
        # CLAIM FIRST, then act. The claim is a conditional UPDATE, so two
        # concurrent orchestrators produce exactly one winner per event --
        # MEASURED 2026-10-31: reading the events and updating them in
        # separate statements let two orchestrators both act on the same
        # signal and create two tasks for it.
        if not store.claim_event(con, ev["id"]):
            continue        # another consumer took it
        if ev["relevance"] < threshold:
            store.finish_event(con, ev["id"], "dismissed")
            dismissed.append({"event_key": ev["event_key"],
                              "relevance": ev["relevance"],
                              "reason": "below relevance threshold"})
            continue
        key = f"event.{ev['event_key']}"
        store.add_task(
            con, key,
            f"respond to {ev['kind']} signal from {ev['source'] or 'unknown'}",
            priority=2,
            expected_artifact=f"decision + evidence for {ev['event_key']}",
            evidence_req="relevance analysis recorded against the signal")
        store.finish_event(con, ev["id"], "worked", created_task=key)
        worked.append({"event_key": ev["event_key"], "task": key})
    con.commit()
    return {"worked": worked, "dismissed": dismissed,
            "threshold": threshold, "considered": len(events)}


def watch(con: sqlite3.Connection, signals: list[dict[str, Any]]
          ) -> dict[str, Any]:
    """HermesWatcher intake (spec §42): signal -> relevance -> event.

    `signals` are already-fetched observations. This module does no network I/O
    on its own: raw community claims must be treated as leads, and keeping the
    fetch outside makes that boundary structural rather than a convention.
    """
    accepted, rejected = 0, 0
    for s in signals:
        key = s.get("event_key")
        if not key:
            rejected += 1
            continue
        # A raw social claim is capped below the action threshold no matter how
        # confident it sounds.
        rel = float(s.get("relevance", 0.0))
        if (s.get("source_type") or "") == "social":
            rel = min(rel, 0.4)
        if store.emit_event(con, key, s.get("kind", "signal"),
                           source=s.get("source", ""),
                           severity=s.get("severity", "info"),
                           payload=s, relevance=rel):
            accepted += 1
        else:
            rejected += 1
    return {"accepted": accepted, "rejected_duplicate_or_malformed": rejected}


# ---------------------------------------------------------------------------
# Overnight entry point (spec §50)
# ---------------------------------------------------------------------------

def overnight(con: sqlite3.Connection, executor=None, *, max_tasks: int = 25,
              task_filter=None) -> dict[str, Any]:
    """One full autonomous iteration, then an automatic re-audit.

    The re-audit is the point: finishing a planned list is explicitly not a
    stop condition, so the loop immediately looks for the next valuable task.
    """
    cycle1 = run(con, executor=executor, max_tasks=max_tasks,
                 task_filter=task_filter)
    audit = self_audit(con)
    nxt = priority.weakest_classes(con, limit=5)
    nxt_task = priority.next_task(con)
    return {
        "cycle": cycle1,
        "re_audit": audit,
        "weakest_classes": nxt,
        "next_task": nxt_task,
        "continue_work": bool(nxt_task) or audit["health"] != "healthy",
    }


def self_audit(con: sqlite3.Connection) -> dict[str, Any]:
    """Structural + functional + behavioural audit (spec §43).

    Structural checks are cheap and always run. Functional checks EXECUTE the
    components; a health claim in this system must never rest on files merely
    existing (spec §52).
    """
    from . import selfaudit
    return selfaudit.audit(con)


def write_report(con: sqlite3.Connection, report: dict[str, Any],
                 name: str = "orchestrator") -> str:
    out = wks_config.runtime_dir() /  f"{name}-{_now().replace(':', '')}.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"# Orchestrator report {_now()}", "",
             f"- stop reason: `{report.get('stop_reason')}`",
             f"- executed: {len(report.get('executed', []))}",
             f"- cycles repaired: {len(report.get('cycles_repaired', []))}", ""]
    g = report.get("graph", {})
    lines += ["## Graph", f"- nodes: {g.get('nodes')} edges: {g.get('edges')} "
              f"ready: {g.get('ready')} cycles: {len(g.get('cycles', []))}",
              f"- by status: {g.get('by_status')}", ""]
    lines.append("## Executed")
    for e in report.get("executed", []):
        lines.append(f"- `{e['task_key']}` -> {e['status']}"
                     + (f" ({e.get('detail')})" if e.get("detail") else ""))
    out.write_text("\n".join(lines), encoding="utf-8")
    return str(out)