"""Background workers (spec §39) and event intake helpers.

A worker is a named, heart-beating loop that writes results into the shared
structured state. It is deliberately NOT a thread pool: the point is that a
worker's output is observable by the orchestrator even when the orchestrator
is not running, and that a crashed worker's last cycle is visible rather than
inferred from silence.

`run_workers` executes each worker once (a cycle), which is what makes it
testable and schedulable. Long-running behaviour comes from being invoked
repeatedly by a scheduler, not from hiding a sleep loop in here — a sleep loop
cannot be observed, cannot be checkpointed, and cannot be unit tested.
"""
from __future__ import annotations

import sqlite3
from typing import Any, Callable

from . import dag, orchestrator, priority, selfaudit, store, validate

# Each worker declares what it does and which domain it serves. Registered
# rather than hard-coded as call sites so a new worker is data, not a branch.
WORKERS: dict[str, dict[str, Any]] = {
    "maintenance": {
        "fn": "maintenance_cycle",
        "domain": "system",
        "desc": "refresh readiness, repair cycles, reorder the backlog",
    },
    "research": {
        "fn": "research_cycle",
        "domain": "research",
        "desc": "turn the weakest classes into ranked research tasks",
    },
    "validation": {
        "fn": "validation_cycle",
        "domain": "validation",
        "desc": "revalidate open findings and collapse duplicates",
    },
    "watcher": {
        "fn": "watcher_cycle",
        "domain": "research",
        "desc": "triage inbound signals into work",
    },
    "auditor": {
        "fn": "audit_cycle",
        "domain": "system",
        "desc": "run the self-audit and report health",
    },
}


def maintenance_cycle(con: sqlite3.Connection) -> dict[str, Any]:
    """Keep the graph honest. Cheap, idempotent, and safe to run often."""
    cycles = dag.break_cycles(con)
    ready = dag.refresh_readiness(con)
    reordered = priority.reorder_tasks(con)
    return {"cycles_repaired": len(cycles["fixed"]), "readiness": ready,
            "backlog_reordered": reordered,
            "graph": dag.graph_report(con)}


def research_cycle(con: sqlite3.Connection, limit: int = 5) -> dict[str, Any]:
    """Create research tasks for the classes the gate says are weakest.

    Reads the gate's own verdict rather than a local opinion, so the research
    queue cannot disagree with the quality engine.
    """
    weak = priority.weakest_classes(con, limit=limit)
    created = []
    for w in weak:
        cid = w["class_id"]
        key = f"research.{cid}"
        store.add_task(
            con, key,
            f"research and gate evidence for class {cid} "
            f"(currently {w['n_items']} promoted item(s))",
            priority=2, class_id=cid,
            expected_artifact=f">=2 gated items for {cid}, each cited to "
                              f">=2 distinct publisher hosts",
            evidence_req="verbatim quote verified against the live source")
        created.append(key)
    con.commit()
    dag.refresh_readiness(con)
    return {"weak_classes": [w["class_id"] for w in weak], "tasks": created}


def validation_cycle(con: sqlite3.Connection) -> dict[str, Any]:
    """Revalidate candidates, dedup, and turn false positives into lessons."""
    revalidated = []
    for f in store.findings(con, "candidate"):
        v = validate.validate_finding(con, f["finding_key"])
        validate.apply_validation(con, f["finding_key"], v)
        revalidated.append({"finding_key": f["finding_key"],
                            "verdict": v["verdict"], "score": v["score"]})
    dedup = validate.dedupe(con)
    return {"revalidated": revalidated, "dedup": dedup}


def watcher_cycle(con: sqlite3.Connection) -> dict[str, Any]:
    """Turn open events into work, or explicitly dismiss them."""
    return orchestrator.triage_events(con)


def audit_cycle(con: sqlite3.Connection) -> dict[str, Any]:
    result = selfaudit.audit(con)
    key = f"audit:{result['audited_at']}"
    store.emit_event(
        con, key, "health", source="orch.selfaudit",
        severity="info" if result["health"] == "healthy" else "warn",
        payload={"health": result["health"], "failed": result["failed"]},
        relevance=0.9 if result["health"] != "healthy" else 0.1)

    # A healthy heartbeat is not a signal. It must be closed out here, because
    # an event left in `new` is counted by the stop condition — which means a
    # system that audits every cycle accumulates one un-triaged event per cycle
    # and can NEVER decide it is done. It stops itself forever on its own
    # bookkeeping. Caught by eval/test_scheduler.py S3.
    row = con.execute("SELECT id, relevance, state FROM event WHERE event_key=?",
                      (key,)).fetchone()
    if row and row["state"] == "new" and row["relevance"] < 0.5:
        # CLAIM before dismissing, so a concurrent triage cannot also act on
        # this event. `finish_event` is conditional on the event still being
        # `triaged`, so only the claimant can record the outcome.
        if store.claim_event(con, row["id"]):
            store.finish_event(con, row["id"], "dismissed")
    return result


_CYCLE_FNS: dict[str, Callable[[sqlite3.Connection], dict]] = {
    "maintenance_cycle": maintenance_cycle,
    "research_cycle": research_cycle,
    "validation_cycle": validation_cycle,
    "watcher_cycle": watcher_cycle,
    "audit_cycle": audit_cycle,
}


def run_worker(con: sqlite3.Connection, worker_key: str) -> dict[str, Any]:
    """Run one worker cycle with heartbeat before and after.

    The status is recorded even on failure: a worker that stops heart-beating
    is indistinguishable from one that is merely idle, and only an explicit
    `failed` row tells the orchestrator to re-dispatch it.
    """
    spec = WORKERS.get(worker_key)
    if not spec:
        return {"worker": worker_key, "ok": False,
                "error": f"unknown worker {worker_key!r}"}
    fn = _CYCLE_FNS[spec["fn"]]
    store.beat(con, worker_key, spec["domain"], "running")
    try:
        out = fn(con)
        store.beat(con, worker_key, spec["domain"], "idle",
                   result=str(out)[:400], bump=True)
        return {"worker": worker_key, "ok": True, "result": out}
    except Exception as e:  # noqa: BLE001
        store.beat(con, worker_key, spec["domain"], "failed",
                   result=f"{type(e).__name__}: {e}", bump=True)
        return {"worker": worker_key, "ok": False,
                "error": f"{type(e).__name__}: {e}"}


def run_all(con: sqlite3.Connection, workers: list[str] | None = None
            ) -> dict[str, Any]:
    names = workers or list(WORKERS.keys())
    out = {}
    for n in names:
        out[n] = run_worker(con, n)
    return out


def heartbeat_report(con: sqlite3.Connection) -> dict[str, Any]:
    rows = store.workers(con)
    return {
        "workers": [
            {"worker_key": r["worker_key"], "kind": r["kind"],
             "status": r["status"], "cycle": r["cycle"],
             "last_beat": r["last_beat"]}
            for r in rows
        ],
        "stale": [r["worker_key"] for r in rows
                  if r["status"] == "failed"],
    }


def schedule(con: sqlite3.Connection) -> list[dict[str, Any]]:
    """The intended overnight cadence, as data.

    Not executed by a hidden timer: an autonomous system that only runs while
    someone is watching is not autonomous. This returns the plan, and the
    caller (a real scheduler) decides when to act.
    """
    return [
        {"worker": "maintenance", "every_minutes": 15,
         "why": "graph stays consistent between long tasks"},
        {"worker": "watcher", "every_minutes": 60,
         "why": "signals are time-sensitive"},
        {"worker": "research", "every_minutes": 120,
         "why": "research is network-bound; batching reduces fetch churn"},
        {"worker": "validation", "every_minutes": 60,
         "why": "findings should not sit unvalidated"},
        {"worker": "auditor", "every_minutes": 180,
         "why": "health drift is the failure that hides longest"},
    ]