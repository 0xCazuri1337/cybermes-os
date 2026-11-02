"""Scheduling and event-driven activation (spec §40, §41).

`orch/workers.py` declares WHICH workers exist and what cadence makes sense.
This module is the part that actually runs unattended, and it is deliberately
a small, resumable loop rather than a scheduler daemon:

  * No new process, no cron registration, no background thread that outlives
    the run. The system already runs inside Hermes; a second scheduler is a
    second thing to break at 04:00.
  * The loop is bounded by cycle count or wall-clock, and it checkpoints every
    cycle, so stopping it mid-flight resumes from the checkpoint instead of
    replaying the night.
  * Every cycle is heartbeat + checkpoint + re-audit. A cycle that does nothing
    still records that it did nothing.

A genuine stop condition (§51) ends the loop: no ready work AND no open events
AND nothing left to validate. Everything else continues.
"""
from __future__ import annotations

import sqlite3
import time
from datetime import datetime, timezone
from typing import Any

from . import agents, dag, events, orchestrator, priority, selfaudit, store, workers


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def has_useful_work(con: sqlite3.Connection) -> dict[str, Any]:
    """The stop condition, evaluated against live state.

    Every clause must be true simultaneously for the loop to stop. Reporting a
    stop while events are pending or findings are unvalidated is how an
    autonomous system declares victory over unfinished work.
    """
    dag.refresh_readiness(con)
    ready = len(dag.ready_tasks(con))
    open_ev = con.execute(
        "SELECT count(*) n FROM event WHERE state='new'").fetchone()["n"]
    # PRODUCTION FINDINGS ONLY.
    #
    # MEASURED 2026-11-01: this counted every finding with status
    # `candidate` or `validating`, and 44 of the live corpus's findings
    # were test output -- so the scheduler's stop condition was reading
    # test data as unvalidated work. A corpus full of test findings never
    # reached its stop condition.
    #
    # The filter is now the provenance filter, not the status filter. A
    # finding with UNKNOWN provenance does not count either: an origin
    # that could not be established is not unvalidated production work,
    # it is unclassified.
    unvalidated = store.unvalidated_production_count(con)
    in_flight = con.execute(
        "SELECT count(*) n FROM task WHERE status IN"
        " ('running','retrying')").fetchone()["n"]
    blocked = con.execute(
        "SELECT count(*) n FROM task WHERE status='blocked'").fetchone()["n"]
    weakest = priority.weakest_classes(con, limit=1)

    stop = (ready == 0 and open_ev == 0 and unvalidated == 0
            and in_flight == 0 and not weakest)
    return {
        "should_stop": stop,
        "ready": ready,
        "open_events": open_ev,
        "unvalidated_findings": unvalidated,
        "in_flight": in_flight,
        "blocked": blocked,
        "weakest_class": weakest[0]["class_id"] if weakest else None,
    }


def run_cycle(con: sqlite3.Connection, *, cycle: int = 0) -> dict[str, Any]:
    """One unattended iteration: maintain -> triage -> research -> validate ->
    audit -> checkpoint. The order is deliberate: maintenance first so the
    graph is trustworthy before anything decides what to work on."""
    started = _now()
    out: dict[str, Any] = {"cycle": cycle, "started_at": started}

    out["maintenance"] = workers.run_worker(con, "maintenance")
    out["triage"] = workers.run_worker(con, "watcher")
    # The stop condition is evaluated BEFORE the workers run, not after.
    #
    # Evaluating it afterwards meant the cycle could never stop: `auditor` and
    # `triage` open an event as part of doing their job, so by the time line 80
    # asked "is there work left?" the answer always included the event that very
    # cycle had just created. `open_events` then ratcheted up by one per cycle
    # and the supervisor burned its whole budget on an empty system.
    #
    # The state a cycle STARTS from is the state that decides whether it should
    # run at all. Anything the cycle itself creates is next cycle's business.
    out["stop_condition"] = has_useful_work(con)

    out["research"] = workers.run_worker(con, "research")
    out["validation"] = workers.run_worker(con, "validation")
    out["audit"] = workers.run_worker(con, "auditor")

    # Re-evaluated after the workers, so the caller can still see what the cycle
    # left behind, but it is not what decides `stopped_because`.
    out["stop_condition_after"] = has_useful_work(con)
    out["next_task"] = priority.next_task(con)
    out["graph"] = {k: v for k, v in dag.graph_report(con).items()
                    if k != "blocked_detail"}
    out["finished_at"] = _now()

    store.save_checkpoint(con, "system", "scheduler", {
        "last_cycle": cycle,
        "last_cycle_at": out["finished_at"],
        "stop_condition": out["stop_condition"],
        "next_task": out["next_task"],
    })
    # Same rule as workers.audit_cycle: a heartbeat below the action threshold
    # is closed immediately. Leaving it `new` makes open_events grow by one per
    # cycle, and open_events is part of the stop condition — so the loop would
    # be mathematically unable to ever stop.
    key = f"cycle:{out['finished_at']}"
    healthy = out["audit"]["result"]["health"] == "healthy"
    store.emit_event(
        con, key, "health", source="orch.scheduler",
        severity="info" if healthy else "warn",
        payload={"cycle": cycle, "health": out["audit"]["result"]["health"]},
        relevance=0.2 if healthy else 0.9)
    if healthy:
        con.execute("UPDATE event SET state='dismissed', acted_at=? "
                    "WHERE event_key=? AND state='new'", (_now(), key))
    con.commit()
    return out


def supervise(con: sqlite3.Connection, *, max_cycles: int = 5,
              sleep_seconds: int = 0, checkpoint_label: str = "supervisor"
              ) -> dict[str, Any]:
    """Run cycles until a stop condition or the cycle budget is spent.

    `sleep_seconds` is honoured but defaults to 0: a caller that wants pacing
    should schedule this rather than block a session on a sleep loop.
    """
    cycles: list[dict[str, Any]] = []
    stopped_because = "cycle_budget"
    start = time.time()

    for i in range(max_cycles):
        c = run_cycle(con, cycle=i)
        cycles.append(c)

        store.save_checkpoint(con, "system", checkpoint_label, {
            "cycles_completed": i + 1,
            "last": c,
            "elapsed_s": round(time.time() - start, 1),
        })

        if c["stop_condition"]["should_stop"]:
            stopped_because = "stop_condition"
            break
        if sleep_seconds and i < max_cycles - 1:
            time.sleep(sleep_seconds)
    else:
        stopped_because = "cycle_budget"

    final_audit = selfaudit.audit(con)
    return {
        "cycles_run": len(cycles),
        "stopped_because": stopped_because,
        "final_audit": {"health": final_audit["health"],
                        "passed": final_audit["passed"],
                        "total": final_audit["total"],
                        "failures": final_audit["failures"]},
        "stop_condition": cycles[-1]["stop_condition"] if cycles else None,
        "elapsed_s": round(time.time() - start, 1),
        "cycle_summaries": [
            {"cycle": c["cycle"],
             "health": c["audit"]["result"]["health"],
             "ready": c["stop_condition"]["ready"],
             "next": c["next_task"]["task_key"] if c["next_task"] else None}
            for c in cycles
        ],
    }


def next_signal(con: sqlite3.Connection, *, threshold: float = 0.5
                ) -> dict[str, Any] | None:
    """The highest-relevance unworked event, or None. The scheduler's view of
    'is there something new worth waking up for'."""
    pending = events.pending(con, threshold)
    return pending[0] if pending else None


def render_supervision(result: dict[str, Any]) -> str:
    lines = ["# SUPERVISED RUN", "",
             f"- cycles run      : {result['cycles_run']}",
             f"- stopped because : {result['stopped_because']}",
             f"- elapsed         : {result['elapsed_s']}s",
             f"- final health    : {result['final_audit']['health']} "
             f"({result['final_audit']['passed']}/{result['final_audit']['total']})",
             ""]
    sc = result.get("stop_condition") or {}
    if sc:
        lines += ["## Stop condition", f"- should_stop: {sc['should_stop']}",
                  f"- ready: {sc['ready']} | open events: {sc['open_events']}",
                  f"- unvalidated findings: {sc['unvalidated_findings']}",
                  f"- in flight: {sc['in_flight']} | blocked: {sc['blocked']}",
                  f"- weakest class: {sc['weakest_class']}", ""]
    lines += ["## Cycles"]
    for c in result.get("cycle_summaries", []):
        lines.append(f"- cycle {c['cycle']}: health={c['health']} "
                     f"ready={c['ready']} next={c['next']}")
    if result["final_audit"]["failures"]:
        lines += ["", "## Failures"]
        for f in result["final_audit"]["failures"]:
            lines.append(f"- {f['name']}: {f['detail']}")
    return "\n".join(lines)