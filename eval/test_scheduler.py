"""Scheduler + supervisor tests (spec §40, §41, §51).

The important one is T3: a stop condition that has never fired is not a stop
condition, it is a hope. This drives the system to genuinely empty state and
asserts the loop STOPS — and drives it to non-empty state and asserts it does
NOT stop early, which is the failure that would end an overnight run while
useful work remains.

Runs against a sandboxed copy; never touches the real corpus.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

FAILURES: list[str] = []
PASSES = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name}  {detail}")


def sandbox() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="orch-sched-"))
    dest = tmp / "cyber"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        "quarantine", "*.tar.gz", "__pycache__", "state"))
    return dest


def main() -> int:
    root = sandbox()
    os.environ["WKS_ROOT"] = str(root)
    sys.path.insert(0, str(root))
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]
    from orch import dag, orchestrator, scheduler, store

    con = store.open_db()

    print("S1 a cycle runs every worker and records a checkpoint")
    c = scheduler.run_cycle(con, cycle=0)
    check("cycle ran five workers",
          all(k in c for k in ("maintenance", "triage", "research",
                               "validation", "audit")),
          str(list(c)))
    check("all workers succeeded",
          all(c[k]["ok"] for k in ("maintenance", "triage", "research",
                                   "validation", "audit")),
          str({k: c[k].get("error") for k in
               ("maintenance", "triage", "research", "validation", "audit")}))
    cp = store.load_checkpoint(con, "system", "scheduler")
    check("cycle checkpointed", cp is not None, "none")
    check("checkpoint names the last cycle",
          cp and cp.get("last_cycle") == 0, str(cp)[:160])

    print("\nS2 the stop condition refuses to stop while work remains")
    orchestrator.decompose(con, "learn xss", prefix="sched")
    sc = scheduler.has_useful_work(con)
    check("should_stop is False with ready work",
          not sc["should_stop"], str(sc))
    check("ready work is counted", sc["ready"] > 0, str(sc))
    # This used to assert `weakest_class is not None`, treating "a weak class
    # exists" as a guaranteed work source. It stopped being one when the corpus
    # reached 62/62 mature: every class clears the maturity bar, so there is no
    # weakest class and none should be invented to keep an assertion true.
    #
    # What still has to hold is the CONTROL property: the loop stays alive while
    # ANY work source exists. `ready` is one such source and it is non-zero
    # here, so the stop condition must be False regardless of whether any class
    # is weak.
    check("work keeps the loop alive with no weak class present",
          not sc["should_stop"],
          f'ready={sc["ready"]} weakest={sc["weakest_class"]}')

    print("\nS3 the stop condition DOES fire at genuinely empty state")
    # Remove every source of work: no tasks, no events, no findings, and no
    # weak classes. A stop condition that cannot fire is not a control.
    con.execute("DELETE FROM task")
    con.execute("DELETE FROM task_dep")
    con.execute("DELETE FROM event")
    con.execute("DELETE FROM finding")
    # Empty the class table so weakest_classes() returns nothing.
    # Child rows first: FKs are ON and correctly refuse to orphan knowledge.
    # Disabling the constraint to make this test pass would be exactly the
    # "weaken the gate until it stops complaining" move this system forbids.
    #
    # `item` is deleted, NOT `item_fts`. Deleting from an FTS5 external-content
    # virtual table directly corrupts its index ("database disk image is
    # malformed"); the shadow tables are maintained only by the schema's own
    # triggers, which fire on `item`. So the row delete is correct and the
    # index is left to be rebuilt afterwards.
    #
    # Children before parents, because foreign_keys=ON and the constraints are
    # correct: turning them off to make a test pass is the same move as
    # lowering a gate threshold until the failure stops being reported.
    #
    # THE DELETES RUN AS THE OWNER. MEASURED 2026-10-31: the runtime
    # ownership authorizer refused these statements, because `conflict`,
    # `chain`, `chain_step`, `chain_edge`, `fp_case`, `item`, `quality`,
    # `item_source` and `class_domain` are KNOWLEDGE tables and this
    # connection belongs to the orchestration layer. The refusal is the
    # correct outcome -- this test is reaching across the boundary to set up
    # an empty state, and it must do so with the knowledge OWNER's
    # authority, explicitly.
    from wks import ownership as _ownership
    with _ownership.owner_write(con, _ownership.WKS):
        for child in ("ab_result", "evidence", "conflict", "chain_edge",
                      "chain_step", "fp_case", "task", "item_source", "quality",
                      "item", "class_domain", "chain"):
            con.execute(f"DELETE FROM {child}")
        con.execute("DELETE FROM bug_class")
        con.commit()
    left = con.execute("SELECT count(*) n FROM bug_class").fetchone()["n"]
    check("bug_class emptied for the empty-state case", left == 0, str(left))
    # Prove the corpus is still readable after the deletes — a torn FTS index
    # would surface here as an exception rather than as a wrong number.
    try:
        from wks import retrieval
        retrieval.rebuild_index(con)
        con.execute("SELECT count(*) FROM item_fts").fetchone()
        fts_ok = True
        fts_detail = "index rebuilt and readable"
    except Exception as e:  # noqa: BLE001
        fts_ok, fts_detail = False, f"{type(e).__name__}: {e}"
    check("FTS index survives the deletes", fts_ok, fts_detail)
    sc2 = scheduler.has_useful_work(con)
    check("should_stop is True at empty state", sc2["should_stop"], str(sc2))
    check("no ready work remains", sc2["ready"] == 0, str(sc2))
    check("no weakest class remains", sc2["weakest_class"] is None, str(sc2))

    r = scheduler.supervise(con, max_cycles=5)
    check("supervisor stopped on the condition, not the budget",
          r["stopped_because"] == "stop_condition", str(r["stopped_because"]))
    check("it stopped after exactly one cycle", r["cycles_run"] == 1,
          str(r["cycles_run"]))

    print("\nS4 the supervisor does NOT stop early when work exists")
    # Rebuild a graph and confirm it keeps going.
    from orch import orchestrator as orch2
    orch2.decompose(con, "learn graphql", prefix="sched2")
    r2 = scheduler.supervise(con, max_cycles=3)
    check("supervisor used its whole budget with work pending",
          r2["stopped_because"] == "cycle_budget", str(r2["stopped_because"]))
    check("it ran every requested cycle", r2["cycles_run"] == 3,
          str(r2["cycles_run"]))

    print("\nS5 supervision is resumable")
    cp2 = store.load_checkpoint(con, "system", "supervisor")
    check("supervisor checkpoint written", cp2 is not None, "none")
    check("checkpoint records cycles completed",
          cp2 and cp2.get("cycles_completed") == 3, str(cp2)[:160])

    print("\nS6 a crashing worker is recorded, not swallowed")
    from orch import workers
    con.execute("UPDATE worker_heartbeat SET status='running'")
    # inject a worker that raises
    orig = workers._CYCLE_FNS["audit_cycle"]

    def boom(c):
        raise RuntimeError("simulated audit crash")

    workers._CYCLE_FNS["audit_cycle"] = boom
    try:
        res = workers.run_worker(con, "auditor")
    finally:
        workers._CYCLE_FNS["audit_cycle"] = orig
    check("crashing worker reports failure", not res["ok"], str(res))
    check("the error text survives", "simulated audit crash" in str(res.get("error")),
          str(res.get("error")))
    hb = {w["worker_key"]: w["status"] for w in store.workers(con)}
    check("heartbeat records the failure", hb.get("auditor") == "failed",
          str(hb))

    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"SCHEDULER: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"SCHEDULER: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())