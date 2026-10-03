"""Spine test: store, DAG, priority, validation.

Run against a TEMPORARY database so it cannot mutate the real corpus, and so a
pass cannot be produced by pre-existing rows. Every check is written to be able
to FAIL — memory records a verifier that was correct, tested, and never called,
which passed as loudly as a broken one.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

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


def fresh_db() -> sqlite3.Connection:
    """A throwaway db with the orchestration schema. Uses open_db's script so the
    test exercises the real DDL rather than a copy of it."""
    tmp = Path(tempfile.mkdtemp()) / "test.db"
    os.environ["WKS_ROOT"] = str(ROOT)
    from orch import store
    real = store.db_path
    store.db_path = lambda: tmp  # type: ignore[assignment]
    try:
        con = store.open_db(create=True)
    finally:
        store.db_path = real  # type: ignore[assignment]
    return con


def t_schema() -> None:
    print("O1 the orchestration schema exists")
    con = fresh_db()
    have = {r["name"] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    for t in ("task_dep", "agent_role", "agent_run", "capability_grant",
              "scope_grant", "evidence", "finding", "event",
              "worker_heartbeat", "checkpoint", "ab_experiment", "ab_result",
              "recovery_attempt"):
        check(f"table {t} exists", t in have, "missing from sqlite_master")
    con.close()


def t_dag() -> None:
    print("O2 the DAG derives runnability from edges")
    con = fresh_db()
    from orch import dag, store

    store.add_task(con, "a", "root task")
    store.add_task(con, "b", "needs a", depends_on=["a"])
    store.add_task(con, "c", "needs b", depends_on=["b"])
    con.commit()

    dag.refresh_readiness(con)
    a = store.get_task(con, "a")["status"]
    b = store.get_task(con, "b")["status"]
    c = store.get_task(con, "c")["status"]
    check("a with no deps is ready", a == "ready", f"got {a}")
    check("b with unmet dep is NOT ready", b == "planned", f"got {b}")
    check("c with unmet dep is NOT ready", c == "planned", f"got {c}")

    store.set_status(con, "a", "completed")
    dag.refresh_readiness(con)
    check("completing a makes b ready",
          store.get_task(con, "b")["status"] == "ready",
          f"got {store.get_task(con, 'b')['status']}")

    waves = dag.parallel_waves(con)
    check("waves separate independent work", len(waves) >= 1, str(waves))

    # a failed dependency must NOT silently unblock its dependents
    con2 = fresh_db()
    store.add_task(con2, "x", "root")
    store.add_task(con2, "y", "needs x", depends_on=["x"])
    store.set_status(con2, "x", "failed")
    dag.refresh_readiness(con2)
    check("failed dep blocks dependent, does not unblock it",
          store.get_task(con2, "y")["status"] == "blocked",
          f"got {store.get_status if False else store.get_task(con2,'y')['status']}")
    con2.close()
    con.close()


def t_cycle() -> None:
    print("O3 cycles are detected and broken, not silently stalled")
    con = fresh_db()
    from orch import dag, store
    store.add_task(con, "p", "p")
    store.add_task(con, "q", "q", depends_on=["p"])
    store.add_task(con, "r", "r", depends_on=["q"])
    con.execute("INSERT OR IGNORE INTO task_dep(task_key, depends_on)"
                " VALUES ('p','r')")  # close the loop
    con.commit()
    cyc = dag.find_cycles(con)
    check("cycle is found", len(cyc) >= 1, f"got {cyc}")
    fixed = dag.break_cycles(con)
    check("break_cycles leaves an acyclic graph",
          len(fixed["remaining_cycles"]) == 0,
          str(fixed["remaining_cycles"]))
    con.close()


def t_dangling() -> None:
    print("O4 dangling dependencies are reported, not silently dropped")
    con = fresh_db()
    from orch import dag, store
    store.add_task(con, "live", "live task")
    con.execute("INSERT INTO task_dep(task_key, depends_on)"
                " VALUES ('live','ghost')")
    con.commit()
    bad = dag.missing_deps(con)
    check("missing dep is named", "live" in bad, str(bad))
    con.close()


def t_priority() -> None:
    print("O5 priority ranking is explainable and orders real work")
    con = fresh_db()
    from orch import priority, store
    store.add_task(con, "blocker", "build the capability that gates others",
                   priority=5)
    for i in range(3):
        store.add_task(con, f"leaf{i}", f"leaf task {i}", priority=5,
                       depends_on=["blocker"])
    con.commit()
    # blocker gates 3 tasks; leaves gate none
    from orch import dag
    dag.refresh_readiness(con)
    r = priority.rank(con)
    check("ranking is non-empty", len(r) == 1, str(r))
    top = r[0]
    check("the gating task ranks first", top["task_key"] == "blocker",
          f"got {top['task_key']}")
    check("score is a real number", isinstance(top["score"], float)
          and 0.0 <= top["score"] <= 1.0, str(top["score"]))
    expl = priority.explain(con, "blocker")
    check("explain() names the weighting", "unblocks" in expl, expl[:80])
    con.close()


def t_scope() -> None:
    print("O6 scope denies by default (spec 25)")
    con = fresh_db()
    from orch import store
    r = store.check_scope(con, "public-endpoint.example.com")
    check("unlisted target is NOT authorized", not r["authorized"], str(r))
    check("denial states a reason", bool(r.get("reason")), str(r))

    store.grant_scope(con, "s1", "lab.local", "lab", "local lab 1",
                      offensive_allowed=True)
    r2 = store.check_scope(con, "lab.local")
    check("granted lab is authorized", r2["authorized"], str(r2))
    check("grant carries offensive permission", r2["offensive_allowed"], str(r2))

    store.grant_scope(con, "s2", "old.example", "bugbounty", "prog",
                      expires_at="2000-01-01T00:00:00+00:00")
    r3 = store.check_scope(con, "old.example")
    check("expired grant does not authorize", not r3["authorized"], str(r3))
    con.close()


def t_validation() -> None:
    print("O7 validation L1-L6, and independence can actually fail")
    con = fresh_db()
    from orch import store, validate

    store.add_finding(con, "f1", "IDOR on orders endpoint",
                      target="t", asset="a", endpoint="/api/orders/{id}",
                      hypothesis="any authenticated user can read another "
                                 "user's order by changing the id",
                      severity="high")
    fid = con.execute("SELECT id FROM finding WHERE finding_key='f1'"
                      ).fetchone()["id"]
    store.add_evidence(con, "request", finding_id=fid,
                       request_raw="GET /api/orders/2", response_raw="200 ok",
                       provenance="manual")

    v = validate.validate_finding(con, "f1")
    check("L1 passes on a well-formed record",
          v["results"]["L1"]["passed"], v["results"]["L1"]["detail"])
    check("L2 passes on a falsifiable claim",
          v["results"]["L2"]["passed"], v["results"]["L2"]["detail"])
    check("L3 FAILS with no reproduction recorded",
          not v["results"]["L3"]["passed"], "unproven must not pass")
    check("L5 passes with substantive evidence",
          v["results"]["L5"]["passed"], v["results"]["L5"]["detail"])
    check("not reportable while L3 unproven", not v["reportable"], str(v))

    # independence must FAIL when validator == claimant
    v_bad = validate.validate_finding(con, "f1", claimant_run="run-1",
                                      validator_run="run-1")
    check("L4 FAILS when validator is the claimant",
          not v_bad["results"]["L4"]["passed"], v_bad["results"]["L4"]["detail"])

    v_good = validate.validate_finding(con, "f1", reproduced=True,
                                       claimant_run="run-1",
                                       validator_run="run-2",
                                       rep_detail="replayed, 200 with other "
                                                  "user's data")
    check("L4 passes with a genuinely different validator",
          v_good["results"]["L4"]["passed"], v_good["results"]["L4"]["detail"])
    check("fully validated verdict reached",
          v_good["validated"], str(v_good["levels_failed"]))

    # a finding with no evidence must fail L5
    store.add_finding(con, "f2", "empty claim", target="t",
                      hypothesis="x" * 40, severity="low")
    v2 = validate.validate_finding(con, "f2")
    check("L5 FAILS with zero evidence",
          not v2["results"]["L5"]["passed"], v2["results"]["L5"]["detail"])
    con.close()


def t_dedupe() -> None:
    print("O8 dedup merges without discarding evidence")
    con = fresh_db()
    from orch import store, validate
    fid_a = store.add_finding(con, "fa", "IDOR /api/orders", target="t",
                              endpoint="/api/orders", dedup_group="g1",
                              hypothesis="cross-user read of orders")
    fid_b = store.add_finding(con, "fb", "BOLA on orders (same bug)",
                              target="t", endpoint="/api/orders",
                              dedup_group="g1",
                              hypothesis="cross-user read of orders")
    store.add_evidence(con, "response", finding_id=fid_a,
                       response_raw="A-body", provenance="agent-1")
    store.add_evidence(con, "response", finding_id=fid_b,
                       response_raw="B-body", provenance="agent-2")
    res = validate.dedupe(con)
    check("one group merged", res["groups_merged"] == 1, str(res))
    b = con.execute("SELECT status, canonical_id FROM finding"
                    " WHERE finding_key='fb'").fetchone()
    check("duplicate is linked, not deleted", b["status"] == "duplicate"
          and b["canonical_id"] == fid_a, str(dict(b)))
    n = con.execute("SELECT count(*) n FROM evidence WHERE finding_id=?",
                    (fid_a,)).fetchone()["n"]
    check("evidence from both is preserved on canonical", n == 2, f"got {n}")
    con.close()


def t_fp_learning() -> None:
    print("O9 a false positive becomes a durable lesson")
    con = fresh_db()
    from orch import store, validate

    # An unattributable lesson is worse than none: it would later be cited as
    # evidence of experience. The guard must be able to fail.
    try:
        validate.false_positive(con, "ghost", invalidated_by="x",
                                early_signal_missed="y", rejection_rule="z")
        check("unknown finding is refused", False, "no error raised")
    except KeyError:
        check("unknown finding is refused", True)
    check("refusal wrote no rule",
          con.execute("SELECT count(*) n FROM fp_case").fetchone()["n"] == 0)

    store.add_finding(con, "real", "reflected input in shared cache",
                      target="t", endpoint="/x",
                      hypothesis="payload reflects into a cached response")
    # fp_case.class_id is a real FK, so the lesson must attach to a registered
    # class. An unregistered one is refused loudly, not silently dropped.
    try:
        validate.false_positive(con, "real", invalidated_by="x",
                                early_signal_missed="y",
                                rejection_rule="unregistered class rule",
                                class_id="not_a_real_class")
        check("unregistered class is refused", False, "no error raised")
    except KeyError:
        check("unregistered class is refused", True)

    # seed a real class, then the lesson must persist
    from wks import store as wstore
    wstore.upsert_class(con, "xss", "XSS", "web")
    con.commit()
    validate.false_positive(con, "real",
                            invalidated_by="reflected only in the shared cache",
                            early_signal_missed="did not check cache headers",
                            rejection_rule="a reflected string in a shared "
                                           "cache is not a finding",
                            class_id="xss")
    row = con.execute("SELECT * FROM fp_case WHERE rejection_rule LIKE"
                      " '%shared cache%'").fetchone()
    check("fp_case row written", row is not None, "no row")
    check("rejection rule is stored verbatim",
          row is not None and "shared cache" in row["rejection_rule"],
          str(dict(row)) if row else "no row")
    check("refused rule was NOT persisted",
          con.execute("SELECT count(*) n FROM fp_case WHERE"
                      " rejection_rule='unregistered class rule'"
                      ).fetchone()["n"] == 0)
    check("finding marked false_positive", con.execute(
        "SELECT status FROM finding WHERE finding_key='real'"
    ).fetchone()["status"] == "false_positive")
    con.close()


def t_checkpoint() -> None:
    print("O10 checkpoints survive a reopen (spec 37/49)")
    con = fresh_db()
    from orch import store
    store.save_checkpoint(con, "project", "overnight", {"step": 7,
                                                        "cursor": "xss"})
    back = store.load_checkpoint(con, "project", "overnight")
    check("state round-trips", back and back["step"] == 7, str(back))
    store.save_checkpoint(con, "project", "overnight", {"step": 8})
    again = store.load_checkpoint(con, "project", "overnight")
    check("checkpoint overwrites in place", again["step"] == 8, str(again))
    check("only one checkpoint row survives",
          con.execute("SELECT count(*) n FROM checkpoint").fetchone()["n"] == 1)
    con.close()


def t_recovery() -> None:
    print("O11 recovery attempts are counted, so 'blocked' is earned")
    con = fresh_db()
    from orch import store
    for i in range(1, 4):
        store.record_recovery(con, "t1", i, "alt_method", "failed",
                              f"attempt {i}")
    check("three attempts recorded", store.recovery_count(con, "t1") == 3)
    check("budget is readable", store.recovery_count(con, "nope") == 0)
    con.close()


def t_events() -> None:
    print("O12 events are idempotent by key")
    con = fresh_db()
    from orch import store
    first = store.emit_event(con, "cve-2026-1", "cve", source="nvd",
                             relevance=0.8)
    second = store.emit_event(con, "cve-2026-1", "cve", source="nvd",
                              relevance=0.8)
    check("first emit creates", first, "returned False")
    check("duplicate signal is NOT a second event", not second, "returned True")
    check("exactly one row", con.execute(
        "SELECT count(*) n FROM event").fetchone()["n"] == 1)
    con.close()


def main() -> int:
    for t in (t_schema, t_dag, t_cycle, t_dangling, t_priority, t_scope,
              t_validation, t_dedupe, t_fp_learning, t_checkpoint,
              t_recovery, t_events):
        t()
    print()
    if FAILURES:
        print(f"ORCH SPINE: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"ORCH SPINE: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())