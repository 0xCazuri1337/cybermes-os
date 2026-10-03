"""Regressions for the adversarial review's structural findings.

Each test here reproduces a defect an independent validator found BY EXECUTION
while all 105 of my own checks were green. That is the point of this file: my
suite was green and the system was still wrong, so these cases are written to
fail against the code as it was.

  #2  `blocked` was terminal — a failed dependency poisoned its dependents for
      the life of the database.
  #3  `check_scope("")`, `check_scope("%")` and any PREFIX of a granted host
      all returned authorized=True.
  #5  L4 passed vacuously when no claimant was supplied, reaching
      `verdict='validated'` with no independent agent.
  #11 a malformed `expires_at` read as "never expires".
  #12 the stall check returned True unconditionally, so a 100% stalled graph
      audited as healthy.
"""
from __future__ import annotations

import os
import shutil
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
    tmp = Path(tempfile.mkdtemp(prefix="orch-regress-"))
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
    from orch import dag, store, validate

    con = store.open_db()

    # ---------------------------------------------------------------- #2
    print("R1 a blocked task recovers when its dependency is repaired")
    con.execute("DELETE FROM task")
    con.execute("DELETE FROM task_dep")
    con.commit()
    store.add_task(con, "D", "dependency", expected_artifact="x")
    store.add_task(con, "B", "child", depends_on=["D"], expected_artifact="y")
    con.commit()
    dag.refresh_readiness(con)
    store.set_status(con, "D", "failed")
    dag.refresh_readiness(con)
    check("child is blocked when its dep fails",
          store.get_task(con, "B")["status"] == "blocked",
          store.get_task(con, "B")["status"])

    store.set_status(con, "D", "completed")
    dag.refresh_readiness(con)
    check("child is revived once the dep completes",
          store.get_task(con, "B")["status"] == "ready",
          f"stuck in {store.get_task(con, 'B')['status']} — dead-end")
    check("the revived task is actually claimable",
          "B" in [r["task_key"] for r in dag.ready_tasks(con)],
          str([r["task_key"] for r in dag.ready_tasks(con)]))

    print("\nR2 a retrying task also recovers (it is not terminal either)")
    store.add_task(con, "RT", "retry me", expected_artifact="z")
    con.commit()
    dag.refresh_readiness(con)
    store.set_status(con, "RT", "retrying")
    store.set_status(con, "RT", "ready")   # via the normal path
    dag.refresh_readiness(con)
    check("a retrying task can be re-readied",
          store.get_task(con, "RT")["status"] == "ready",
          store.get_task(con, "RT")["status"])

    print("\nR3 a still-broken dependency does NOT revive its child")
    store.add_task(con, "D2", "dep 2", expected_artifact="x")
    store.add_task(con, "B2", "child 2", depends_on=["D2"],
                   expected_artifact="y")
    con.commit()
    dag.refresh_readiness(con)
    store.set_status(con, "D2", "failed")
    dag.refresh_readiness(con)
    check("child stays blocked while its dep is still failed",
          store.get_task(con, "B2")["status"] == "blocked",
          store.get_task(con, "B2")["status"])

    # ---------------------------------------------------------------- #3
    print("\nR4 the scope gate refuses empty, wildcard and prefix targets")
    store.grant_scope(con, "s", "lab.internal", "lab", "lab 1",
                      offensive_allowed=True)
    for bad, why in (("", "empty target"),
                     ("   ", "blank target"),
                     ("%", "wildcard"),
                     ("*", "star wildcard"),
                     ("lab%", "partial wildcard"),
                     ("lab.intern", "PREFIX of a granted host"),
                     ("lab.internal.evil.com", "SUFFIX attack")):
        r = store.check_scope(con, bad)
        check(f"{why} is NOT authorized", not r["authorized"],
              f"target={bad!r} -> {r}")
    ok = store.check_scope(con, "lab.internal")
    check("the exact granted host IS authorized", ok["authorized"], str(ok))
    check("case/space differences still resolve",
          store.check_scope(con, "  LAB.INTERNAL ")["authorized"],
          "normalisation broken")

    # --------------------------------------------------------------- #11
    print("\nR5 a malformed expiry does not become a permanent grant")
    store.grant_scope(con, "bad-expiry", "corrupt.example", "bugbounty",
                      "prog", expires_at="not-a-date")
    r = store.check_scope(con, "corrupt.example")
    check("unparseable expiry is treated as EXPIRED", not r["authorized"],
          f"fail-open: {r}")
    check("and the reason says so", r.get("reason") == "scope_expired", str(r))

    # ---------------------------------------------------------------- #5
    print("\nR6 L4 cannot be satisfied by omission")
    store.add_finding(con, "L4vac", "claim", target="t", endpoint="/z",
                      hypothesis="z" * 60, severity="high")
    fid = con.execute("SELECT id FROM finding WHERE finding_key='L4vac'"
                      ).fetchone()["id"]
    store.add_evidence(con, "request", finding_id=fid, request_raw="GET /z",
                       response_raw="200", provenance="t")
    # no claimant at all
    v = validate.validate_finding(con, "L4vac", reproduced=True)
    check("L4 FAILS with no claimant recorded",
          not v["results"]["L4"]["passed"], v["results"]["L4"]["detail"])
    check("no claimant cannot reach 'validated'",
          not v["validated"], f"verdict={v['verdict']}")
    check("verdict is not validated", v["verdict"] != "validated", v["verdict"])

    # validator only
    v2 = validate.validate_finding(con, "L4vac", reproduced=True,
                                  validator_run="run-v")
    check("L4 FAILS with a validator but no claimant",
          not v2["results"]["L4"]["passed"], v2["results"]["L4"]["detail"])

    print("\nR7 the same ROLE on both sides is not independence")
    store.add_role(con, "solo", "validation", toolsets=["validation"],
                   capabilities=["READ", "ANALYZE"], max_depth=0,
                   rationale="probe")
    store.start_agent_run(con, "run-a", "solo", "claim")
    store.start_agent_run(con, "run-b", "solo", "validate")
    v3 = validate.validate_finding(con, "L4vac", reproduced=True,
                                  claimant_run="run-a",
                                  validator_run="run-b")
    check("two run keys of ONE role do not satisfy L4",
          not v3["results"]["L4"]["passed"], v3["results"]["L4"]["detail"])

    store.add_role(con, "other", "validation", toolsets=["validation"],
                   capabilities=["READ", "ANALYZE"], max_depth=0,
                   rationale="probe")
    store.start_agent_run(con, "run-c", "other", "independent validation")
    v4 = validate.validate_finding(con, "L4vac", reproduced=True,
                                  claimant_run="run-a",
                                  validator_run="run-c")
    check("a genuinely different role DOES satisfy L4",
          v4["results"]["L4"]["passed"], v4["results"]["L4"]["detail"])
    check("and only then can it validate", v4["validated"],
          f"verdict={v4['verdict']} failed={v4['levels_failed']}")

    # --------------------------------------------------------------- #12
    print("\nR8 the audit reports DEGRADED on a stalled graph")
    from orch import selfaudit
    con.execute("DELETE FROM task")
    con.execute("DELETE FROM task_dep")
    con.execute("DELETE FROM finding")
    con.execute("DELETE FROM evidence")
    con.execute("DELETE FROM agent_run")
    con.execute("DELETE FROM agent_role")
    con.commit()
    store.add_task(con, "s.dep", "dead dependency", expected_artifact="never")
    store.add_task(con, "s.child", "blocked child", depends_on=["s.dep"],
                   expected_artifact="never")
    con.commit()
    dag.refresh_readiness(con)
    store.set_status(con, "s.dep", "failed")
    dag.refresh_readiness(con)
    r = selfaudit.audit(con)
    check("a fully stalled graph is NOT healthy", r["health"] == "degraded",
          f"health={r['health']} ({r['passed']}/{r['total']})")
    prog = [c for c in r["checks"] if c["name"] == "the run can make progress"]
    check("the progress check exists and failed",
          prog and not prog[0]["passed"],
          str(prog[0]["detail"])[:200] if prog else "check missing")
    check("the failure names the stall", prog and "STALLED" in prog[0]["detail"],
          str(prog[0]["detail"])[:200] if prog else "")

    print("\nR9 a healthy graph is still reported healthy")
    con.execute("DELETE FROM task")
    con.execute("DELETE FROM task_dep")
    con.commit()
    store.add_task(con, "ok1", "runnable work", expected_artifact="artifact")
    con.commit()
    dag.refresh_readiness(con)
    r2 = selfaudit.audit(con)
    check("a graph with runnable work audits healthy",
          r2["health"] == "healthy", f"health={r2['health']}")

    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"REGRESSION: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"REGRESSION: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())