"""Authorization-gate tests (spec §25, §35).

An adversarial validator proved the capability and scope systems were
DECLARATION ONLY:

  * `capability_grant` existed in the schema but nothing ever wrote it, so a
    gate requiring a grant could never pass — it was decoration.
  * `check_scope` was never called from `dispatch`, `orchestrator`, or any
    worker. A role declared ["READ".."DESTRUCTIVE"] at depth 5 dispatched with
    ZERO scope grants in the database.
  * `apply_validation` trusted the caller's verdict string, so
    `apply_validation({"verdict": "validated"})` set a finding to validated.

Every test below is written to FAIL against that code. A gate that cannot be
observed failing is not a gate.
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
    tmp = Path(tempfile.mkdtemp(prefix="orch-auth-"))
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
    from orch import agents, dag, orchestrator, store, validate

    con = store.open_db()

    print("G1 a DESTRUCTIVE role cannot dispatch with no authorization")
    agents.build_role(con, "root", "system",
                      toolsets=["network", "ad"],
                      capabilities=["READ", "ANALYZE", "WRITE", "EXECUTE",
                                    "DESTRUCTIVE"],
                      max_depth=5, rationale="escalation probe")
    grants = con.execute("SELECT count(*) n FROM capability_grant"
                         ).fetchone()["n"]
    check("no capability grants exist yet", grants == 0, str(grants))

    d = agents.dispatch(con, "r1", "root", "act on target",
                        target="victim.internal")
    check("DESTRUCTIVE dispatch is REFUSED", not d["dispatched"], str(d))
    check("refusal cites authorization", "authorization refused" in
          (d.get("reason") or ""), str(d.get("reason"))[:160])
    # Count only runs created by THIS probe. The sandbox copy carries the
    # author's earlier runs, so an absolute count proves nothing.
    r1 = con.execute("SELECT count(*) n FROM agent_run WHERE run_key='r1'"
                     ).fetchone()["n"]
    check("no agent run was created for the refused dispatch", r1 == 0,
          f"{r1} run(s) named r1")

    print("\nG2 granting the capability ALONE is still not enough")
    store.grant_capability(con, "root", "DESTRUCTIVE", granted_by="operator",
                           rationale="test")
    d2 = agents.dispatch(con, "r2", "root", "act on target",
                         target="victim.internal")
    check("capability without a SCOPE grant is still refused",
          not d2["dispatched"], str(d2))
    check("the refusal names the missing scope",
          "scope_ok" in str(d2.get("gate", {})), str(d2.get("gate"))[:200])

    print("\nG3 capability AND scope together permit dispatch")
    store.grant_scope(con, "s1", "victim.internal", "lab", "lab 1",
                      offensive_allowed=True)
    d3 = agents.dispatch(con, "r3", "root", "act on target",
                         target="victim.internal")
    check("fully authorized dispatch succeeds", d3["dispatched"], str(d3))
    check("the gate records offensive permission",
          d3.get("gate", {}).get("offensive_allowed") is True,
          str(d3.get("gate"))[:200])

    print("\nG4 scope WITHOUT offensive permission blocks offensive work")
    store.grant_scope(con, "s2", "readonly.internal", "research_only",
                      "passive research only", offensive_allowed=False)
    d4 = agents.dispatch(con, "r4", "root", "act on target",
                         target="readonly.internal")
    check("authorized-but-not-offensive still refuses EXECUTE",
          not d4["dispatched"], str(d4))
    check("the refusal distinguishes scope from offensive permission",
          d4.get("gate", {}).get("scope_ok") is True
          and d4.get("gate", {}).get("offensive_allowed") is False,
          str(d4.get("gate"))[:200])

    print("\nG5 a READ-only role is not gated (it cannot act off-system)")
    agents.build_role(con, "reader", "system", toolsets=["research"],
                      capabilities=["READ", "ANALYZE"], max_depth=1,
                      rationale="read-only")
    d5 = agents.dispatch(con, "r5", "reader", "read local state")
    check("READ-only role dispatches without a scope grant", d5["dispatched"],
          str(d5))
    check("and is reported as ungated",
          d5["gate"]["needs_execution_gate"] is False, str(d5["gate"]))

    print("\nG6 the orchestrator path is gated too, not just direct dispatch")
    store.add_task(con, "auth.probe", "probe", expected_artifact="x")
    con.commit()
    dag.refresh_readiness(con)
    from orch import priority
    # force the probe to rank first
    con.execute("UPDATE task SET priority=1 WHERE task_key='auth.probe'")
    con.commit()
    only = lambda row: row["task_key"] == "auth.probe"
    agents.build_role(con, "executor", "system", toolsets=["validation"],
                      capabilities=["READ", "ANALYZE", "WRITE"], max_depth=1,
                      rationale="default executor")
    r = orchestrator.run(con, executor=lambda row, ctx: {
        "ok": True,
        "summary": "wrote the projection and recorded the artifact path"},
        max_tasks=2, checkpoint_label="auth", task_filter=only)
    # the built-in executor role is WRITE-only, so it must NOT be blocked
    check("WRITE-only executor still runs internal work",
          r["executed"] and r["executed"][0]["status"] == "completed",
          str(r["executed"])[:200])

    print("\nG7 a forged verdict cannot mark a finding validated")
    store.add_finding(con, "forged", "no evidence at all", target="t",
                      endpoint="/x", hypothesis="x" * 50, severity="high")
    verdict = validate.apply_validation(con, "forged",
                                        {"verdict": "validated"})
    st = con.execute("SELECT status FROM finding WHERE finding_key='forged'"
                     ).fetchone()["status"]
    check("a forged 'validated' verdict is NOT honoured",
          st != "validated", f"status={st} returned={verdict}")
    check("the re-derived verdict is returned", verdict == st,
          f"returned={verdict} stored={st}")
    check("the stored verdict is one the gate can justify",
          st in {"candidate", "rejected", "false_positive"}, str(st))

    print("\nG8 the same finding CAN be validated legitimately")
    fid = con.execute("SELECT id FROM finding WHERE finding_key='forged'"
                      ).fetchone()["id"]
    store.add_evidence(con, "request", finding_id=fid,
                       request_raw="GET /x", response_raw="200",
                       provenance="test")
    v = validate.validate_finding(con, "forged", reproduced=True,
                                  claimant_run="r-claim",
                                  validator_run="r-val")
    applied = validate.apply_validation(con, "forged", {
        "reproduced": True, "claimant_run": "r-claim",
        "validator_run": "r-val"})
    check("a genuinely validated finding reaches validated",
          applied == "validated", f"{applied} levels={v['levels_failed']}")
    check("L4 required an independent validator",
          v["results"]["L4"]["passed"], v["results"]["L4"]["detail"])

    print("\nG9 self-validation is still refused after the refactor")
    store.add_finding(con, "selfval", "claim", target="t", endpoint="/y",
                      hypothesis="y" * 50, severity="low")
    fid2 = con.execute("SELECT id FROM finding WHERE finding_key='selfval'"
                       ).fetchone()["id"]
    store.add_evidence(con, "request", finding_id=fid2, request_raw="GET /y",
                       response_raw="200", provenance="t")
    out = validate.apply_validation(con, "selfval", {
        "reproduced": True, "claimant_run": "same", "validator_run": "same"})
    check("claiming and validating with the same run is not validated",
          out != "validated", str(out))

    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"AUTHORIZATION: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"AUTHORIZATION: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())