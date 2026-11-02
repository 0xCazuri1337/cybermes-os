"""Integration tests for the OMH <-> Cyber boundary (`orch.omh`).

Written to be adversarial about its own subject. Every property that could
quietly become false is checked BOTH ways: a control proves the check can fail.
A suite that only proves the happy path is a suite that certifies nothing, and
the module under test is an authority boundary -- exactly where a
self-confirming test does the most damage.

The specific danger these guard against, repeated by a real defect found
during the audit: an OMH result becoming a VERDICT. Phase 15 QA, Phase 14's
finding gate and Phase 2's research-ingestion path must all remain
Cyber-decided. If any of them can be satisfied by an OMH string, the
integration has promoted itself to authority.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name} — {detail}")


def sandbox_db(tmp: Path) -> sqlite3.Connection:
    """A throwaway db built by `store.open_db`, exactly as `test_orch.py` does.

    Deliberately NOT a hand-assembled schema. Copying `wks/schema.sql` +
    `orch/schema.sql` produced a database missing `tool_attempt`, which is
    created imperatively by `orch.tools`, so the QA test died on
    `no such table` and read as a broken gate. `open_db` runs every module's
    real DDL, which is also the only version that stays true when a third
    schema fragment is added.
    """
    from orch import store as orch_store
    from orch import tools as tools_mod

    tmp.mkdir(parents=True, exist_ok=True)
    real = orch_store.db_path
    orch_store.db_path = lambda: tmp / "omh_it.db"  # type: ignore[assignment]
    try:
        con = orch_store.open_db(create=True)
    finally:
        orch_store.db_path = real  # type: ignore[assignment]
    # `tool_attempt` is created imperatively by `orch.tools`, not by either
    # .sql file, so `open_db` alone leaves it absent and the report gate's
    # program-rules stage dies with `no such table`. Applying `orch.tools.SCHEMA`
    # is what makes this sandbox match what a real hunt connection sees.
    con.executescript(tools_mod.SCHEMA)
    con.commit()
    return con


def main() -> int:
    import tempfile

    from orch import (agentkit, authz, executor, hypothesis, omh, policy,
                      store, validate)

    tmp = Path(tempfile.mkdtemp(prefix="omh_it_"))
    os.environ["WKS_ROOT"] = str(tmp)

    # ==================================================================
    print("\nA. the workflow map is closed (Phase 4)")
    # ==================================================================
    check("six OMH workflows are mapped",
          set(omh.WORKFLOW_MAP) == {"ulw-context", "ulw-plan", "ulw-research",
                                    "ulw-work", "ulw-loop", "ulw-qa"},
          str(sorted(omh.WORKFLOW_MAP)))
    check("every workflow maps to a lifecycle phase",
          all(v for v in omh.WORKFLOW_MAP.values()),
          str(omh.WORKFLOW_MAP))
    check("an unmapped workflow is refused",
          omh._reject_workflow(["ulw-anything"])["ok"] is False)
    check("offensive workflows are declared",
          omh.OFFENSIVE_WORKFLOWS == {"ulw-work", "ulw-loop"},
          str(omh.OFFENSIVE_WORKFLOWS))

    # ==================================================================
    print("\nB. an OMH result is a CLAIM, never a verdict (Phase 2/15)")
    # ==================================================================
    con = sandbox_db(tmp)

    src = (ROOT / "orch" / "omh.py").read_text(encoding="utf-8")
    # Check the CODE, not the prose. A bare substring scan matched this very
    # docstring, which NAMES those functions in order to say they are never
    # called -- so the isolation check failed on the file explaining that it
    # does not do the thing. Strip comments and docstrings first, so the check
    # measures calls rather than mentions.
    import ast as _ast
    import io as _io
    import tokenize as _tokenize

    def code_only(path: Path) -> str:
        """Strip comments and every string literal, keeping only real code.

        A bare substring scan matched this file's own docstring, which NAMES
        `apply_validation` and `apply_gate` precisely to say they are never
        called -- so the isolation check failed on the file explaining that it
        does not do the thing. Token-type heuristics miss multi-line strings,
        so this walks the AST and rebuilds the source from live statements.
        """
        text = path.read_text(encoding="utf-8")
        tree = _ast.parse(text)
        lines = text.splitlines()

        def seg(node: _ast.AST) -> str:
            return "\n".join(lines[node.lineno - 1:(node.end_lineno or node.lineno)])

        keep: list[str] = []
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Call):
                keep.append(seg(node.func))
        # Only CALLS matter: a bare mention in prose or a string payload is
        # not an invocation.
        return "\n".join(keep)

    code = code_only(ROOT / "orch" / "omh.py")
    forbidden = ["scope_grant", "capability_grant", "grant_scope",
                 "grant_capability", "apply_validation", "apply_gate",
                 "promote"]
    hits = sorted({f for f in forbidden
                   if re.search(rf"\b{re.escape(f)}\b", code)})
    check("omh.py makes no authority-granting CALL", not hits, str(hits))

    # The strongest form of the same check: prove the module never even
    # imports the authority writers. A call reached through an alias is still
    # a call.
    imported = set()
    for node in _ast.walk(_ast.parse(src)):
        if isinstance(node, _ast.ImportFrom):
            for a in node.names:
                imported.add(a.name)
        elif isinstance(node, _ast.Import):
            for a in node.names:
                imported.add(a.name.split(".")[-1])
    authority = {"grant_scope", "grant_capability", "apply_validation",
                 "apply_gate"}
    leaked = imported & authority
    check("omh.py never imports an authority writer", not leaked, str(leaked))

    env = agentkit.parse_output(
        {"type": "VALIDATED_FINDING", "payload": "I am validated"},
        run_key="r1", task_key="t1", con=con)
    check("agent self-declared VALIDATED_FINDING is downgraded",
          env["type"] == "CANDIDATE_FINDING" and env["downgraded"],
          str(env))

    ing = omh.ResultIngest(con)
    r = ing.ingest({"type": "VALIDATED_FINDING", "payload": {"x": 1}},
                   run_key="r2", task_key="t2")
    check("ResultIngest reports the downgrade, not a pass",
          r["downgraded"] and r["type"] == "CANDIDATE_FINDING", str(r))
    n = con.execute("SELECT type FROM agent_result WHERE run_key='r2'"
                    ).fetchone()
    check("the persisted row is a CANDIDATE_FINDING, never validated",
          n and n["type"] == "CANDIDATE_FINDING", str(dict(n) if n else None))

    # CONTROL: an unknown type must be refused, proving parse_output is real.
    try:
        agentkit.parse_output({"type": "DEFINITELY_A_REAL_BUG",
                               "payload": "x"}, run_key="r3")
        check("CONTROL: an invented result type is refused", False,
              "parse_output accepted a type outside the closed vocabulary")
    except agentkit.ResultContractError:
        check("CONTROL: an invented result type is refused", True)

    # CONTROL: a missing type is refused too.
    try:
        agentkit.parse_output({"payload": "no type"}, run_key="r4")
        check("CONTROL: an untyped result is refused", False,
              "parse_output accepted an output with no type")
    except agentkit.ResultContractError:
        check("CONTROL: an untyped result is refused", True)

    # ==================================================================
    print("\nC. authorization gate is deny-by-default (Phase 8)")
    # ==================================================================
    gate = omh.AuthorizationGate(target="example.test", program="p",
                                in_scope_assets=["example.test"],
                                allowed_actions=["recon", "scan", "exploit"],
                                reporting_requirements={"format": "md"})
    v = gate.check(con)
    check("no scope grant means NOT authorized",
          v["allowed"] is False, str(v))

    store.grant_scope(con, "s1", "example.test", "bug_bounty",
                      authorization_ref="REF-1", offensive_allowed=True)
    v = gate.check(con)
    check("grant + permitted action authorizes", v["allowed"] is True, str(v))

    # The grant alone must not be enough when the program forbids the action.
    strict = omh.AuthorizationGate(target="example.test", program="p",
                                   in_scope_assets=["example.test"],
                                   allowed_actions=["scan"],
                                   forbidden_actions=["scan"],
                                   reporting_requirements={"format": "md"})
    check("a program rule overrides an existing grant",
          strict.check(con)["allowed"] is False,
          str(strict.check(con)))

    # An out-of-scope sibling must stay refused even with a grant for another.
    gate2 = omh.AuthorizationGate(target="other.test", program="p",
                                 in_scope_assets=["other.test"],
                                 allowed_actions=["scan"],
                                 reporting_requirements={"format": "md"})
    check("a different host is still refused",
          gate2.check(con)["allowed"] is False)

    # Wildcards must never authorize.
    for bad in ("%", "*.test", ""):
        check(f"wildcard/empty target {bad!r} is refused",
              store.check_scope(con, bad)["authorized"] is False)

    # ==================================================================
    print("\nD. lanes must be bounded (Phase 5)")
    # ==================================================================
    try:
        omh.LaneSpec(name="bad", objective="o", stop_condition="")
        check("a lane with no stop condition is refused", False,
              "LaneSpec accepted a lane that cannot end")
    except ValueError:
        check("a lane with no stop condition is refused", True)

    try:
        omh.LaneSpec(name="bad2", objective="o", stop_condition="s")
        check("a lane with no evidence contract is refused", False,
              "LaneSpec accepted output nothing can gate")
    except ValueError:
        check("a lane with no evidence contract is refused", True)

    try:
        omh.LaneSpec(name="bad3", objective="o", stop_condition="s",
                     evidence_contract="e", depends_on=["other"])
        check("a dependent lane is refused from the parallel set", False,
              "LaneSpec accepted a lane that needs another lane's output")
    except ValueError:
        check("a dependent lane is refused from the parallel set", True)

    good = omh.LaneSpec(name="ok", objective="o", stop_condition="s",
                        evidence_contract="e")
    check("a well-formed lane is accepted",
          good.to_payload()["lane"] == "ok")

    # ==================================================================
    print("\nE. research completion is NOT knowledge approval (Phase 2/3)")
    # ==================================================================
    item = {"item_key": "otp.technique.demo", "kind": "technique",
            "claim": "a claim long enough to clear the minimum claim length "
                     "threshold used by the gate",
            "body": "body text", "disproof": "refuted if it is not observed",
            "sources": [{"url": "https://example.invalid/a", "quote": "q"}]}
    out = omh.write_research_intake("otp", [item])
    check("research intake is written", out["ok"] and Path(out["path"]).exists(),
          str(out))
    n_items = con.execute("SELECT count(*) n FROM item").fetchone()["n"]
    check("writing an intake file promoted ZERO items",
          n_items == 0, f"item table has {n_items} rows")
    check("the writer says it did not ingest",
          "NOT ingested" in out["note"], out.get("note", ""))

    empty = omh.write_research_intake("otp", [])
    check("an empty payload is refused",
          empty["ok"] is False, str(empty))

    try:
        omh.research_intake_path("../escape")
        check("a path-traversal class id is refused", False,
              "research_intake_path accepted a traversal")
    except ValueError:
        check("a path-traversal class id is refused", True)

    # ==================================================================
    print("\nF. the unknown-behaviour loop actually routes (Phase 9)")
    # ==================================================================
    con2 = sandbox_db(tmp)
    engine = hypothesis.HypothesisEngine(con2, "hunt1")
    res = engine.open_unknown("unexpected OAuth redirect on token exchange",
                              signals=["unexpected_status"])
    check("unknown behaviour opens a research path",
          bool(res["research_task"]), str(res))
    check("unknown behaviour opens a hunting path",
          bool(res["hunting_task"]), str(res))

    class Row(dict):
        def __getitem__(self, k):
            return dict.get(self, k)

    h = executor.pick_handler(Row(task_key=res["research_task"],
                                  class_id=None))
    check("the research task routes to unknown-research, not maintenance",
          h.__name__ == "do_unknown_research", h.__name__)

    out = executor.execute(con2, Row(task_key=res["research_task"],
                                     objective="research the behaviour",
                                     class_id=None, status="ready",
                                     result=None, id=1))
    check("the research handler refuses honestly when nothing can seed it",
          out["ok"] is False
          and out.get("error") == "unclassifiable_research_target", str(out))
    row = con2.execute("SELECT classification, resolved_by FROM"
                       " unknown_behaviour WHERE ub_key=?",
                       (f"ub.{res['research_task']}",)).fetchone()
    check("the behaviour stays UNCLASSIFIED and unresolved",
          row and row["classification"] in ("UNKNOWN", "UNCLASSIFIED")
          and row["resolved_by"] is None, str(dict(row) if row else None))

    # CONTROLS: the ordinary research paths still route correctly.
    check("CONTROL: research.<cls> still routes to do_research",
          executor.pick_handler(Row(task_key="research.otp",
                                    class_id="otp")).__name__
          == "do_research")
    check("CONTROL: seed.<cls>.research still routes to do_research",
          executor.pick_handler(Row(task_key="seed.otp.research",
                                    class_id="otp")).__name__
          == "do_research")
    check("CONTROL: an audit task still routes to do_audit",
          executor.pick_handler(Row(task_key="audit.corpus",
                                    class_id=None)).__name__ == "do_audit")

    # ==================================================================
    print("\nG. failure -> learning opens new work (Phase 10)")
    # ==================================================================
    hyp = engine.propose(
        "the OAuth token endpoint accepts a client_assertion without "
        "signature verification",
        class_id="authn", disproof="refuted if an unsigned assertion is "
                                   "rejected with 401",
        origin="research", confidence=0.4)
    r = omh.failure_to_learning(con2, hyp_key=hyp,
                                failure_detail="unsigned assertion accepted")
    check("a refuted hypothesis produces a fresh research task",
          r["ok"] and bool(r["research_task"]), str(r))
    st = engine.get(hyp)
    check("the hypothesis is marked refuted, not deleted",
          st and st["status"] == "refuted", str(dict(st) if st else None))

    bad = omh.failure_to_learning(con2, hyp_key="hyp.nope", failure_detail="x")
    check("an unknown hypothesis is refused, not invented",
          bad["ok"] is False, str(bad))

    # ==================================================================
    print("\nH. the loop stops (Phase 13)")
    # ==================================================================
    lk = omh.open_loop(con2, mission="smoke loop", objective="iterate",
                       budget=2)
    check("a loop opens running", omh.loop_state(con2, lk)["state"] == "running")

    r1 = omh.record_iteration(con2, lk, phase="TEST")
    check("first iteration is within budget",
          r1["ok"] and r1["iterations_used"] == 1, str(r1))
    r2 = omh.record_iteration(con2, lk, phase="TEST")
    check("spending the budget STOPS the loop",
          r2["state"] == "stopped", str(r2))

    again = omh.record_iteration(con2, lk, phase="TEST")
    check("a stopped loop refuses to advance",
          again["ok"] is False and again["reason"] == "loop is stopped",
          str(again))
    check("the loop reports why it stopped",
          omh.loop_state(con2, lk)["stop_reason"] == "budget exhausted",
          str(omh.loop_state(con2, lk)))

    dec = omh.loop_may_continue(con2, lk)
    check("stopcheck says do not continue",
          dec["continue"] is False, str(dec))

    lk2 = omh.open_loop(con2, mission="stopped by hand", objective="x",
                        budget=99)
    omh.stop_loop(con2, lk2, "policy blocked execution")
    check("a manually stopped loop does not continue",
          omh.loop_may_continue(con2, lk2)["continue"] is False)

    # ==================================================================
    print("\nI. QA cannot certify its own claim (Phase 15)")
    # ==================================================================
    same = omh.qa_finding(con2, "finding.nonexistent",
                          validator_run="run.1", claimant_run="run.1")
    check("QA with validator == claimant is refused",
          same["ok"] is False and same["report_ready"] is False, str(same))

    indep = omh.qa_finding(con2, "finding.nonexistent",
                           validator_run="run.validator",
                           claimant_run="run.claimant")
    check("independent QA on a missing finding is NOT report_ready",
          indep.get("report_ready") is False, str(indep)[:200])
    check("the verdict is attributed to Cyber's gate",
          "Cyber" in indep.get("authority", ""), str(indep.get("authority")))

    # A MISSING FINDING IS NOT A FAILED VALIDATION.
    #
    # MEASURED 2026-11-01: before this, a missing finding and a finding
    # that genuinely failed the gates produced the same shape -- `ok: True`,
    # `report_ready: False` -- so a caller could not tell "the finding was
    # checked and failed" from "there was no finding to check". A caller
    # that cannot tell them apart tunes the checklist instead of fixing the
    # lookup.
    check("a missing finding is reported AS a missing finding",
          indep.get("outcome") == "missing_finding", str(indep.get("outcome")))
    check("a missing finding is not certified (ok is False)",
          indep.get("ok") is False, str(indep.get("ok")))
    check("the missing-finding reason names the absence",
          "no finding is stored" in str(indep.get("reason", "")),
          str(indep.get("reason"))[:160])

    # And the gate itself must distinguish the two.
    from orch import fp_checklist as _fp
    miss = _fp.run_fp_gate(con2, "finding.nonexistent")
    check("the FP gate reports outcome=missing_finding",
          miss.get("outcome") == "missing_finding", str(miss.get("outcome")))
    check("the FP gate still refuses to pass a missing finding",
          miss.get("passed") is False, str(miss.get("passed")))

    # An UNEXPECTED DATABASE ERROR MUST NOT BECOME A VALIDATION FAILURE.
    # A gate that reports "the finding failed the FP checklist" when the
    # database is broken will have the checklist tuned to compensate for a
    # broken environment -- and the real failure disappears.
    import sqlite3 as _sq

    class _BrokenEvidence:
        """A connection whose evidence table is missing."""

        def __init__(self, real):
            self._r = real

        def execute(self, sql, *a, **k):
            if "FROM evidence" in sql:
                raise _sq.OperationalError("no such table: evidence")
            return self._r.execute(sql, *a, **k)

        def __getattr__(self, n):
            return getattr(self._r, n)

    # Find a finding that actually exists, so the early "missing" return
    # is not what is being exercised. The sandbox is built from the real
    # schema and starts EMPTY, so the finding is created here rather than
    # borrowed from the live database -- a test that depends on the live
    # database's contents is a test that fails when the corpus changes.
    from wks import ownership as _own
    _real_key = "test.gate.error.finding"
    with _own.owner_write(con2, _own.ORCH):
        con2.execute(
            "INSERT OR REPLACE INTO finding "
            "(finding_key, title, class_id, severity, status, created_at, "
            "updated_at) VALUES (?,?,?,?,?,?,?)",
            (_real_key, "A synthetic finding for the error-path test",
             "idor", "medium", "candidate", "2026-11-01T00:00:00+00:00",
             "2026-11-01T00:00:00+00:00"))
    con2.commit()
    check("a real finding exists for the error test",
          con2.execute("SELECT count(*) FROM finding WHERE finding_key=?",
                       (_real_key,)).fetchone()[0] == 1,
          _real_key)
    if _real_key:
        raised = False
        try:
            _fp.run_fp_gate(_BrokenEvidence(con2), _real_key)
        except _sq.OperationalError:
            raised = True
        except Exception as _e:
            check("the DB error propagates as a database error",
                  False, f"{type(_e).__name__}: {_e}")
        check("a missing evidence table RAISES, it is not a validation failure",
              raised,
              "the gate converted an unexpected DB error into 'the finding "
              "failed the FP checklist'")

    # ==================================================================
    print("\nJ. memory boundary (Phase 18)")
    # ==================================================================
    check("an orchestration lesson is admissible",
          omh.memory_admissible("ulw-loop stopped on budget exhaustion")[
              "admissible"] is True)
    check("a technique is NOT admissible in OMH memory",
          omh.memory_admissible("AngularJS sandbox bypass technique")[
              "admissible"] is False)
    check("a finding is NOT admissible in OMH memory",
          omh.memory_admissible("confirmed IDOR finding on /api/v1")[
              "admissible"] is False)

    # ==================================================================
    print("\nK. isolation: omh writes no authority table (Phase 20)")
    # ==================================================================
    # The AST-based call check and the import check run in section B, where
    # `code_only` is defined. This section exists to keep the Phase 20
    # boundary visible as its own named gate in the report.

    con2.close()
    con.close()

    print(f"\nOMH INTEGRATION: {PASS} passed, {FAIL} failed")
    if FAILURES:
        print("\nFAILURES:")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())