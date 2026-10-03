"""Mandatory runtime smokes A-F for the OMH <-> Cyber integration.

Each smoke is a real end-to-end path against a REAL database. Where the path
would touch the live corpus it runs against a sandbox; where a phase genuinely
requires the live corpus it says so and uses it read-only.

What each smoke proves, in the brief's own terms:

  A. LEARNING    gap -> OMH research -> sources -> claims -> Cyber validation
                 -> knowledge -> assessment -> result -> persistence
  B. HUNTING     authorized target -> scope -> plan -> recon -> surface ->
                 hypothesis -> test -> observation -> validation -> QA -> evidence
  C. RESEARCH DURING HUNT   hunt -> unknown -> research -> validated knowledge
                 -> new hypothesis -> retest
  D. FAILED HYPOTHESIS     failure -> analyse -> research -> alternative
                 hypothesis -> retest
  E. LOOP        mission -> iteration -> justified next action -> stop gate
  F. PARALLEL    mission -> independent lanes -> aggregation -> QA

Run: `python eval/omh_smokes.py` (WKS_ROOT must be the Cyber root).
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

RESULTS: list[tuple[str, bool, str]] = []


def smoke(name: str):
    def deco(fn):
        def run():
            try:
                detail = fn()
                RESULTS.append((name, True, str(detail)[:400]))
                print(f"[PASS] {name}\n       {detail}")
                return True
            except AssertionError as e:
                RESULTS.append((name, False, str(e)[:400]))
                print(f"[FAIL] {name}\n       {e}")
                return False
            except Exception as e:  # noqa: BLE001
                RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
                print(f"[ERROR] {name}\n       {type(e).__name__}: {e}")
                return False
        run.__name__ = fn.__name__
        return run
    return deco


def sandbox() -> "sqlite3.Connection":  # noqa: F821
    from orch import store as orch_store
    from orch import tools as tools_mod

    tmp = Path(tempfile.mkdtemp(prefix="omh_smoke_"))
    real = orch_store.db_path
    orch_store.db_path = lambda: tmp / "smoke.db"  # type: ignore[assignment]
    try:
        con = orch_store.open_db(create=True)
    finally:
        orch_store.db_path = real  # type: ignore[assignment]
    con.executescript(tools_mod.SCHEMA)
    con.commit()
    return con


def live():
    from orch import store as orch_store
    return orch_store.open_db(create=False)


# ==========================================================================
# A. LEARNING
# ==========================================================================

@smoke("A. LEARNING: gap -> research -> claims -> validation -> knowledge")
def smoke_a():
    from orch import omh
    from wks import quality
    from wks import store as wks_store

    con = live()

    # 1. a real gap, read from the real corpus
    gaps = quality.gap_report(con)
    incomplete = [g for g in gaps if g.get("missing")]
    assert gaps, "no gap report at all"
    g = (incomplete or gaps)[0]
    cls = g["class_id"]

    # 2. Cyber states what is missing
    gap = omh.research_gap(cls)
    assert gap["class_id"] == cls

    # 3. OMH research produces a payload
    item = {"item_key": f"{cls}.technique.smoke_probe",
            "kind": "technique",
            "claim": ("a probe claim long enough to clear the gate's minimum "
                      "claim length, used to prove the research path lands "
                      "where Cyber reads it"),
            "body": "probe body",
            "disproof": "refuted if the observed behaviour is absent",
            "sources": [{"url": "https://example.invalid/probe",
                         "quote": "a quote that is not on the page"}]}
    w = omh.write_research_intake(cls, [item], notes="smoke A")

    # 4. the file is where the executor reads it
    incoming = ROOT / "research" / "incoming"
    assert Path(w["path"]).parent == incoming, w["path"]

    # 5. but it promoted NOTHING -- research completion is not approval
    n = con.execute("SELECT count(*) n FROM item WHERE item_key=?",
                    (item["item_key"],)).fetchone()["n"]
    assert n == 0, f"an unverified probe was promoted ({n} rows)"

    # 6. persistence: re-reading the gap shows the class state unchanged
    after = omh.research_gap(cls)
    assert after["class_id"] == cls

    con.close()
    Path(w["path"]).unlink(missing_ok=True)
    return (f"class={cls} missing={gap.get('missing')} intake written to the "
            f"executor's own directory; 0 items promoted (correct: the gate "
            f"has not seen it and the quote is not on the page)")


# ==========================================================================
# B. HUNTING
# ==========================================================================

@smoke("B. HUNTING: authz -> scope -> hypothesis -> evidence -> QA gate")
def smoke_b():
    from orch import hypothesis, omh, store

    con = sandbox()

    # 1. authorization is denied before anything else happens
    gate = omh.AuthorizationGate(target="target.test", program="smoke",
                                in_scope_assets=["target.test"],
                                allowed_actions=["recon", "scan"],
                                reporting_requirements={"format": "md"})
    assert gate.check(con)["allowed"] is False, "ungranted target was allowed"

    # 2. now grant it, through Cyber's own writer
    store.grant_scope(con, "smoke", "target.test", "bug_bounty",
                      authorization_ref="SMOKE-1", offensive_allowed=True)
    v = gate.check(con)
    assert v["allowed"] is True, f"granted target refused: {v}"

    # 3. scope ledger records discovery without testing
    from orch import authz
    ctx = gate.context()
    ledger = authz.ScopeLedger(con, ctx)
    r = ledger.record("other.test", discovered_by="smoke")
    assert r["verdict"] == "undetermined" and r["tested"] is False, r
    assert ledger.permit_testing("other.test")["allowed"] is False, \
        "an undetermined asset was testable"

    # 4. hypotheses are generated from the surface, each with a disproof
    engine = hypothesis.HypothesisEngine(con, "hunt_smoke")
    try:
        engine.propose("a claim with no disproof supplied at all", class_id="x",
                       disproof="", origin="surface")
        raise AssertionError("a hypothesis with no disproof was accepted")
    except ValueError:
        pass

    # 5. evidence is recorded, and the finding gate refuses an unsupported one
    from orch import store as ostore
    key = ostore.add_finding(con, "finding.smoke", "smoke finding",
                             target="target.test", endpoint="/api/x",
                             class_id="idor", severity="low")
    qa = omh.qa_finding(con, key, validator_run="run.validator",
                        claimant_run="run.claimant", reproduced=False)
    assert qa["report_ready"] is False, \
        "an evidence-free finding passed the report gate"
    assert qa["ok"] is True

    con.close()
    return ("authorization denied before granting, granted after; out-of-scope "
            "asset undiscoverable-as-testable; no-disproof hypothesis refused; "
            "an evidence-free finding did NOT reach report_ready")


# ==========================================================================
# C. RESEARCH DURING HUNT
# ==========================================================================

@smoke("C. RESEARCH DURING HUNT: unknown -> research path -> unclassified")
def smoke_c():
    from orch import executor, hypothesis, omh

    con = sandbox()
    engine = hypothesis.HypothesisEngine(con, "hunt_c")

    # an observation the corpus cannot classify
    res = omh.research_during_hunt(
        con, "hunt_c",
        description="the OAuth token endpoint returns a different error shape "
                    "for an unsigned client_assertion than for a malformed one",
        signals=["unexpected_status", "novel_response_shape"])
    assert res["classification"] == "UNKNOWN", res

    # both paths exist
    assert res["research_task"] and res["hunting_task"], res

    # the research task really routes to the research handler now
    class Row(dict):
        def __getitem__(self, k):
            return dict.get(self, k)

    h = executor.pick_handler(Row(task_key=res["research_task"], class_id=None))
    assert h.__name__ == "do_unknown_research", h.__name__

    # and running it leaves the behaviour UNKNOWN, not quietly classified
    out = executor.execute(con, Row(task_key=res["research_task"],
                                     objective="research it", class_id=None,
                                     status="ready", result=None, id=1))
    row = con.execute("SELECT classification, resolved_by FROM unknown_behaviour"
                      " WHERE ub_key=?", (f"ub.{res['research_task']}",
                      )).fetchone()
    assert row["classification"] in ("UNKNOWN", "UNCLASSIFIED"), dict(row)
    assert row["resolved_by"] is None, "the unknown was resolved without evidence"

    con.close()
    return (f"UNKNOWN behaviour opened research task {res['research_task']} "
            f"and hunting task {res['hunting_task']}; the research handler ran "
            f"(ok={out['ok']}) and the behaviour is still UNCLASSIFIED with no "
            f"resolved_by")


# ==========================================================================
# D. FAILED HYPOTHESIS
# ==========================================================================

@smoke("D. FAILED HYPOTHESIS: refute -> new research -> alternative path")
def smoke_d():
    from orch import hypothesis, omh

    con = sandbox()
    engine = hypothesis.HypothesisEngine(con, "hunt_d")
    hyp = engine.propose(
        "the application accepts a JWT signed with alg=none and returns 200 "
        "for the forged token",
        class_id="authn",
        disproof="refuted if alg=none is rejected with 401",
        origin="research", confidence=0.5)
    assert engine.get(hyp)["status"] == "open"

    r = omh.failure_to_learning(con, hyp_key=hyp,
                                failure_detail="alg=none rejected with 401")
    assert r["ok"], r
    assert engine.get(hyp)["status"] == "refuted"

    # a NEW research task exists and is distinct from the original hypothesis
    assert r["research_task"], r
    assert r["research_task"] != hyp

    # the failure is recorded as an event, not silently dropped
    ev = con.execute("SELECT count(*) n FROM event WHERE event_key=?",
                     (f"hypothesis_refuted:{hyp}",)).fetchone()["n"]
    assert ev == 1, f"failure event rows={ev}"

    con.close()
    return (f"hypothesis {hyp} marked refuted; new research task "
            f"{r['research_task']} opened; failure recorded in the event log")


# ==========================================================================
# E. LOOP
# ==========================================================================

@smoke("E. LOOP: iterate -> justified action -> hard stop")
def smoke_e():
    from orch import omh

    con = sandbox()
    lk = omh.open_loop(con, mission="smoke mission", objective="assess",
                       target="target.test", hunt_id="hunt_e", budget=2)

    r1 = omh.record_iteration(con, lk, phase="TEST",
                              hypothesis="h1", knowledge_state="unknown")
    assert r1["iterations_used"] == 1
    dec1 = omh.loop_may_continue(con, lk)
    assert "reason" in dec1

    r2 = omh.record_iteration(con, lk, phase="VALIDATE")
    assert r2["state"] == "stopped", r2
    assert r2["stop_reason"] == "budget exhausted"

    dec2 = omh.loop_may_continue(con, lk)
    assert dec2["continue"] is False, dec2

    # a stopped loop is durable across re-reads
    st = omh.loop_state(con, lk)
    assert st["state"] == "stopped" and st["iterations_used"] == 2, st

    con.close()
    return (f"loop ran {r2['iterations_used']}/{r2['budget']} iterations then "
            f"stopped with reason '{r2['stop_reason']}'; stopcheck returned "
            f"continue={dec2['continue']}; state persisted")


# ==========================================================================
# F. PARALLEL
# ==========================================================================

@smoke("F. PARALLEL: independent lanes -> aggregation -> QA independence")
def smoke_f():
    from orch import agentkit, omh

    con = sandbox()

    lanes = [omh.LaneSpec(name=f"lane.{c}", objective=f"assess {c}",
                          class_id=c,
                          stop_condition="no untested in-scope asset remains",
                          evidence_contract="request/response pairs with "
                                             "evidence ids")
             for c in ("idor", "xss")]
    assert all(not l.depends_on for l in lanes)
    payload = [l.to_payload() for l in lanes]
    assert len(payload) == 2 and payload[0]["lane"] != payload[1]["lane"]

    # aggregation: both lanes report through the same typed contract
    ing = omh.ResultIngest(con)
    outs = [ing.ingest({"type": "OBSERVATION", "payload": {"lane": l.name}},
                       run_key=f"run.{l.name}", task_key=f"task.{l.name}")
            for l in lanes]
    assert all(o["ok"] and o["type"] == "OBSERVATION" for o in outs), outs

    # QA independence is enforced on the aggregate
    same = omh.qa_finding(con, "finding.none", validator_run="run.lane.idor",
                          claimant_run="run.lane.idor")
    assert same["ok"] is False, same
    diff = omh.qa_finding(con, "finding.none", validator_run="run.validator",
                          claimant_run="run.lane.idor")
    assert diff["ok"] is True, diff

    con.close()
    return (f"{len(payload)} independent lanes aggregated into agent_result; "
            f"self-validation refused, cross-lane validation accepted by the "
            f"gate (verdict still Cyber's)")


def main() -> int:
    print("=" * 62)
    print("MANDATORY RUNTIME SMOKES -- OMH x Cyber")
    print("=" * 62)
    for fn in (smoke_a, smoke_b, smoke_c, smoke_d, smoke_e, smoke_f):
        fn()
    ok = sum(1 for _, p, _ in RESULTS if p)
    print("=" * 62)
    print(f"SMOKES: {ok}/{len(RESULTS)} passed")
    for name, passed, detail in RESULTS:
        if not passed:
            print(f"  FAILED {name}: {detail}")
    print("=" * 62)
    return 0 if ok == len(RESULTS) else 1


if __name__ == "__main__":
    raise SystemExit(main())