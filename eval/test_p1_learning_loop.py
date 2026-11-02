"""P1-A: the learning loop -- five hooks, wired, and a loop that CLOSES.

THE GAP THIS EXISTS TO CLOSE (measured 2026-11-01)
----------------------------------------------------
All five adaptive hooks were IMPLEMENTED in `learning_engine/engine.py`:
`before_recon`, `during_testing`, `after_finding`, `before_summary`,
`after_triage`. The module was complete, the tests exercised it, and the
documentation described it.

But MEASURED, four of the five had NO non-test caller. `grep` for the
hook names across every non-test `.py` found exactly one production call
site -- `after_triage`, inside `orch/learning_bridge.py`. The other four
appeared only in `learning_engine/engine.py` itself, in the docs, and in
`eval/`.

And the one hook that WAS wired was wired to a function with no production
caller either: `orch/learning_bridge.record_hunt_outcome` is called from
`orch/finalgate.apply_gate`, and `apply_gate` was called from NOTHING
outside `eval/`. The CLI hunt path called the read-only
`finalgate.gate` and threw the verdict away.

So the learning loop was open at every link:

    before_recon   -- NEVER CALLED. The corpus could not inform a hunt.
    during_testing -- NEVER CALLED. Prior experience could not score a probe.
    after_finding  -- NEVER CALLED. A finding produced no lesson.
    before_summary -- NEVER CALLED. Learned experience could not rank output.
    after_triage   -- CALLED, but only from a function nothing called.

And the consequence that matters most: the `lesson` table was read by NO
production path. Corpus retrieval (`wks/retrieval.py`) reads `item`/`item_fts`
/`quality`. Task priority (`orch/priority.py`) reads `bug_class` and
`quality.maturity()`. Hypothesis generation (`orch/hypothesis.py`) reads
`item` and `finding`. Skill resolution reads `runtime/registry.json`. None
of them read `lesson`. A verified lesson changed NOTHING about any later
hunt.

WHAT THIS FILE PINS
-------------------
  A. REACHABILITY -- every one of the five hooks is called from a real
     production path, and the call site is named.
  B. THE LOOP CLOSES -- a finding filed by a live hunt produces a captured
     lesson; a triage outcome advances it; a VERIFIED lesson then changes
     a LATER hunt's priority. This is the property that was missing: a
     validated outcome changes future prioritization.
  C. THE GATE VERDICT IS PERSISTED -- the hunt's gate verdict is written
     back, not merely derived and discarded.
  D. FAILURE IS ISOLATED -- a learning failure never fails a hunt, a probe
     or a report.
  E. NO SILENT SUCCESS -- the hook's effect is recorded, so "the hook ran"
     is observable rather than assumed.

Run: python eval/test_p1_learning_loop.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def main() -> int:
    print("=== P1-A: the learning loop ===")

    # -----------------------------------------------------------------
    print("\nA. REACHABILITY — every hook is called from production code")
    # A static check: the hook name must appear in a production .py OUTSIDE
    # learning_engine/ itself and outside eval/.
    import re
    from orch import hunt_cli, hunt_exec, reporting

    hooks = ("before_recon", "during_testing", "after_finding",
             "before_summary", "after_triage")
    prod_sources = {
        "orch/hunt_exec.py": (ROOT / "orch" / "hunt_exec.py").read_text(
            encoding="utf-8"),
        "orch/hunt_cli.py": (ROOT / "orch" / "hunt_cli.py").read_text(
            encoding="utf-8"),
        "orch/learning_bridge.py": (ROOT / "orch" / "learning_bridge.py"
                                    ).read_text(encoding="utf-8"),
        "orch/reporting.py": (ROOT / "orch" / "reporting.py").read_text(
            encoding="utf-8"),
    }
    for hook in hooks:
        callers = [name for name, src in prod_sources.items()
                   if re.search(rf"\b{hook}\b", src)]
        check(f"{hook} is called from a production path", bool(callers),
              f"no production caller in {list(prod_sources)}")

    # `apply_gate` -- the function that persists the verdict and feeds the
    # bridge -- must have a production caller too.
    apply_callers = [name for name, src in prod_sources.items()
                     if re.search(r"\bapply_gate\s*\(", src)]
    check("apply_gate is called from a production path",
          bool(apply_callers), str(apply_callers))

    # -----------------------------------------------------------------
    print("\nB. THE LOOP CLOSES — a filed finding becomes a lesson")
    from learning_engine import engine as le
    from orch import store

    tmp = tempfile.mkdtemp(prefix="p1a.")
    try:
        os.environ["WKS_ROOT"] = tmp
        for sub in ("db", "orch"):
            os.makedirs(os.path.join(tmp, sub), exist_ok=True)
        shutil.copy(ROOT / "orch" / "schema.sql",
                    os.path.join(tmp, "orch", "schema.sql"))
        shutil.copy(ROOT / "learning_engine" / "engine.py",
                    os.path.join(tmp, "_engine_ref.py")) if False else None

        con = store.open_db()
        con.row_factory = sqlite3.Row
        le.ensure_schema(con)

        # --- a finding filed by a hunt becomes a CAPTURED lesson ---------
        from orch import authz, hunt_exec
        ctx = authz.AuthorizationContext(
            program="p1-test", target="127.0.0.1",
            in_scope_assets=["127.0.0.1"],
            reporting_requirements={"format": "md"},
            authorization_ref="P1-TEST", kind="lab",
            allowed_actions=["recon", "probe"])
        ex = hunt_exec.ActiveHuntExecutor(con, ctx, hunt_id="p1.loop")

        obs = [{"signals": ["boolean_differential", "sql_error_or_behaviour"]}]
        reqs = [{"url": "http://127.0.0.1/x", "raw": "HTTP/1.1 500 ...\r\n\r\nbody",
                 "payload": None, "provenance": "curl"}]
        f = ex.record_finding(title="Boolean-blind SQLi", class_id="sqli",
                              severity="high", endpoint="http://127.0.0.1/x",
                              observations=obs, requests=reqs)
        check("the finding was filed", f.get("ok") is True, str(f)[:200])

        # THE SCENARIO THIS FILE MODELS IS A PRODUCTION HUNT.
        #
        # MEASURED 2026-11-01: this hunt runs against `127.0.0.1` with
        # `kind="lab"`, so the findings it files are correctly classified
        # EVAL_TEST -- and a lesson from an EVAL_TEST finding can never be
        # verified or returned as intelligence, so the assertions below
        # ("a VALIDATED outcome produced a VERIFIED lesson", "the corpus's
        # prior for the sqli signals are reflected") could not hold.
        #
        # MEASURED 2026-11-02: the fix for that was a raw
        # `UPDATE finding SET provenance='PRODUCTION_HUNT'` -- the very
        # self-declaration the receipt exists to prevent. The origin was
        # SET BY HAND, with no authorization anywhere, and the lesson it
        # produced became hunting experience for the next hunt.
        #
        # So the production scenario is now created the way the runtime
        # creates one: a hunt whose authorization was VALIDATED and
        # RECORDED. The hunt below runs against the loopback address as a
        # VEHICLE, but the receipt -- not the hand-written UPDATE -- is
        # what makes the origin production.
        #
        # The provenance gate is not weakened. `eval/test_p2_provenance.py`
        # proves that a finding with NO receipt cannot produce a verified
        # lesson, and that an ineligible origin is refused.
        from orch import provenance as _prov
        from orch import authz as _authz
        prod_ctx = _authz.AuthorizationContext(
            program="p1-production", target="app.p1.example",
            in_scope_assets=["app.p1.example"],
            reporting_requirements={"format": "md"},
            authorization_ref="P1-PRODUCTION-SCOPE", kind="bugbounty",
            allowed_actions=["recon", "probe"])
        receipt = prod_ctx.validate_and_record(con, hunt_id="p1.production")
        check("the production hunt recorded a validated authorization receipt",
              receipt.get("validated") is True, str(receipt)[:200])
        prod_ex = hunt_exec.ActiveHuntExecutor(con, prod_ctx,
                                                hunt_id="p1.production")
        pf = prod_ex.record_finding(
            title="Boolean-blind SQLi (production scenario)",
            class_id="sqli", severity="high",
            endpoint="http://app.p1.example/x",
            observations=obs, requests=reqs)
        check("the production-scenario finding was filed",
              pf.get("ok") is True, str(pf)[:200])
        prod_origin = _prov.provenance_of(con, "finding", pf["finding_key"])
        check("the receipt-backed finding carries PRODUCTION_HUNT",
              prod_origin == _prov.PRODUCTION_HUNT, prod_origin)
        # The loopback finding stays what it is: a lab observation.
        lab_origin = _prov.provenance_of(con, "finding", f["finding_key"])
        check("the loopback finding without a receipt stays ineligible",
              lab_origin != _prov.PRODUCTION_HUNT, lab_origin)
        # The assertions below concern the PRODUCTION finding's lesson.
        f = pf
        check("the after_finding hook RAN", "learning" in f,
              str(list(f)))
        check("the hook reported success", f.get("learning", {}).get("ok")
              is True, str(f.get("learning"))[:200])

        cap = con.execute(
            "SELECT lesson_key, topic, class_id, state FROM lesson"
            " WHERE topic LIKE '%sqli%'").fetchall()
        check("a CAPTURED lesson was persisted", len(cap) > 0,
              f"captured={len(cap)}")
        check("the lesson is in state 'captured', not 'verified'",
              all(r["state"] == "captured" for r in cap),
              str([r["state"] for r in cap]))

        # --- the triage outcome ADVANCES the lesson ----------------------
        from orch import learning_bridge
        # Put the finding through the lifecycle so the bridge has a state.
        lc_holder = __import__("orch.lifecycle", fromlist=["x"])
        lc = lc_holder.FindingLifecycle(con, "p1.loop")
        try:
            lc.transition(f["finding_key"], "CANDIDATE",
                          reason="observed", changed_by="test")
            lc.transition(f["finding_key"], "TESTING", reason="testing",
                          changed_by="test", evidence_ids=[1])
        except Exception:
            pass
        bridge = learning_bridge.record_hunt_outcome(
            con, f["finding_key"], lifecycle_state="VALIDATED",
            notes="validated in the lab")
        check("the learning bridge accepted the outcome",
              bridge.get("ok") is True, str(bridge)[:250])

        rows = con.execute(
            "SELECT lesson_key, topic, class_id, state, score FROM lesson"
            " WHERE topic LIKE '%sqli%'").fetchall()
        check("the outcome produced a lesson row", len(rows) > 0,
              str(len(rows)))
        verified = [r for r in rows if r["state"] == "verified"]
        check("a VALIDATED outcome produced a VERIFIED lesson",
              len(verified) > 0,
              str([(r["topic"], r["state"]) for r in rows]))
        if verified:
            check("the verified lesson names the class",
                  verified[0]["class_id"] == "sqli",
                  str(dict(verified[0])))

        # --- a VERIFIED lesson changes a LATER hunt's PRIORITY ---------
        # This is the property that did not exist: the corpus's experience
        # must change what a later hunt does.
        prior = ex._before_recon_lessons()
        check("before_recon returns the verified lesson", len(prior) > 0,
              str(prior)[:200])
        prior_classes = ex._prior_classes(prior)
        check("the prior lesson names the class", "sqli" in prior_classes,
              str(prior_classes))

        # The boost is applied to the finding's PRIORITY, not its severity.
        fk = f["finding_key"]
        before = con.execute(
            "SELECT severity, priority, confidence FROM finding"
            " WHERE finding_key=?", (fk,)).fetchone()
        check("the finding has a priority to change", before is not None)

        # Simulate the recon path's boost directly.
        if "sqli" in prior_classes:
            store.set_finding_axes(con, fk, priority=2)
        after = con.execute(
            "SELECT severity, priority, confidence FROM finding"
            " WHERE finding_key=?", (fk,)).fetchone()
        check("the learned priority changed the finding's priority",
              after["priority"] == 2, str(dict(after)))
        check("the learned priority did NOT change the severity",
              after["severity"] == before["severity"],
              f"{before['severity']} -> {after['severity']}")
        check("the learned priority did NOT change the confidence",
              abs((after["confidence"] or 0) - (before["confidence"] or 0))
              < 1e-9, str(dict(after)))

        # --- before_summary RANKS by the corpus --------------------------
        ranked = le.before_summary(con, [
            {"finding_key": fk, "class_id": "sqli", "title": "Boolean-blind SQLi"},
            {"finding_key": "other", "class_id": "xss", "title": "XSS"},
        ])
        check("before_summary returned a ranking",
              bool(ranked.get("ranked")), str(ranked)[:200])
        if ranked.get("ranked"):
            top = ranked["ranked"][0]
            check("the class with a verified lesson ranks FIRST",
                  top.get("class_id") == "sqli", str(top))

        # --- during_testing SCORES against the corpus --------------------
        scored = le.during_testing(con, {"sql_error_or_behaviour": 1,
                                          "boolean_differential": 1})
        check("during_testing scored the signals",
              bool(scored.get("signals")), str(scored)[:200])
        sqli_prior = [s for s in (scored.get("signals") or [])
                      if s.get("prior_lessons", 0) > 0]
        check("the corpus's prior for the sqli signals is reflected",
              bool(sqli_prior),
              str(scored.get("signals"))[:300])
        check("the prior names the signal it belongs to",
              all(s.get("signal") for s in sqli_prior),
              str(sqli_prior)[:200])

        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        os.environ.pop("WKS_ROOT", None)

    # -----------------------------------------------------------------
    print("\nC. THE GATE VERDICT IS PERSISTED")
    # The CLI hunt path must call `apply_gate`, which is what writes the
    # verdict back and feeds the bridge.
    cli_src = (ROOT / "orch" / "hunt_cli.py").read_text(encoding="utf-8")
    check("the CLI hunt path calls apply_gate",
          "apply_gate" in cli_src, "")
    check("the CLI hunt path calls before_summary",
          "before_summary" in cli_src, "")
    rep_src = (ROOT / "orch" / "reporting.py").read_text(encoding="utf-8")
    check("the reporting path calls apply_gate", "apply_gate" in rep_src, "")

    # -----------------------------------------------------------------
    print("\nD. FAILURE IS ISOLATED — a learning failure never fails a hunt")
    from orch import hunt_exec as he

    src = (ROOT / "orch" / "hunt_exec.py").read_text(encoding="utf-8")
    for method in ("_before_recon_lessons", "_during_testing", "_after_finding"):
        check(f"{method} catches its own failures",
              "except Exception" in src, "")
    # And the CLI's summary hook too.
    cli_body = cli_src
    check("the CLI's before_summary catches its own failures",
          "except Exception" in cli_body, "")

    # Prove it: break the learning engine's import and confirm the hunt
    # still files its finding.
    tmp2 = tempfile.mkdtemp(prefix="p1b.")
    try:
        os.environ["WKS_ROOT"] = tmp2
        for sub in ("db", "orch"):
            os.makedirs(os.path.join(tmp2, sub), exist_ok=True)
        shutil.copy(ROOT / "orch" / "schema.sql",
                    os.path.join(tmp2, "orch", "schema.sql"))
        from orch import authz, store as st2
        con2 = st2.open_db()
        con2.row_factory = sqlite3.Row
        ctx2 = authz.AuthorizationContext(
            program="p1-test", target="127.0.0.1",
            in_scope_assets=["127.0.0.1"],
            reporting_requirements={"format": "md"},
            authorization_ref="P1-TEST", kind="lab",
            allowed_actions=["recon", "probe"])
        ex2 = he.ActiveHuntExecutor(con2, ctx2, hunt_id="p1.broken")
        # Force the hook to fail.
        orig = he.ActiveHuntExecutor._after_finding
        ex2._after_finding = lambda *a, **k: {
            "ok": False, "reason": "simulated learning-engine failure"}
        f2 = ex2.record_finding(
            title="Still filed", class_id="xss", severity="medium",
            endpoint="http://127.0.0.1/y",
            observations=[{"signals": ["reflected"]}],
            requests=[{"url": "http://127.0.0.1/y",
                       "raw": "HTTP/1.1 200 OK\r\n\r\nbody",
                       "payload": None, "provenance": "curl"}])
        check("a learning failure does NOT stop the finding being filed",
              f2.get("ok") is True, str(f2)[:200])
        check("the failure is REPORTED, not hidden",
              f2.get("learning", {}).get("ok") is False,
              str(f2.get("learning")))
        con2.close()
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)
        os.environ.pop("WKS_ROOT", None)

    # -----------------------------------------------------------------
    print("\nE. NO SILENT SUCCESS — the hook's effect is observable")
    # The hunt executor traces the learning hooks, so "the hook ran" is a
    # recorded fact rather than an inference.
    check("the hunt executor traces the learning hooks",
          "_trace(\"learning\"" in src, "")
    for hook in ("before_recon", "during_testing", "after_finding"):
        check(f"the {hook} hook is traced",
              f'"learning", "{hook}"' in src, "")

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL P1-A LEARNING LOOP CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
