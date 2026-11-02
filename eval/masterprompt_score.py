"""The scorer. Run it; the number is the deliverable.

    python eval/masterprompt_score.py              # score out of 100
    python eval/masterprompt_score.py --section 48 # one section
    python eval/masterprompt_score.py --json
    python eval/masterprompt_score.py --selftest   # prove the harness can FAIL

The `--selftest` mode is the control case and is not optional. It injects a
defect into each enforcement point and asserts the corresponding check FLIPS to
failing. A harness whose checks all pass in a deliberately broken world is
certifying nothing, which is worse than having no harness — and the previous
build of this system proved exactly that: 105 self-authored checks were green
while an independent agent found 14 defects, including every critical one.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

import mp_checks_1 as P1           # noqa: E402
import mp_checks_2 as P2           # noqa: E402

ALL_CHECKS = P1.CHECKS

# The prompt's section headings, so a reader can see coverage at a glance and
# so a MISSING section is a visible hole rather than an absent line.
SECTIONS = {
    "§1": "SYSTEM IDENTITY", "§2": "PRIMARY OPERATING PRINCIPLE",
    "§3": "AUTONOMY BOUNDARY", "§4": "AUTHORIZATION GATE",
    "§5": "AMBIGUOUS SCOPE", "§6": "OUT-OF-SCOPE DISCOVERIES",
    "§7": "FORBIDDEN TECHNIQUES", "§8": "HUNT INITIALIZATION",
    "§9": "DYNAMIC HUNTING PLAN", "§10": "GLOBAL ORCHESTRATOR",
    "§11": "DYNAMIC TASK GRAPH", "§12": "RECONNAISSANCE ENGINE",
    "§13": "TOOL AGILITY", "§14": "BURP SUITE", "§15": "BROWSER", "§16": "WSL",
    "§17": "AUTHENTICATED HUNTING", "§18": "ATTACK SURFACE MODEL",
    "§19": "HYPOTHESIS ENGINE", "§20": "SPECIALIZED AGENTS",
    "§21": "AGENT DELEGATION", "§22": "AGENT SELECTION",
    "§23": "AGENT OUTPUT CONTRACT", "§24": "PARALLEL EXECUTION",
    "§25": "DYNAMIC RESOURCE MANAGEMENT", "§26": "TECHNIQUE FAILURE",
    "§27": "ATTACK PATH REASONING", "§28": "VULNERABILITY CHAINING",
    "§29": "MAXIMUM SAFE PROOF", "§30": "UNKNOWN BEHAVIOR",
    "§31": "RESEARCH ENGINE", "§32": "SOURCE QUALITY",
    "§33": "LEARNING-HUNTING INTEGRATION", "§34": "KNOWLEDGE ADMISSION",
    "§35": "FINDING LIFECYCLE", "§36": "VALIDATION", "§37": "WEAK EVIDENCE",
    "§38": "DUPLICATE DETECTION", "§39": "EVIDENCE ENGINE",
    "§40": "RETESTING", "§41": "TARGET CHANGE DETECTION",
    "§42": "FAILURE RECOVERY", "§43": "TOOL / AGENT FAILURE",
    "§44": "PROVIDER POLICY", "§45": "RATE LIMITS",
    "§46": "NO-FINDING STRATEGY", "§47": "HUNT COMPLETION",
    "§48": "FINAL VALIDATION GATE", "§49": "REPORTING",
    "§50": "REPORT QUALITY", "§51": "FINAL HUNT DOSSIER",
    "§52": "NEXT-CYCLE STATE", "§53": "RUNTIME ISOLATION",
    "§54": "SIMPLE CYBER ARCHITECTURE", "§55": "DOMAIN METHODOLOGY",
    "§56": "CORE DECISION RULES", "§57": "GLOBAL PRIORITY ORDER",
    "§58": "OBSERVE -> DECIDE -> ACT LOOP", "§59": "HUNTING STATE MACHINE",
    "§60": "NON-NEGOTIABLE BEHAVIOR", "§61": "DEFINITION OF SUCCESS",
    "§62": "FINAL DIRECTIVE",
}


#: Rows a check may create under these prefixes. The runner sweeps them after
#: EVERY check, so a check that raises part-way through still cannot leave
#: state behind in the live corpus.
SCRIPTS = ("score.%", "hunt.score.%", "unknown.%", "hunt.unknown.%",
           "event.score%", "cp.score%")

#: Dependencies are swept before their tasks. A dangling edge outlives its own
#: row and is invisible to a task-only cleanup — which is exactly how four of
#: them reached the live graph and turned the self-audit red.
DEP_SCRIPTS = tuple(f"%{p}%" for p in SCRIPTS)


def sweep(con) -> dict:
    """Delete every probe row this harness could have created.

    Idempotent and narrow: only rows whose keys match a probe prefix. It never
    touches a real hunt, a real finding, or knowledge.
    """
    out = {"task_dep": 0, "task": 0, "other": 0}
    like = " OR ".join(["task_key LIKE ?"] * len(DEP_SCRIPTS))
    # Both clauses need their own WHERE. An f-string that reuses `like` on
    # the right of OR reads fine and is a syntax error, which is what the
    # first draft did: `... WHERE a OR b LIKE ?` binds b as an alias.
    cur = con.execute(f"DELETE FROM task_dep WHERE ({like})"
                      f" OR ({like})", DEP_SCRIPTS * 2)
    out["task_dep"] = cur.rowcount if cur.rowcount > 0 else 0
    like2 = " OR ".join(["task_key LIKE ?"] * len(SCRIPTS))
    cur = con.execute(f"DELETE FROM task WHERE {like2}", SCRIPTS)
    out["task"] = cur.rowcount if cur.rowcount > 0 else 0
    for table, col, pats in (
            ("agent_failure", "task_key", SCRIPTS),
            ("recovery_attempt", "task_key", SCRIPTS),
            ("revalidation_queue", "finding_key", ("score.%", "e2e.%",
                                                  "t3_%", "t4_%")),
            ("dedup_decision", "finding_key", ("score.%",)),
            ("finding_state", "finding_key", ("score.%",)),
    ):
        try:
            w = " OR ".join([f"{col} LIKE ?" for _ in pats])
            cur = con.execute(f"DELETE FROM {table} WHERE {w}", pats)
            out["other"] += cur.rowcount if cur.rowcount > 0 else 0
        except Exception:  # noqa: BLE001 - the table may not exist yet
            pass
    try:
        cur = con.execute(
            "DELETE FROM finding WHERE finding_key LIKE 'score.%'"
            " OR finding_key LIKE 'e2e.%'")
        out["other"] += cur.rowcount if cur.rowcount > 0 else 0
        cur = con.execute("DELETE FROM evidence WHERE finding_id NOT IN"
                          " (SELECT id FROM finding)")
        out["other"] += cur.rowcount if cur.rowcount > 0 else 0
    except Exception:  # noqa: BLE001
        pass
    con.commit()
    return out


def _live_connection():
    from orch import store as ostore
    prev = os.environ.get("WKS_ROOT")
    os.environ["WKS_ROOT"] = str(ROOT)
    try:
        for m in [m for m in list(sys.modules)
                  if m.startswith(("wks", "orch"))]:
            del sys.modules[m]
        return ostore.open_db(create=True), prev
    except Exception:  # noqa: BLE001
        return None, prev


def run_one(c: dict) -> dict:
    t0 = time.time()
    try:
        ok, detail = c["fn"]()
        res = {**c, "passed": bool(ok), "detail": str(detail)[:400],
               "ms": round((time.time() - t0) * 1000)}
    except Exception as e:  # noqa: BLE001 - a raising check is a FAILED check
        res = {**c, "passed": False,
               "detail": f"RAISED {type(e).__name__}: {e}"[:400],
               "traceback": traceback.format_exc()[-500:],
               "ms": round((time.time() - t0) * 1000)}
    # Sweep AFTER the check regardless of outcome. Per-check cleanup remains
    # the honest thing to do, but it is not the only line of defence.
    con, prev = _live_connection()
    if con is not None:
        try:
            res["swept"] = sweep(con)
        finally:
            con.close()
            if prev:
                os.environ["WKS_ROOT"] = prev
    return res


def score(checks=None, *, verbose=True) -> dict:
    checks = checks if checks is not None else ALL_CHECKS
    results = [run_one(c) for c in checks]
    passed = sum(1 for r in results if r["passed"])
    total = len(results)
    pct = round(100.0 * passed / total, 2) if total else 0.0

    by_section: dict[str, dict] = {}
    for r in results:
        d = by_section.setdefault(r["section"],
                                  {"name": SECTIONS.get(r["section"], "?"),
                                   "passed": 0, "total": 0, "failures": []})
        d["total"] += 1
        if r["passed"]:
            d["passed"] += 1
        else:
            d["failures"].append(f"{r['name']} — {r['detail'][:200]}")

    covered = sorted({r["section"] for r in results},
                     key=lambda s: int(s.lstrip("§")))
    uncovered = [s for s in SECTIONS if s not in covered]

    if verbose:
        cur = None
        for r in results:
            if r["section"] != cur:
                cur = r["section"]
                d = by_section[cur]
                mark = "OK " if d["passed"] == d["total"] else "!! "
                print(f"\n{mark}{cur:5} {d['name']}  "
                      f"[{d['passed']}/{d['total']}]")
            print(f"    [{'PASS' if r['passed'] else 'FAIL'}] "
                  f"{r['kind']:4} {r['name']}")
            if not r["passed"]:
                print(f"           -> {r['detail']}")

    return {"score": pct, "passed": passed, "total": total,
            "sections": by_section, "covered_sections": covered,
            "uncovered_sections": uncovered,
            "section_coverage": f"{len(covered)}/{len(SECTIONS)}",
            "results": results}


# ---------------------------------------------------------------------------
# Selftest: prove each WIRE check can fail.
#
# Each case breaks ONE enforcement point in a throwaway copy of the module and
# asserts the check's own predicate flips. A check that cannot go red is
# decoration, so this is run before any score is believed.
# ---------------------------------------------------------------------------

def selftest() -> int:
    """Prove every enforcement point is BREAKABLE.

    POLARITY: a case PASSES when the injected defect SUCCEEDS. The case breaks
    a control and then asserts the control no longer holds; that is what makes
    it evidence that the corresponding check would go red. Asserting the
    opposite — that a working check still passes while its control is broken —
    is the error this harness exists to catch, and it is the error it caught in
    its own first version.
    """
    print("HARNESS SELFTEST — proving the checks can FAIL\n")
    results = []

    def case(label: str, section: str):
        def deco(fn):
            results.append((label, section, fn))
            return fn
        return deco

    # 1. Authorization: break asset scoping and confirm §3/§6 refuse nothing.
    @case("scope gate always allows", "§3")
    def _():
        import mp_checks_1 as P
        from orch import authz
        orig = authz.AuthorizationContext.asset_verdict
        authz.AuthorizationContext.asset_verdict = lambda self, a: "in_scope"
        try:
            # A COMPLETE context: an ambiguous one is refused before the scope
            # check runs, so the injected defect would have nothing to break.
            c = P.ctx(in_scope_assets=["a.test"])
            leaked = c.decision("exploit", asset="attacker.example")["allowed"]
        finally:
            authz.AuthorizationContext.asset_verdict = orig
        return (leaked,
                f"with asset_verdict broken, an UNKNOWN asset was allowed="
                f"{leaked} — so the §3 check, which requires refusal, FAILS")

    # 2. Hypothesis disproof requirement removed.
    @case("hypothesis accepts no disproof", "§19")
    def _():
        from orch import hypothesis as H
        orig = H.HypothesisEngine.propose
        H.HypothesisEngine.propose = (
            lambda self, s, *, class_id, disproof, origin, basis=None,
            confidence=0.0: "hyp.fake")
        try:
            root = P1.sandbox("st_hyp")
            con = P1.fresh_db(root)
            e = H.HypothesisEngine(con, "st")
            accepted = False
            try:
                e.propose("a claim with nothing to refute it at all",
                          class_id="idor", disproof="", origin="s")
                accepted = True
            except ValueError:
                pass
            con.close()
            shutil.rmtree(root.parent, ignore_errors=True)
        finally:
            H.HypothesisEngine.propose = orig
        return (accepted,
                f"with the disproof guard removed an unfalsifiable hypothesis "
                f"was ACCEPTED={accepted} — so the §19.1 check, which requires "
                f"refusal, FAILS")

    # 3. Output contract stops downgrading self-validation.
    @case("agent self-validation is trusted", "§23")
    def _():
        from orch import agentkit
        orig = agentkit.parse_output
        src = orig.__doc__  # keep reference
        def trusting(raw, *, run_key="", task_key="", con=None):
            env = orig(raw, run_key=run_key, task_key=task_key,
                       con=None)
            env["type"] = str(raw.get("type") or "").upper()
            env["downgraded"] = False
            return env
        agentkit.parse_output = trusting
        try:
            out = agentkit.parse_output({"type": "VALIDATED_FINDING",
                                         "payload": "trust me"})
            trusted = out["type"] == "VALIDATED_FINDING"
        finally:
            agentkit.parse_output = orig
        return (trusted,
                f"with the downgrade removed an agent marked its own finding "
                f"VALIDATED={trusted} — so the §23 check, which requires a "
                f"downgrade, FAILS")

    # 4. Lifecycle transition check removed.
    @case("illegal lifecycle jump allowed", "§35")
    def _():
        from orch import lifecycle as L
        orig = L.FindingLifecycle.transition

        def permissive(self, finding_key, to_state, **kw):
            self._write(finding_key, to_state, kw.get("changed_by", ""),
                        kw.get("reason", ""), None, None)
            return {"ok": True, "from": "?", "to": to_state}

        L.FindingLifecycle.transition = permissive
        try:
            root = P1.sandbox("st_life")
            con = P1.fresh_db(root)
            from orch import store
            store.add_finding(con, "X", "probe", target="t",
                              hypothesis="x" * 40, severity="low")
            con.commit()
            lc = L.FindingLifecycle(con, "st")
            jumped = False
            try:
                lc.transition("X", "REPORT_READY")
                jumped = True
            except L.IllegalTransition:
                pass
            con.close()
            shutil.rmtree(root.parent, ignore_errors=True)
        finally:
            L.FindingLifecycle.transition = orig
        return (jumped,
                f"with the transition check removed OBSERVED->REPORT_READY "
                f"succeeded={jumped} — so the §35 check, which requires the "
                f"jump to be refused, FAILS")

    # 5. Provider fallback permitted.
    @case("provider fallback allowed", "§44")
    def _():
        from orch import policy
        p = policy.ProviderPolicy(provider="nous", model="m")
        orig = policy.ProviderPolicy.route
        try:
            # Replacing the exception CLASS is not enough: `route()` still
            # executes `raise`, so the case raised the replacement instead of
            # permitting the switch. The METHOD is what must be replaced.
            policy.ProviderPolicy.route = (
                lambda self, requested_provider="", requested_model="": {
                    "provider": requested_provider or self.provider,
                    "model": requested_model or self.model,
                    "switched": bool(requested_provider or requested_model)})
            switched = p.route(requested_provider="openai")["provider"]
        finally:
            policy.ProviderPolicy.route = orig
        return (switched == "openai",
                f"with the refusal removed the policy ROUTED TO "
                f"{switched!r} — so the §44 check, which requires a refusal, "
                f"FAILS")

    # 6. Rate limiter never denies.
    @case("rate limiter never denies", "§45")
    def _():
        from orch import policy
        orig = policy.RateGovernor.acquire
        policy.RateGovernor.acquire = (
            lambda self, **kw: {"allowed": True, "spent": 0})
        try:
            c = P1.ctx(rate_limits={"requests_per_second": 0.01, "burst": 1,
                                     "per_host_per_minute": 2,
                                     "concurrency": 1})
            g = policy.RateGovernor(c)
            allowed = sum(1 for _ in range(10)
                          if g.acquire(host="h", actor="a")["allowed"])
        finally:
            policy.RateGovernor.acquire = orig
        return (allowed > 4,
                f"with the limiter disabled {allowed}/10 requests were allowed "
                f"— so the §45 check, which requires denials, FAILS")

    # 7. Final gate trusts the caller's verdict.
    @case("final gate trusts the caller", "§48")
    def _():
        from orch import finalgate
        root = P1.sandbox("st_gate")
        con = P1.fresh_db(root)
        from orch import store
        store.add_finding(con, "G", "probe", target="app.acme.test",
                          hypothesis="g" * 40, severity="high")
        con.commit()
        # Walk the finding to REPORT_READY FIRST. With the real transition
        # checks in place the rubber-stamp gate would otherwise be blocked by a
        # CANDIDATE -> REPORT_READY IllegalTransition, so the case would raise
        # instead of showing a rubber stamp releasing an unvalidated finding.
        from orch import lifecycle as _lc
        _lc.FindingLifecycle(con, "st").transition(
            con.execute("SELECT finding_key FROM finding LIMIT 1").fetchone()[0],
            "CANDIDATE", reason="selftest setup")
        for st in ("TESTING", "VALIDATED", "EVIDENCE_COMPLETE"):
            from orch import lifecycle as _lc2
            _lc2.FindingLifecycle(con, "st").transition("G", st,
                                                       reason="selftest setup")
        from orch import lifecycle as _lc3
        _lc3.FindingLifecycle(con, "st").retest_due("G",
                                                     trigger="report_preparation")
        from orch import lifecycle as _lc4
        _lc4.FindingLifecycle(con, "st").transition("G", "REPORT_READY",
                                                    reason="selftest setup")
        orig = finalgate.gate
        # `apply_gate` reads `stages` back, so a fake gate that omits it raises
        # KeyError instead of demonstrating a rubber stamp.
        all_pass = {n: {"passed": True, "detail": "rubber stamp",
                        "critical": True} for n, _, _ in finalgate.GATE_STAGES}
        finalgate.gate = lambda con, k, **kw: {
            "finding_key": k, "verdict": "REPORT_READY", "report_ready": True,
            "stages": all_pass, "failed_critical": [], "failed_other": [],
            "return_to": None, "lifecycle_state": "VALIDATED",
            "validation_vector": {}, "score": "6/6"}
        try:
            out = finalgate.apply_gate(con, "G", {"verdict": "REPORT_READY"})
        finally:
            finalgate.gate = orig
        con.close()
        shutil.rmtree(root.parent, ignore_errors=True)
        return (out == "REPORT_READY",
                f"with a rubber-stamp gate, an unvalidated finding was RELEASED "
                f"as {out} — so the §48 check, which requires NO_REPORT, FAILS")

    # 8. Out-of-scope ledger stops refusing.
    @case("out-of-scope asset becomes testable", "§6")
    def _():
        from orch import authz
        root = P1.sandbox("st_scope")
        con = P1.fresh_db(root)
        c = P1.ctx()
        led = authz.ScopeLedger(con, c)
        led.record("cdn.acme-static.com", discovered_by="probe")
        orig = authz.ScopeLedger.permit_testing
        authz.ScopeLedger.permit_testing = (
            lambda self, a: {"allowed": True, "asset": a, "tested": True})
        try:
            permitted = led.permit_testing("cdn.acme-static.com")["allowed"]
        finally:
            authz.ScopeLedger.permit_testing = orig
        con.close()
        shutil.rmtree(root.parent, ignore_errors=True)
        return (permitted,
                f"with permit_testing broken an out-of-scope asset became "
                f"TESTABLE={permitted} — so the §6 check, which requires a "
                f"refusal, FAILS")

    # 9. Report quality checklist always passes.
    @case("report checklist rubber-stamps", "§50")
    def _():
        from orch import finalgate
        orig = finalgate.REPORT_CHECKS
        finalgate.REPORT_CHECKS = (("always", r"(?s).*"),)
        try:
            root = P1.sandbox("st_rq")
            p = root / "bad.md"
            p.write_text("probably vulnerable", encoding="utf-8")
            res = finalgate.report_quality(p)
            shutil.rmtree(root.parent, ignore_errors=True)
        finally:
            finalgate.REPORT_CHECKS = orig
        return (res["ok"],
                f"with a rubber-stamp checklist a one-line report PASSED="
                f"{res['ok']} — so the §50 check, which requires it to fail, "
                f"FAILS")

    # 10. Safe proof stops refusing destructive tiers.
    @case("destructive proof tier allowed", "§29")
    def _():
        from orch import policy
        orig = policy.PROOF_TIERS
        policy.PROOF_TIERS = (("read_only_response", "r", "authorized", False),
                              ("denial_of_service", "d", "authorized", True))
        try:
            c = P1.ctx()
            d = policy.safe_proof(c, tier="denial_of_service")
        finally:
            policy.PROOF_TIERS = orig
        return (d["allowed"],
                f"with the NEVER list weakened a DoS proof was ALLOWED="
                f"{d['allowed']} — so the §29 check, which requires a "
                f"refusal, FAILS")

    passed = 0
    for label, section, fn in results:
        try:
            ok, detail = fn()
        except Exception as e:  # noqa: BLE001
            ok, detail = False, f"selftest case raised {type(e).__name__}: {e}"
        passed += 1 if ok else 0
        print(f"  [{'PASS' if ok else 'FAIL'}] {section:5} {label}")
        print(f"         {detail}")

    print(f"\nSELFTEST: {passed}/{len(results)} enforcement points proven "
          f"breakable")
    if passed != len(results):
        print("A check that cannot go red certifies nothing. Fix the harness "
              "before trusting any score.")
    return 0 if passed == len(results) else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--section", help="run one section only, e.g. 48")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    a = ap.parse_args()

    if a.selftest:
        return selftest()

    checks = ALL_CHECKS
    if a.section:
        want = a.section if a.section.startswith("§") else f"§{a.section}"
        checks = [c for c in ALL_CHECKS if c["section"] == want]
        if not checks:
            print(f"no checks for {want}")
            return 2

    r = score(checks, verbose=not a.quiet and not a.json)
    if a.json:
        print(json.dumps({k: v for k, v in r.items() if k != "results"},
                         indent=2, default=str))
    else:
        print("\n" + "=" * 78)
        print(f"HUNTING ENGINE SCORE: {r['score']}/100   "
              f"({r['passed']}/{r['total']} checks, "
              f"{r['section_coverage']} sections covered)")
        if r["uncovered_sections"]:
            print(f"UNCOVERED SECTIONS: {', '.join(r['uncovered_sections'])}")
        bad = {s: d for s, d in r["sections"].items() if d["passed"] != d["total"]}
        if bad:
            print(f"FAILING SECTIONS: {', '.join(sorted(bad, key=lambda s: int(s.lstrip('§'))))}")
        print("=" * 78)
    return 0 if r["score"] == 100.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())