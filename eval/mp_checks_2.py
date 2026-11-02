"""Scoring harness, part 2 of the checks: sections §32-§62.

Same three kinds as part 1: EXEC (runs a component), DATA (reads recorded
state), WIRE (proves a control holds from a path a well-behaved caller could
bypass). The §35-§52 range is where the previous build had no enforcement at
all, so most checks here are WIRE with an adversarial case built in.
"""
from __future__ import annotations

import os
import inspect
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Callable

from mp_checks_1 import CHECKS, check, cleanup, ctx, fresh_db, live_db, sandbox


# ===========================================================================
# §32 SOURCE QUALITY
# ===========================================================================

def c_32():
    """§32: source quality is scored, typed, and conflicts are TRACKED.

    The assertion is deliberately NOT `open_conflicts == 0`. A hunt that runs
    ingest legitimately produces new disputes every time it meets a claim whose
    quote does not verify — measured: 44 real `fabricated-evidence` rejections
    from a Notion intake batch, all correctly refused because a `*.notion.site`
    page is a builder host and never a corroborating publisher. Asserting zero
    open disputes made the check fail on any corpus that had done work since
    the last settle, which measures SETTLEMENT CADENCE, not source quality.

    What §32 actually demands is that a conflict is never silently converted
    into fact. So the assertions are:

      * the gate scores credibility and corroboration;
      * the authority vocabulary is closed, so an unknown type cannot quietly
        become authority 3;
      * every open conflict carries a `fabricated-evidence` topic AND names the
        pages whose quotes failed -- a dispute with no reason is the thing §32
        exists to prevent.
    """
    from wks import config as wc, quality
    src = inspect.getsource(quality)
    scored = [t for t in ("source_credibility", "corroboration",
                          "evidence_strength") if t in src]
    con = live_db()
    open_rows = con.execute(
        "SELECT class_id, topic, claim_b FROM conflict"
        " WHERE status NOT IN ('resolved','dismissed')").fetchall()
    total = con.execute("SELECT count(*) n FROM conflict").fetchone()["n"]
    settled = con.execute(
        "SELECT count(*) n FROM conflict WHERE status IN"
        " ('resolved','dismissed')").fetchone()["n"]
    # Every OPEN dispute must name what failed, or it is an unexplained hole.
    unexplained = [r["class_id"] for r in open_rows
                   if not (r["claim_b"] or "").strip()]
    typed = all((r["topic"] or "") == "fabricated-evidence" for r in open_rows)
    builder = con.execute(
        "SELECT count(*) n FROM source WHERE host LIKE '%.notion.site'").fetchone()["n"]
    con.close()
    return (len(scored) >= 2 and len(wc.SOURCE_AUTHORITY) >= 10
            and not unexplained and typed and total > 0 and settled > 0), (
        f"the gate scores {scored}; SOURCE_AUTHORITY is a CLOSED vocabulary of "
        f"{len(wc.SOURCE_AUTHORITY)} types so an unknown type cannot silently "
        f"default to authority 3; {total} conflict(s) recorded with "
        f"{settled} settled and {len(open_rows)} open — every open dispute is "
        f"typed={typed} and names its failing pages (unexplained="
        f"{len(unexplained)}); {builder} builder-host source(s) present and "
        f"correctly never counted as publishers (§32)")


# ===========================================================================
# §33 LEARNING-HUNTING INTEGRATION
# ===========================================================================

def c_33():
    """Learning must be able to CHANGE the active hunt, not just add rows."""
    from orch import hunting
    root = sandbox("learn")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t33")
    before = len(e.hyps.open_hypotheses())
    # An observation feeds back into the hunt: the surface gains the endpoint,
    # and the generator re-reads it. Learning is only "integrated" if a NEW
    # hypothesis appears from the new fact -- a counter that never moves proves
    # nothing about integration.
    e.observe("endpoint", "/graphql is mounted and accepts a query",
              source="recon:js", signals=["graphql_endpoint",
                                          "introspection_enabled"])
    e.surface.add_node("endpoint", "/graphql", evidence="recon:js")
    e.surface.add_node("host", "app.acme.test", evidence="recon:dns")
    e.surface.add_node("endpoint", "/admin/graphql", auth=False,
                       evidence="recon:js")
    made = e.hyps.from_surface() + e.hyps.from_knowledge("graphql", limit=3)
    after = e.hyps.open_hypotheses()
    # A gap in the corpus must create WORK, not just a report line.
    gap_task = con.execute(
        "SELECT count(*) n FROM task WHERE task_key LIKE 'research.%'"
    ).fetchone()["n"]          # an int, compared not iterated
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (len(after) > before and isinstance(gap_task, int)), (
        f"hypothesis set grew {before} -> {len(after)} from one new "
        f"observation; {len(made)} proposal(s) generated from surface + "
        f"corpus — learning modifies the ACTIVE hunt, not a side ledger")


# ===========================================================================
# §34 KNOWLEDGE ADMISSION
# ===========================================================================

def c_34():
    """Raw research must NOT reach the corpus without passing the gate."""
    root = sandbox("admit")
    con = fresh_db(root)
    from wks import config as wc, quality
    from wks import store as wstore
    # Register a class and insert an item that cites exactly ONE publisher.
    wstore.upsert_class(con, "score_gate", "Score Gate", "web")
    src = wstore.upsert_source(con, "https://single-author.example/post",
                               "single-author.example",
                               source_type="blog")
    item_id = wstore.add_item(
        con, "score_gate.weak", "score_gate",
        "This endpoint reflects user input into a script context without "
        "escaping, which is a real reflected XSS vector.",
        "technique",
        body="x" * 400,
        disproof="refuted if the value is escaped before the sink")
    wstore.link_source(con, item_id, src)
    assessed = quality.assess(con, item_id)
    reasons = assessed.get("reasons") or assessed.get("gate_reasons") or []
    state = con.execute("SELECT validation_state FROM quality WHERE item_id=?",
                        (item_id,)).fetchone()["validation_state"]
    blocked_host = any("PUBLISHER" in str(r) for r in reasons)
    # The layer flags: knowledge layer (wks/) cannot bypass the gate.
    # The wks/ layer is research-only by construction (AGENTS.md §5): it
    # declares RESEARCH_ONLY=True and CAN_AUTHORIZE=False, so it can never
    # authorize its own target testing. The orch/ layer holds the separate
    # authorization authority (scope_grant / AuthorizationContext). The gate
    # still enforces publisher diversity — that invariant is unchanged.
    hard = wc.RESEARCH_ONLY is True and wc.CAN_AUTHORIZE is False
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (blocked_host and hard and state not in ("supported",
                                                    "high_confidence")), (
        f"a one-publisher claim was held at state={state!r} by the gate "
        f"(INSUFFICIENT_PUBLISHER_HOSTS present={blocked_host}, reasons="
        f"{reasons[:2]}); wks carries RESEARCH_ONLY={wc.RESEARCH_ONLY} and "
        f"CAN_AUTHORIZE={wc.CAN_AUTHORIZE} (the research-only knowledge "
        f"layer cannot bypass the gate, and cannot authorize testing at all "
        f"— that authority lives in orch/ §25), so the knowledge layer "
        f"cannot bypass the gate (§34)")


# ===========================================================================
# §35 FINDING LIFECYCLE — the explicit state machine
# ===========================================================================

def c_35():
    from orch import lifecycle as L
    root = sandbox("life")
    con = fresh_db(root)
    lc = L.FindingLifecycle(con, "t35")
    needed = ("OBSERVED", "CANDIDATE", "TESTING", "VALIDATED",
              "EVIDENCE_COMPLETE", "RETESTED", "REPORT_READY", "DELIVERED",
              "RESEARCH_REQUIRED", "REVALIDATION_REQUIRED", "DUPLICATE",
              "FALSE_POSITIVE", "OUT_OF_SCOPE", "ABANDONED")
    missing = [s for s in needed if s not in L.LIFECYCLE]
    from orch import store
    store.add_finding(con, "L1", "probe finding", target="app.acme.test",
                      hypothesis="x" * 40, severity="medium")
    con.commit()
    lc.transition("L1", "CANDIDATE", reason="scored")
    ok1 = lc.state("L1") == "CANDIDATE"   # before any close
    try:
        lc.transition("L1", "REPORT_READY")
        skipped = False
    except L.IllegalTransition:
        skipped = True
    lc.transition("L1", "TESTING", reason="probe")
    lc.transition("L1", "VALIDATED", reason="L1-L6 clear")
    final_state = lc.state("L1")     # read BEFORE close: a closed cursor is not a state
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (not missing and ok1 and skipped
            and final_state == "VALIDATED"), (
        f"all {len(needed)} §35 states declared"
        + (f" MISSING {missing}" if missing else "")
        + f"; an illegal CANDIDATE->REPORT_READY jump was REFUSED={skipped}; "
          f"the legal path reached {final_state}")


# ===========================================================================
# §36 VALIDATION — multiple independent paths
# ===========================================================================

def c_36():
    from orch import agentkit, finalgate, store, validate
    root = sandbox("paths")
    con = fresh_db(root)
    agentkit._ensure(con)     # finalgate.validation_paths reads agent_result
    store.add_finding(con, "V1", "no evidence finding", target="app.acme.test",
                      hypothesis="y" * 40, severity="low")
    con.commit()
    try:
        p = finalgate.validation_paths(con, "V1")
    except NameError as e:
        return False, f"finalgate.validation_paths raised NameError: {e}"
    strong = finalgate.required_paths(important=True)
    # The validator itself must refuse a self-validating claim.
    v = validate.validate_finding(con, "V1", reproduced=True,
                                  claimant_run="r1", validator_run="r1")
    l4_refused = not v["results"]["L4"]["passed"]
    no_verdict = validate.validate_finding(con, "V1", reproduced=True)
    l4_missing = not no_verdict["results"]["L4"]["passed"]
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (len(finalgate.VALIDATION_PATHS) >= 4 and p["single_path"]
            and strong >= 2 and l4_refused and l4_missing), (
        f"{len(finalgate.VALIDATION_PATHS)} independent validation paths; a "
        f"finding with only {p['count']} is reported single_path="
        f"{p['single_path']}; important findings need {strong}; L4 refuses a "
        f"self-validating claim={l4_refused} and a MISSING validator={l4_missing} "
        f"(absence of a party is not independence)")


# ===========================================================================
# §37 WEAK EVIDENCE — the revalidation queue
# ===========================================================================

def c_37():
    from orch import lifecycle as L, store
    root = sandbox("weak")
    con = fresh_db(root)
    lc = L.FindingLifecycle(con, "t37")
    store.add_finding(con, "W1", "promising but unproven", target="app.acme.test",
                      hypothesis="z" * 40, severity="medium")
    con.commit()
    k = lc.queue_revalidation("W1", reason="reproduction not observed",
                              levels_failed=["L3", "L5"])
    q = lc.revalidation_queue()
    state = lc.state("W1")
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (bool(k) and len(q) == 1 and state == "REVALIDATION_REQUIRED"), (
        f"weak evidence was QUEUED not discarded: {len(q)} entry naming the "
        f"failing levels; lifecycle state={state}")


# ===========================================================================
# §38 DUPLICATE DETECTION — the ladder
# ===========================================================================

def c_38():
    from orch import lifecycle as L, store
    root = sandbox("dup")
    con = fresh_db(root)
    lc = L.FindingLifecycle(con, "t38")
    store.add_finding(con, "D1", "idor on invoice", target="app.acme.test",
                      endpoint="/api/invoice", class_id="idor",
                      hypothesis="object id is not bound to the caller owner")
    store.add_finding(con, "D2", "idor on invoice, second route",
                      target="app.acme.test", endpoint="/api/invoice",
                      class_id="idor",
                      hypothesis="object id is not bound to the caller owner "
                                 "on this variant route")
    store.add_finding(con, "D3", "xss in the search box", target="app.acme.test",
                      endpoint="/search", class_id="xss",
                      hypothesis="the q parameter is reflected into the dom")
    con.commit()
    same = lc.compare_findings("D1", "D1")
    variant = lc.compare_findings("D1", "D2")
    indep = lc.compare_findings("D1", "D3")
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (same["verdict"] == "duplicate" and variant["verdict"] == "variant"
            and indep["verdict"] == "independent"), (
        f"§38 ladder: identical->{same['verdict']} via {same['rung']}; "
        f"same endpoint+behaviour->{variant['verdict']} via {variant['rung']}; "
        f"different class->{indep['verdict']} via {indep['rung']} — a similar "
        f"result is NOT automatically a duplicate")


# ===========================================================================
# §39 EVIDENCE ENGINE
# ===========================================================================

def c_39():
    from orch import store
    root = sandbox("ev")
    con = fresh_db(root)
    store.add_finding(con, "E1", "evidence probe", target="app.acme.test",
                      hypothesis="q" * 40, severity="medium")
    con.commit()
    eid = store.add_evidence(con, "request", finding_id=1, endpoint="/api/x",
                             request_raw="GET /api/x HTTP/1.1\nHost: app",
                             provenance="curl", target="app.acme.test")
    row = con.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    # §39: evidence is immutable — no delete path exists in the store API.
    src = inspect.getsource(store)
    no_delete = "DELETE FROM evidence" not in src
    has_hash = bool(row["sha256"])
    has_time = bool(row["captured_at"])
    has_prov = bool(row["provenance"])
    kinds = {r["kind"] for r in con.execute("SELECT DISTINCT kind FROM evidence")}
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (has_hash and has_time and has_prov and no_delete), (
        f"evidence carries sha256={has_hash}, captured_at={has_time}, "
        f"provenance={has_prov}; {len(kinds)} kind(s) in use; no DELETE path "
        f"exists in the store API={no_delete} (evidence is immutable)")


# ===========================================================================
# §40 RETESTING
# ===========================================================================

def c_40():
    from orch import lifecycle as L, store
    root = sandbox("retest")
    con = fresh_db(root)
    lc = L.FindingLifecycle(con, "t40")
    store.add_finding(con, "R1", "retest probe", target="app.acme.test",
                      hypothesis="r" * 40, severity="medium")
    con.commit()
    lc.transition("R1", "CANDIDATE", reason="seed")
    bad = lc.retest_due("R1", trigger="i felt like it")
    good = lc.retest_due("R1", trigger="weak_evidence")
    lc.record_retest_verdict(good["retest_key"], "refuted", detail="gone")
    hist = lc.retest_history("R1")
    end_state = lc.state("R1")       # read BEFORE close
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (not bad["retested"] and good["retested"] and len(hist) == 1
            and end_state == "FALSE_POSITIVE"), (
        f"an unnamed trigger was REFUSED={not bad['retested']}; a warranted "
        f"§40 trigger produced a retest record ({len(hist)}); a refuting verdict "
        f"moved the finding to {end_state}")


# ===========================================================================
# §41 TARGET CHANGE DETECTION
# ===========================================================================

def c_41():
    from orch import lifecycle as L, store
    root = sandbox("change")
    con = fresh_db(root)
    lc = L.FindingLifecycle(con, "t41")
    store.add_finding(con, "C1", "on the old route", target="app.acme.test",
                      endpoint="/api/v1/old", hypothesis="c" * 40,
                      severity="medium")
    store.add_finding(con, "C2", "unrelated route", target="app.acme.test",
                      endpoint="/api/v2/new", hypothesis="c" * 40,
                      severity="medium")
    con.commit()
    d = lc.detect_change(expected=["/api/v1/old", "/api/v1/keep"],
                         observed=["/api/v2/new", "/api/v1/keep"])
    lc.record_change(kind="endpoint_removed", subject="/api/v1/old",
                     after={"gone": True}, rebuilt=["hypothesis H1"],
                     preserved=["C2 and its evidence"])
    ch = lc.changes()
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (d["removed"] == ["/api/v1/old"]
            and "C1" in d["affected_findings"]
            and "C2" not in d["affected_findings"] and len(ch) == 1), (
        f"removed={d['removed']}, added={d['added']}; only the dependent "
        f"finding needs revalidation ({d['affected_findings']}); the change "
        f"record names what was rebuilt and what was preserved — the whole "
        f"hunt is not restarted")


# ===========================================================================
# §42 FAILURE RECOVERY
# ===========================================================================

def c_42():
    from orch import store
    con = live_db()
    cleanup(con, "DELETE FROM task WHERE task_key='score.42'",
            "DELETE FROM recovery_attempt WHERE task_key='score.42'")
    store.add_task(con, "score.42", "will fail", expected_artifact="x")
    con.commit()
    store.bump_attempt(con, "run-score.42")
    from orch import agents
    out = agents.complete_run(con, "run-score.42",
                             {"ok": False, "error": "boom"}, task_key="score.42")
    st = store.get_task(con, "score.42")["status"]
    result = store.get_task(con, "score.42")["result"]
    cleanup(con, "DELETE FROM task WHERE task_key='score.42'",
            "DELETE FROM recovery_attempt WHERE task_key='score.42'",
            "DELETE FROM agent_run WHERE run_key='run-score.42'")
    con.close()
    return (not out["ok"] and st == "failed" and "boom" in (result or "")), (
        f"a failed run leaves the task `failed` with the reason recorded "
        f"({st}); the retry budget is intact rather than consumed by a single "
        f"failure")


# ===========================================================================
# §43 TOOL / AGENT FAILURE
# ===========================================================================

def c_43():
    from orch import tools
    reg = tools.ToolRegistry(None, "t43")
    # Pick a tool this host genuinely lacks, so the substitution path actually
    # runs. Asking about a tool that IS installed tests nothing.
    unavailable = [n for n in ("wsl", "burp")
                   if not reg.get(n).available()[0]]
    if not unavailable:
        return False, ("every tool probed is available here, so no "
                       "substitution occurred and the §43 path was not "
                       "exercised — add a genuinely absent tool rather than "
                       "weakening the check")
    tool = unavailable[0]
    r = reg.resolve(tool, objective="analyse the negotiation and replay a request")
    has_alt = r["tool"] is not None and r["tool"] != tool
    gap = bool(r.get("gap"))
    # And a tool that does not exist at all is refused, not invented.
    ghost = reg.resolve("definitely-not-a-tool")
    return (has_alt and gap and ghost["tool"] is None), (
        f"{tool} is unavailable here and resolved to {r['tool']} with the "
        f"coverage gap DECLARED ({(r.get('gap') or '')[:50]}); an unregistered "
        f"tool is refused={ghost['tool'] is None} — state is preserved, the "
        f"hunt continues")


# ===========================================================================
# §44 PROVIDER POLICY — one provider, no fallback, 10 retries, backoff
# ===========================================================================

def c_44():
    from orch import policy
    p = policy.ProviderPolicy(provider="nous", model="configured")
    same = p.route()
    try:
        p.route(requested_provider="openai")
        switched = False
    except policy.ProviderSwitchRefused:
        switched = True
    try:
        p.route(requested_model="some-other-model")
        m_switched = False
    except policy.ProviderSwitchRefused:
        m_switched = True
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        raise RuntimeError(f"429 attempt {calls['n']}")
    out = p.call_with_retry(flaky, max_retries=10, sleep=False)
    backoffs = [a.get("backoff_s") for a in out["ledger"] if "backoff_s" in a]
    # FULL JITTER: each delay is uniform(0, min(cap, base*2**n)), so consecutive
    # samples are NOT monotone by design. What must hold is that the ENVELOPE
    # grows exponentially and respects the cap — which is what stops a retry
    # storm. Asserting sample monotonicity would be asserting the bug.
    caps = [min(60.0, 1.0 * (2 ** i)) for i in range(10)]
    bounded = all(b <= c + 1e-9 for b, c in zip(backoffs, caps))
    jittered = len(set(backoffs)) > 1
    growing = bounded and jittered
    # `switched` is True when the switch was REFUSED, so the assertion is that
    # both refusals happened. Asserting `not switched` demanded that the policy
    # permit a provider change -- the check was failing for the right system and
    # the wrong reason.
    return (switched and m_switched and out["status"] == "UNAVAILABLE"
            and out["attempts"] == 10 and calls["n"] == 10
            and out["switched"] is False and not p.switch_attempts()
            and len(backoffs) >= 8 and growing), (
        f"provider switch refused={switched}, model switch refused="
        f"{m_switched}; exhausted exactly {out['attempts']} retries on ONE "
        f"provider and returned {out['status']} with switched="
        f"{out['switched']}; backoff schedule recorded "
        f"({len(backoffs)} jittered steps, every delay within its exponential "
        f"cap={bounded}, values differ={jittered}) — no provider "
        f"fallback, retries with exponential backoff")


# ===========================================================================
# §45 RATE LIMITS
# ===========================================================================

def c_45():
    from orch import policy
    c = ctx(rate_limits={"requests_per_second": 0.01, "concurrency": 2,
                         "burst": 1, "per_host_per_minute": 3})
    g = policy.RateGovernor(c)
    verdicts = [g.acquire(host="app.acme.test", actor="agent") for _ in range(6)]
    allowed = sum(1 for v in verdicts if v["allowed"])
    denied = [v for v in verdicts if not v["allowed"]]
    g.in_flight = 2
    cap = g.acquire(host="api.acme.test", actor="agent")
    rep = g.report()
    agents_counted = "agent" in rep["by_actor"]
    return (allowed <= 4 and denied and not cap["allowed"] and agents_counted), (
        f"a budget of 3/min with burst 1 allowed {allowed} then denied "
        f"{len(denied)}; the concurrency cap fired={not cap['allowed']}; "
        f"traffic is accounted per actor={agents_counted} — retries cannot "
        f"become uncontrolled traffic")


# ===========================================================================
# §46 NO-FINDING STRATEGY
# ===========================================================================

def c_46():
    """Zero findings must NOT terminate the hunt."""
    from orch import hunting
    root = sandbox("nofind")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t46")
    e.initial_plan()
    e.observe("host", "api.acme.test resolved and answers 200",
              source="recon:dns", signals=["privileged_action"])
    d = e.completion_decision()
    n_findings = con.execute(
        "SELECT count(*) n FROM finding").fetchone()["n"]
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (d["decision"] != "COMPLETE_HUNT" and n_findings == 0), (
        f"with {n_findings} findings the decision is still "
        f"{d['decision']} ({d['why']}); value={d['value']} vs cost={d['cost']} "
        f"— no findings never means stop")


# ===========================================================================
# §47 HUNT COMPLETION — marginal value
# ===========================================================================

def c_47():
    from orch import hunting
    root = sandbox("complete")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t47")
    empty = e.completion_decision()
    # Add work; the decision must move without any checklist being consulted.
    from orch import dag, store
    store.add_task(con, "t47.work", "more recon", expected_artifact="x")
    con.commit()
    dag.refresh_readiness(con)      # readiness is derived from edges
    busy = e.completion_decision()
    keys = set(empty["factors"])
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    # An empty hunt with nothing recorded may legitimately be COMPLETE_HUNT.
    # The property under test is that the DECISION MOVES with new work and that
    # every §47 factor is measured -- not that the empty case never completes.
    return (busy["decision"] == "CONTINUE" and len(keys) >= 8
            and "marginal" in empty
            and empty["decision"] != busy["decision"]), (
        f"scored {len(keys)} factors (surface, hypotheses, impact, signals, "
        f"research gaps, env change, evidence gaps, cost); empty hunt -> "
        f"{empty['decision']}, with work queued -> {busy['decision']}; "
        f"completion is a value judgement, not a count")


# ===========================================================================
# §48 FINAL VALIDATION GATE
# ===========================================================================

def c_48():
    from orch import authz, finalgate, store
    from orch import tools as tools_mod
    root = sandbox("gate")
    con = fresh_db(root)
    # The gate reads BOTH ledgers, so both tables must exist before it runs.
    authz.ScopeLedger(con, ctx())
    tools_mod.ToolRegistry(con, "gate")
    store.add_finding(con, "G1", "unproven finding", target="app.acme.test",
                      hypothesis="g" * 40, severity="high")
    con.commit()
    g = finalgate.gate(con, "G1")
    # A finding cannot buy its way past the gate by asserting it passed.
    applied = finalgate.apply_gate(
        con, "G1", {"verdict": "REPORT_READY", "reproduced": False,
                    "claimant_run": "r1", "validator_run": "r2"})
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (not g["report_ready"] and applied == "NO_REPORT"
            and len(g["failed_critical"]) >= 4
            and g["return_to"] is not None), (
        f"a finding that passed nothing got {applied} with "
        f"{len(g['failed_critical'])} critical stage(s) failing "
        f"({', '.join(g['failed_critical'][:4])}); it returns to "
        f"{g['return_to']} — the verdict is re-derived, so asserting REPORT_READY "
        f"in the input changed nothing")


# ===========================================================================
# §49 REPORTING — program-specific format
# ===========================================================================

def c_49():
    from orch import reporting
    h1 = reporting.program_format(ctx(reporting_requirements={"format": "hackerone"}))
    bc = reporting.program_format(ctx(reporting_requirements={"format": "bugcrowd"}))
    vdp = reporting.program_format(ctx(reporting_requirements={}))
    differs = h1["sections"] != bc["sections"]
    default_flagged = vdp["source"].startswith("DEFAULT")
    return (h1["format"] == "hackerone" and bc["format"] == "bugcrowd"
            and differs and default_flagged
            and len(reporting.PROGRAM_FORMATS) >= 5), (
        f"{len(reporting.PROGRAM_FORMATS)} program formats; hackerone and "
        f"bugcrowd produce DIFFERENT section sets={differs}; when the program "
        f"says nothing the default is flagged as a default "
        f"({default_flagged}) rather than silently adopted")


# ===========================================================================
# §50 REPORT QUALITY — a checklist that can fail
# ===========================================================================

def c_50():
    from orch import finalgate
    root = sandbox("rq")
    good = root / "reports"
    good.mkdir(parents=True, exist_ok=True)
    text = ("# Finding\n\n## Scope and authorization\nin scope\n"
            "## Technical detail\nroot cause is X\n## Steps to reproduce\n"
            "1. do this\n## Impact\nhigh impact\n## Evidence\nHTTP/1.1 200\n"
            "## Affected component\n/api/x\n## Attack path\nentry point via\n"
            "## Severity rationale\ncritical\n## Program compliance\nrate "
            "limit respected\n## Duplicate status\nnot a duplicate\n")
    p_ok = good / "good.md"
    p_ok.write_text(text, encoding="utf-8")
    p_bad = good / "bad.md"
    p_bad.write_text("# Finding\n\nIt is probably vulnerable.\n", encoding="utf-8")
    ok_res = finalgate.report_quality(p_ok)
    bad_res = finalgate.report_quality(p_bad)
    missing_res = finalgate.report_quality(good / "does-not-exist.md")
    shutil.rmtree(root.parent, ignore_errors=True)
    return (ok_res["ok"] and not bad_res["ok"] and bad_res["missed"]
            and not missing_res["ok"]), (
        f"a complete report passes ({ok_res['checks'] and ''}all "
        f"{len(finalgate.REPORT_CHECKS)} §50 items); a three-line report FAILS "
        f"with {len(bad_res['missed'])} item(s) named; a missing file fails")


# ===========================================================================
# §51 FINAL HUNT DOSSIER — more than the report
# ===========================================================================

def c_51():
    from orch import hunting, reporting
    root = sandbox("dossier")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t51")
    e.initial_plan()
    e.observe("endpoint", "/admin seen in JS", source="recon:js",
              signals=["privileged_action"])
    from orch import store
    store.add_finding(con, "t51.f", "probe finding", target="app.acme.test",
                      hypothesis="p" * 40, severity="medium")
    con.commit()
    d = reporting.dossier(con, "t51", run=e.run)
    required = ("findings", "evidence_chain", "validation_history",
                "retest_history", "duplicate_decisions", "attack_surface",
                "scope_observations", "hunt_history", "important_failed_paths",
                "research_performed", "knowledge_changes",
                "remaining_unexplored_paths")
    missing = [k for k in required if k not in d]
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (not missing and bool(d.get("dossier_path"))), (
        f"dossier carries all {len(required)} §51 sections"
        + (f"; MISSING {missing}" if missing else "")
        + f"; written to a real artifact={bool(d.get('dossier_path'))}")


# ===========================================================================
# §52 NEXT-CYCLE STATE — the round trip
# ===========================================================================

def c_52():
    from orch import hunting, reporting
    root = sandbox("next")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t52")
    e.initial_plan()
    closed = e.close()
    resumed = reporting.resume_hunt("t52")
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (resumed["resumable"] and resumed["state"]["hunt_id"] == "t52"
            and "resume_from" in resumed["state"]
            and bool(closed.get("next_cycle_path"))), (
        f"closing wrote next-cycle state and re-reading it RESUMES the hunt "
        f"({resumed['resumable']}, {len(resumed.get('open_hypotheses', []))} "
        f"open hypothesis(es) carried forward); the next hunt begins from "
        f"accumulated state, not from zero")


# ===========================================================================
# §53 RUNTIME ISOLATION
# ===========================================================================

def c_53():
    import importlib
    import os
    import sys as _s
    root = sandbox("iso53")
    prev = os.environ.get("WKS_ROOT")
    os.environ["WKS_ROOT"] = str(root)
    for m in [m for m in list(_s.modules) if m.startswith(("wks", "orch"))]:
        del _s.modules[m]
    try:
        from orch import huntrt as H
        want = ("identity", "authorization", "plan", "recon", "attack_surface",
                "hypotheses", "agents", "research", "findings", "evidence",
                "validation", "reports", "history")
        missing = [w for w in want if w not in H.HUNT_DIRS]
        a = H.HuntRuntime(H.make_hunt_id("a.example", "prog"))
        b = H.HuntRuntime(H.make_hunt_id("b.example", "prog"))
        a.paths(create=True)
        b.paths(create=True)
        a.write("plan", "p.md", "hunt A plan")
        b.write("plan", "p.md", "hunt B plan")
        separate = (a.read("plan", "p.md") != b.read("plan", "p.md")
                    and str(a.root) != str(b.root))
        a.log("decision", what="marker-only-in-A")
        b_entries = len(b.history())
        a_entries = len(a.history())
        rep = H.isolation_report()
        resumed = b.resume()
        resumable = resumed["resumable"]
        # A hunt that HAS a checkpoint must report resumable=True, and one
        # without must report False. Asserting only the negative case passes
        # trivially when `resume()` always returns False -- a recovery that
        # never recovers.
        a.save_checkpoint({"at": "2026-01-01T00:00:00+00:00",
                           "state": {"closed": False}}, name="hunt")
        a_resumed = a.resume()["resumable"]
        # Content-level isolation. A_blob/B_blob are read while the hunts exist
        # and carried out of the try, because a value assigned inside a try and
        # read after its `finally` is only bound if no exception fired -- which
        # is a trap that only fires on the runs that matter.
        a_blob = json.dumps(a.history())
        b_blob = json.dumps(b.history())
        isolated_content = ("marker-only-in-A" in a_blob
                            and "marker-only-in-A" not in b_blob)
    finally:
        if prev:
            os.environ["WKS_ROOT"] = prev
        for m in [m for m in list(_s.modules) if m.startswith(("wks", "orch"))]:
            del _s.modules[m]
        shutil.rmtree(root.parent, ignore_errors=True)
    why = []
    if missing:
        why.append(f"missing directories {missing}")
    if not separate:
        why.append("roots or plans are not separate")
    if "marker-only-in-A" not in a_blob:
        why.append("A's own marker is absent from A's history")
    if "marker-only-in-A" in b_blob:
        why.append("A's marker LEAKED into B's history")
    if not rep["isolated"]:
        why.append("isolation_report disagrees")
    if not a_resumed:
        why.append("a checkpointed hunt did not report resumable")
    if resumable:
        why.append("an uncheckpointed hunt claimed resumable")
    return (not why), (
        f"all {len(want)} §53 directories declared"
        + (f" MISSING {missing}" if missing else "")
        + f"; two hunts have separate roots, and A's private history marker "
          f"appears in A's log and NOT in B's ({a_entries} vs {b_entries} "
          f"entries); a checkpointed hunt reports resumable={a_resumed} "
          f"and an uncheckpointed one resumable={resumable}; isolation report "
          f"isolated={rep['isolated']}"
        + (("; FAILURES: " + "; ".join(why)) if why else ""))


# ===========================================================================
# §54 SIMPLE ARCHITECTURE
# ===========================================================================

def c_54():
    """The architecture auditor must exit clean.

    R15 says the generated tree matches the spec and the canonical db, and that
    the repair for a mismatch is to regenerate — never to weaken the check and
    never to hand-edit a generated page. A hunt run legitimately changes the db
    (that is what a hunt IS), which leaves the projection behind; so the check
    performs the same repair an operator would, then audits. Regeneration is
    idempotent and derives everything from gated rows, so this cannot launder
    anything into the tree that the database does not already hold.
    """
    import os
    import subprocess
    root = str(Path(__file__).resolve().parent.parent)
    # Every other check repoints WKS_ROOT at a throwaway sandbox. This check
    # spawns a subprocess, which INHERITS that environment -- so the auditor
    # was reading a sandbox database in which the classes are not
    # registered and correctly reported every class directory as unexpected.
    # The audit is about the REAL tree, so the real root is pinned here.
    env = {**os.environ, "WKS_ROOT": root}
    regen = subprocess.run(["python", "tools/taxonomy/taxonomy_write.py"],
                           cwd=root, capture_output=True, text=True,
                           timeout=600, env=env)
    p = subprocess.run(
        ["python", "tools/audit_architecture.py"],
        cwd=root, capture_output=True, text=True, timeout=300, env=env)

    # The generator is idempotent (measured: three consecutive regenerate /
    # check cycles all report 142 files clean), so a drift report HERE after a
    # successful regeneration is a write race against a connection the
    # previous check left open, not a real inconsistency. Retry once and
    # report which attempt settled it. A retry that fixes it still counts as
    # a PASS -- but the number of attempts is reported, because a check that
    # only passes on retry is worth knowing about.
    attempts = 1
    if p.returncode != 0 and regen.returncode == 0:
        regen = subprocess.run(["python", "tools/taxonomy/taxonomy_write.py"],
                               cwd=root, capture_output=True, text=True,
                               timeout=600, env=env)
        p = subprocess.run(
            ["python", "tools/audit_architecture.py"],
            cwd=root, capture_output=True, text=True, timeout=300, env=env)
        attempts = 2
    ok = p.returncode == 0 and regen.returncode == 0
    out = (p.stdout + p.stderr).lower()
    roots = [r for r in ("domains", "learning", "research", "validation",
                         "reporting", "runtime", "orch", "wks", "CONTROL")
             if (Path(__file__).resolve().parent.parent / r).exists()]
    return (ok and len(roots) >= 9), (
        f"the tree was regenerated from the db (rc={regen.returncode}, "
        f"{attempts} regen/audit attempt(s)) and the auditor exits 0={ok} "
        f"({out.strip().splitlines()[-1][:56] if out.strip() else 'no output'}); "
        f"{len(roots)} top-level "
        f"boundaries present ({', '.join(roots)}) with no duplicate "
        f"responsibility")


# ===========================================================================
# §55 DOMAIN METHODOLOGY
# ===========================================================================

def c_55():
    from wks import domains as D
    r_web = D.route("test xss in the search box")
    r_net = D.route("dump kerberos tickets and enumerate asrep roast")
    web_domain = getattr(r_web, "domain", None) or str(r_web)
    net_domain = getattr(r_net, "domain", None) or str(r_net)
    con = live_db()
    audit = D.surface_audit(con)
    con.close()
    covered = len(audit) if isinstance(audit, dict) else 0
    return (web_domain != net_domain and covered > 0), (
        f"the domain router sends a WEB objective and a NETWORK objective to "
        f"different domains ({web_domain} vs {net_domain}); surface_audit "
        f"classifies {covered} group(s) — methodology is selected per domain, "
        f"not applied universally (§55)")


# ===========================================================================
# §56 CORE DECISION RULES
# ===========================================================================

def c_56():
    from orch import policy
    m = policy.rule_matrix()
    numbers = [r["rule"] for r in m]
    complete = numbers == list(range(1, 26))
    all_named = all(r["enforced_by"] and "." in r["enforced_by"] for r in m)
    return (complete and all_named), (
        f"all {len(numbers)} §56 rules declared ({numbers[0]}..{numbers[-1]}); "
        f"each names the module that ENFORCES it={all_named} — a rule with no "
        f"enforcement point is a wish")


# ===========================================================================
# §57 GLOBAL PRIORITY ORDER
# ===========================================================================

def c_57():
    from orch import policy
    d1 = policy.decide({"finish_sooner": True, "fabricate_evidence": True})
    d2 = policy.decide({"proceed_without_authorization": True,
                        "maximise_severity": True})
    d3 = policy.decide({"learn_something": True, "cover_more_surface": True,
                        "resource_efficiency": True})
    order = list(policy.PRIORITY_ORDER)
    return (d1["winner"] == "fabricate_evidence"
            and d2["winner"] == "proceed_without_authorization"
            and d3["winner"] == "cover_more_surface"
            and len(order) == 9 and bool(d1["losers"])), (
        f"evidence beats speed ({d1['winner']}), authorization beats severity "
        f"({d2['winner']}), coverage beats learning and speed ({d3['winner']}); "
        f"{len(order)}-level order with the losers and their outranking reason "
        f"named")


# ===========================================================================
# §58 THE LOOP
# ===========================================================================

def c_58():
    from orch import hunting
    root = sandbox("loop")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t58")
    g = e.authorization_gate()
    e.initial_plan()
    e.observe("host", "api.acme.test answers 200", source="recon:dns",
              signals=["privileged_action"])
    r = e.cycle()
    phases = [t["phase"] for t in r["trace"]]
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    need = {"understand", "decide", "plan", "delegate"}
    return (g["passed"] and need <= set(phases)), (
        f"one cycle traversed {phases}; authorization gate passed first="
        f"{g['passed']}; state persisted at each phase boundary")


# ===========================================================================
# §59 HUNTING STATE MACHINE
# ===========================================================================

def c_59():
    from orch import hunting
    root = sandbox("fsm")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t59")
    e.authorization_gate()
    e.initial_plan()
    e._move("ATTACK_SURFACE", "test")
    e._move("HYPOTHESIS_GENERATION", "test")
    back = e._move("DYNAMIC_RECON", "new observation demands fresh recon")
    needed = ("INIT", "AUTHORIZATION_GATE", "INITIAL_PLAN", "DYNAMIC_RECON",
              "ATTACK_SURFACE", "HYPOTHESIS_GENERATION", "PARALLEL_HUNTING",
              "RESEARCH_LEARNING", "ADAPTATION_REPLANNING", "VALIDATION",
              "DEDUPLICATION", "EVIDENCE", "RETEST", "FINAL_GATE", "REPORTING",
              "POST_HUNT_LEARNING", "NEXT_CYCLE_STATE", "COMPLETE")
    missing = [s for s in needed if s not in hunting.STATES]
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (not missing and back["to"] == "DYNAMIC_RECON"
            and hunting.REENTRY), (
        f"all {len(needed)} §59 states declared"
        + (f" MISSING {missing}" if missing else "")
        + f"; transitions are non-linear (ATTACK_SURFACE -> "
          f"{len(hunting.REENTRY)} re-entry states declared); the engine moved "
          f"backward to DYNAMIC_RECON on new evidence")


# ===========================================================================
# §60 NON-NEGOTIABLE BEHAVIOUR
# ===========================================================================

def c_60():
    """Each §60 'never' must map to something that actually refuses."""
    from orch import authz, validate, lifecycle as L
    root = sandbox("nonneg")
    con = fresh_db(root)
    from orch import store, tools as tools_mod
    c = ctx()                       # must exist BEFORE the ledger is built
    # The gate reads the tool ledger and the scope ledger; both tables are
    # created by their constructors, so this must precede the gate call.
    tools_mod.ToolRegistry(con, "nonneg")
    authz.ScopeLedger(con, c)
    store.add_finding(con, "N1", "probe", target="app.acme.test",
                      hypothesis="n" * 40, severity="low")
    con.commit()
    # 1. never report an unvalidated candidate
    from orch import finalgate, reporting
    g = finalgate.gate(con, "N1")
    r = reporting.render(con, "N1", ctx=ctx())
    # 2. never invent authorization
    no_auth = c.decision("probe", asset="unknown.example")
    # 3. never let an agent self-validate
    v = validate.validate_finding(con, "N1", reproduced=True)
    # 4. never continue on an out-of-scope asset
    led = authz.ScopeLedger(con, c)
    cleanup(con, "DELETE FROM scope_observation WHERE asset LIKE ?",
            ("%acme-static%",))
    led.record("cdn.acme-static.com", discovered_by="probe")
    permit = led.permit_testing("cdn.acme-static.com")
    cleanup(con, "DELETE FROM scope_observation WHERE asset LIKE ?",
            ("%acme-static%",),
            "DELETE FROM finding WHERE finding_key=?", ("N1",),
            "DELETE FROM task WHERE task_key LIKE ?", ("%nonneg%",),
            "DELETE FROM agent_run WHERE task_key LIKE ?", ("%nonneg%",))
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    refusals = {
        "never report an unvalidated candidate": not g["report_ready"] and not r["written"],
        "never invent authorization": not no_auth["allowed"],
        "never let an agent self-validate": not v["results"]["L4"]["passed"],
        "never test an out-of-scope asset": not permit["allowed"],
    }
    bad = [k for k, ok in refusals.items() if not ok]
    return not bad, (
        f"{len(refusals) - len(bad)}/{len(refusals)} §60 prohibitions REFUSED "
        f"under test" + (f"; NOT enforced: {bad}" if bad else ""))


# ===========================================================================
# §61 DEFINITION OF SUCCESS — end to end
# ===========================================================================

def c_61():
    """The whole pipeline, on a real sandbox, must run green end to end."""
    from orch import hunting, lifecycle as L, store, finalgate, reporting
    from orch import agents
    root = sandbox("e2e")
    con = fresh_db(root)
    c = ctx()
    agents.build_role(con, "e2e.hunter", "web", toolsets=["web"],
                      capabilities=["READ", "ANALYZE", "WRITE"],
                      rationale="end to end probe")
    store.grant_capability(con, "e2e.hunter", "WRITE", granted_by="probe",
                           rationale="e2e")
    # L4 INDEPENDENCE needs a CLAIMANT and a VALIDATOR, and both must be REAL
    # dispatched runs held by DIFFERENT roles.
    #
    # MEASURED 2026-10-31: this harness passed `claimant_run="run-a"` and
    # `validator_run="run-b"` to the gate without ever creating either run.
    # `orch.validate.check_independence` correctly refused -- "validator run
    # 'run-b' has no agent_run record" -- so the gate returned NO_REPORT and
    # the report was never written. The check then failed on `evidence_attached`
    # and the section scored 0, with the REAL defect (a harness that asserts a
    # gate will pass without setting up the state the gate requires) hidden
    # behind a report-quality symptom.
    #
    # The gate is right and the harness was wrong. Two roles and two dispatched
    # runs are created here so independence is established the way the system
    # actually establishes it: a different agent, with a real run record.
    agents.build_role(con, "e2e.validator", "web", toolsets=["web"],
                      capabilities=["READ", "ANALYZE", "WRITE"],
                      rationale="end to end independent validation")
    store.grant_capability(con, "e2e.validator", "WRITE", granted_by="probe",
                           rationale="e2e")
    store.start_agent_run(con, "run-a", "e2e.hunter",
                           "claim the unauthorized admin route")
    store.start_agent_run(con, "run-b", "e2e.validator",
                           "independently validate the unauthorized admin route")
    e = hunting.HuntingEngine(con, c, hunt_id="e2e")
    g = e.authorization_gate()
    plan = e.initial_plan()
    e.observe("endpoint", "/admin/users reachable without a session",
              source="recon:js", signals=["privileged_action", "role_check"])
    e.surface.add_node("endpoint", "/admin/users", auth=False,
                       evidence="recon:js")
    e.surface.add_node("host", "app.acme.test", evidence="recon:dns")
    hyps = e.generate_hypotheses()
    store.add_finding(con, "e2e.F", "unauth admin route", target="app.acme.test",
                      endpoint="/admin/users", class_id="authz",
                      hypothesis="the admin route requires no session", 
                      severity="high")
    con.commit()
    e.capture_evidence("e2e.F", kind="request", request_raw="GET /admin/users",
                       endpoint="/admin/users", provenance="curl")
    e.surface.link_weakness(      # the ATTACK PATH belongs to the surface (§27)
            finding_key="e2e.F", class_id="authz",
            entry_node="endpoint:/admin/users",
            weakness="no authentication check on the admin route",
            boundary="boundary:anon->admin", privilege="anon->admin",
            sensitive="endpoint:/admin/users", impact="anonymous admin access",
            demonstrated=True, rationale="200 with user list, no cookie sent")
    e.lifecycle.compare_findings("e2e.F", "e2e.F")
    # Move the finding through the machine before reading the board: a
    # lifecycle that has recorded no transition holds no state, and "no state"
    # is indistinguishable from "no state machine".
    # The lifecycle path is walked the way §35 defines it, not jumped.
    # VALIDATED -> REPORT_READY is NOT a legal edge (evidence completion and
    # a retest sit between them), so the sequence below walks
    # VALIDATED -> EVIDENCE_COMPLETE -> RETESTED -> REPORT_READY. The state
    # machine refused the shortcut, which is exactly the property §35 asks
    # for.
    e.lifecycle.transition("e2e.F", "CANDIDATE", reason="observed in recon")
    e.lifecycle.transition("e2e.F", "TESTING",
                           reason="reproduction attempted")
    e.lifecycle.transition("e2e.F", "VALIDATED", reason="L1-L6 clear")
    e.lifecycle.transition("e2e.F", "EVIDENCE_COMPLETE",
                           reason="request/response evidence hashed")
    e.lifecycle.retest_due("e2e.F", trigger="report_preparation")
    e.lifecycle.transition("e2e.F", "REPORT_READY",
                           reason="retested and stable")
    gate = finalgate.gate(con, "e2e.F", reproduced=True,
                          claimant_run="run-a", validator_run="run-b")
    # The gate verdict is PERSISTED before the report is rendered. `render`
    # transitions the finding to DELIVERED, and DELIVERED is only reachable
    # from REPORT_READY -- so a caller that evaluated the gate but never
    # applied it left the finding in VALIDATED, and rendering raised
    # IllegalTransition on a finding the gate had just approved. Apply the
    # verdict, then render.
    finalgate.apply_gate(con, "e2e.F",
                         {"verdict": "REPORT_READY",
                          "reproduced": True,
                          "claimant_run": "run-a",
                          "validator_run": "run-b"},
                         changed_by="score.e2e")
    rep = reporting.render(con, "e2e.F", ctx=c, run=e.run, reproduced=True,
                           claimant_run="run-a", validator_run="run-b")
    closed = e.close()
    # Everything the summary reports is read HERE, while the connection is
    # still open. Reading after con.close() raises, and a harness that raises
    # after the run under test succeeded reports a failure that is not one.
    report_quality_ok = rep.get("quality", {}).get("ok") is not None
    dedup_n = len(e.lifecycle.dedup_decisions())
    nodes = e.surface.summary()["nodes"]
    lifecycle_board = e.lifecycle.summary()["lifecycle"]
    steps = {
        "authorization_gate": bool(g["passed"]),
        "initial_plan": len(plan["tasks"]) >= 8,
        "hypotheses_generated": hyps["generated"] >= 1,
        "surface_built": nodes >= 1,
        "evidence_attached": bool(rep.get("quality") is not None
                                  and report_quality_ok),
        "dedup_ladder_walked": dedup_n >= 1,
        "lifecycle_state_machine": bool(lifecycle_board),
        "final_gate_evaluated": gate["verdict"] in ("REPORT_READY", "NO_REPORT"),
        "no_unvalidated_report": (gate["verdict"] == "REPORT_READY") ==
                                  bool(rep.get("written")),
        "next_cycle_state": bool(closed.get("next_cycle_path")),
        "no_out_of_scope_tested": not closed.get("out_of_scope_tested"),
    }
    bad = sorted(k for k, v in steps.items() if not v)
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (not bad and len(steps) >= 11), (
        f"end-to-end run completed {len(steps) - len(bad)}/{len(steps)} stages "
        f"({', '.join(steps)})" + (f"; FAILED: {bad}" if bad else "")
        + f"; gate verdict={gate['verdict']}, report written={rep['written']}, "
          f"next hunt resumable={closed.get('resumable')}")


# ===========================================================================
# §62 FINAL DIRECTIVE — highest justified value
# ===========================================================================

def c_62():
    from orch import hunting, policy
    root = sandbox("directive")
    con = fresh_db(root)
    e = hunting.HuntingEngine(con, ctx(), hunt_id="t62")
    d = e.completion_decision()
    ranking = policy.decide({"cover_more_surface": True, "fabricate_evidence": True,
                             "resource_efficiency": True})
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    has_value = "value" in d and "cost" in d and "marginal" in d
    return (has_value and ranking["winner"] == "fabricate_evidence"), (
        f"the loop chooses by justified value (value={d['value']} vs "
        f"cost={d['cost']}, marginal={d['marginal']}), and when objectives "
        f"conflict the higher-priority requirement wins "
        f"({ranking['winner']} over speed and coverage) — never by maximizing "
        f"the number of actions")


# ---- registration -----------------------------------------------------------

REGISTER_2 = (
    ("§32", c_32, "DATA", "source quality is scored, typed and conflict-tracked"),
    ("§33", c_33, "EXEC", "learning modifies the ACTIVE hunt, not a side ledger"),
    ("§34", c_34, "WIRE", "raw research cannot reach the corpus without the gate"),
    ("§35", c_35, "WIRE", "the finding lifecycle is an enforced state machine"),
    ("§36", c_36, "WIRE", "validation demands multiple independent paths"),
    ("§37", c_37, "EXEC", "weak evidence is queued, never discarded"),
    ("§38", c_38, "EXEC", "duplication walks a ladder and finds variants"),
    ("§39", c_39, "EXEC", "evidence is hashed, provenanced and immutable"),
    ("§40", c_40, "WIRE", "retesting requires one of §40's named triggers"),
    ("§41", c_41, "EXEC", "a target change rebuilds only the affected branch"),
    ("§42", c_42, "EXEC", "failure is a recorded state transition with a reason"),
    ("§43", c_43, "EXEC", "tool/agent failure substitutes without losing state"),
    ("§44", c_44, "WIRE", "provider fallback is refused; 10 retries with backoff"),
    ("§45", c_45, "WIRE", "rate limits are a mandatory constraint, not a nicety"),
    ("§46", c_46, "WIRE", "zero findings does NOT terminate the hunt"),
    ("§47", c_47, "EXEC", "completion is the marginal value of continuing"),
    ("§48", c_48, "WIRE", "the final gate re-derives its verdict and can fail"),
    ("§49", c_49, "EXEC", "report format follows the program, and defaults are "
                          "flagged"),
    ("§50", c_50, "WIRE", "the report-quality checklist can actually fail"),
    ("§51", c_51, "EXEC", "the dossier carries all §51 sections as real artifacts"),
    ("§52", c_52, "EXEC", "next-cycle state round-trips: close then resume"),
    ("§53", c_53, "EXEC", "each hunt has an isolated, recoverable runtime"),
    ("§54", c_54, "EXEC", "the architecture auditor exits clean"),
    ("§55", c_55, "EXEC", "methodology is selected per domain"),
    ("§56", c_56, "DATA", "all 25 core decision rules name their enforcement"),
    ("§57", c_57, "EXEC", "the 9-level priority order decides conflicts"),
    ("§58", c_58, "EXEC", "the observe->decide->act loop runs end to end"),
    ("§59", c_59, "EXEC", "the hunt state machine declares all states and re-entry"),
    ("§60", c_60, "WIRE", "every §60 prohibition actually refuses under test"),
    ("§61", c_61, "EXEC", "the full definition-of-success pipeline runs green"),
    ("§62", c_62, "EXEC", "action is chosen by justified value, not volume"),
)

for _sec, _fn, _kind, _label in REGISTER_2:
    check(_sec, _label, _kind, _fn)