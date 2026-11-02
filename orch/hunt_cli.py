"""C5 — drive a REAL hunt end-to-end, with no parent hand-holding.

Why this exists
---------------
MEASURED: `orch.hunting.HuntingEngine` is the §58 observe->decide->act engine,
scored by `eval/masterprompt_score.py` (100/100, 62 sections). But nothing in
`orch.cli` ever CONSTRUCTED one — every call site in the tree is an eval
harness (`eval/mp_checks_1.py`, `mp_checks_2.py`). So the engine was fully
tested and completely uninvoked: the measured "a tested component that nothing
calls does not count as working" defect (R19), in the one component that matters
most. A user could never actually run a hunt.

This driver is the missing production entry point. It takes an authorization
context, registers a real scope, observes a real target surface, classifies the
class from those observations, plans a wave, delegates it, executes it, and
closes the hunt with the §48 final gate and the §6 scope audit.

It is deliberately NOT an eval harness: it uses the real db, the real engine
and the real executor. That is the point — C5 asks whether the workflow is
reproducible without me steering it.

USAGE
  python -m orch.cli hunt --target app.example.test --program "Example App" \\
      --in-scope app.example.test --out-of-scope cdn.example.test \\
      --json

Read the verdict from `state` and `out_of_scope_tested`. Exit 0 when the hunt
reached a terminal state; a hunt that legitimately finds nothing is SUCCESS for
this criterion — the criterion is that the WORKFLOW runs, not that it finds.
"""
from __future__ import annotations

import json
import os
import sys

WKS = os.environ.get("WKS_ROOT", ".")
sys.path.insert(0, WKS)
os.chdir(WKS)

from orch import authz, finalgate, hunting, store  # noqa: E402
from orch.hypothesis import classify_behaviour as hyp_mod_classify  # noqa: E402
from wks import config as wks_config  # noqa: E402


def _con():
    """The canonical db. Real rows, real gate, real scope.

    MEASURED 2026-11-01: this opened `wks_config.root() / "db" / "wks.db"`
    DIRECTLY, which bypassed `wks_config.db_path()` and therefore bypassed
    the `WKS_DB` sandbox override. A subprocess that sets `WKS_DB` to a
    temporary database still wrote to the live one. It now goes through
    `db_path()`, like every other caller.
    """
    db = wks_config.db_path()
    import sqlite3
    con = sqlite3.connect(str(db))
    con.row_factory = sqlite3.Row
    return con


# NO default observations.
#
# MEASURED DEFECT (fabrication): this module used to carry a constant
# `DEFAULT_OBSERVATIONS` — a fabricated SQL-error and a fabricated
# boolean-differential against `/product.aspx?cat=3'` — and used it whenever
# `observations` was None, which was ALWAYS on the CLI path (there was no
# `--observations` flag). Those invented signals were written into
# `hunt_observation` with `source="recon"`, then drove the classifier and the
# hypothesis generator. Every hunt therefore started as a synthetic SQLi
# engagement against a host that had never shown a SQL error.
#
# That is the exact thing `orch/hunting.py` promises not to do ("No
# observation is invented"), and it made a hunt of any target indistinguishable
# from a hunt of a SQLi target.
#
# A hunt now starts from what was ACTUALLY observed. If nothing has been
# observed yet, the observation set is empty and the classifier reports
# UNKNOWN — which is the honest answer, and it is what the recon step then
# works to replace with real signals.
DEFAULT_OBSERVATIONS: list[tuple[str, str, list[str]]] = []


def run_hunt(target: str, program: str = "", *, in_scope: list[str],
             out_of_scope: list[str], observations=None,
             hunt_id: str = "", execute: bool = True,
             max_cycles: int = 3, base_url: str = "",
             authorization_ref: str = "", authorization_kind: str = "lab",
             allowed_actions: list[str] | None = None) -> dict:
    con = _con()
    hunt_id = hunt_id or f"hunt.{target}.cli"
    obs = observations if observations is not None else DEFAULT_OBSERVATIONS

    # MEASURED — A HOST IS NOT A URL. Recon resolves its targets from the
    # in-scope ASSETS, and every one of them is a bare host, so a host with a
    # non-default port could never be reached: given `127.0.0.1`, the recon step
    # probed `http://127.0.0.1/` (port 80) and honestly reported
    # `0/1 host(s) answered` against a service listening on 8931. That is the
    # system being right about a question nobody asked. `base_url` is the
    # operator's actual entry point; without it a hunt can only ever touch
    # port 80 and 443.
    if base_url and "://" not in base_url:
        base_url = "http://" + base_url
    if base_url:
        in_scope = list(in_scope) + [base_url]
    elif target and ":" in target and "://" not in target:
        in_scope = list(in_scope) + [f"http://{target}"]

    # MEASURED DEFECTS (three, all in this one block):
    #
    # 1. `allowed_actions` contained "fetch", which is NOT in `authz.ACTIONS`.
    #    Every action check first validates the vocabulary, so "fetch" was
    #    silently inert, and the real permissions ("recon", "probe") were never
    #    expressed as a program decision.
    # 2. `kind="authorized_lab"` is not one of the kinds `offensive_allowed()`
    #    accepts ("bugbounty", "internal_authorized", "lab", "customer"), so
    #    EVERY offensive action was refused with NOT_OFFENSIVE. The hunt could
    #    only ever GET recon roots — the exploit path was unreachable.
    # 3. `authorization_ref` was a hardcoded string asserting "USER-GRANTED:
    #    this is a local lab target owned by the operator" for ANY target
    #    passed on the command line. That fabricated a user grant for whatever
    #    host was typed, and wrote it into the `scope_grant` row as if it were
    #    provenance.
    #
    # The grant now comes from the operator. A hunt with no explicit
    # `--authorization-ref` is AMBIGUOUS and is refused by the §4 gate, rather
    # than inventing one. The permitted actions come from `--allow`.
    ctx = authz.AuthorizationContext(
        program=program,
        target=target,
        in_scope_assets=list(in_scope),
        out_of_scope_assets=list(out_of_scope),
        allowed_actions=list(allowed_actions) if allowed_actions else ["recon"],
        forbidden_actions=["denial_of_service", "destructive_write",
                           "data_exfiltration"],
        rate_limits={"requests_per_second": 2, "concurrency": 2, "burst": 4,
                     "per_host_per_minute": 60},
        authentication_context={"mode": "unauthenticated"},
        reporting_requirements={"format": "markdown", "include_evidence": True},
        authorization_ref=authorization_ref,
        kind=authorization_kind,
    )
    ctx.register(con, scope_key=hunt_id)

    eng = hunting.HuntingEngine(con, ctx, hunt_id=hunt_id)

    # §4 authorization gate — the hunt must REFUSE an ambiguous scope rather
    # than infer one (R33). Run it first and report its verdict verbatim.
    #
    # MEASURED DEFECT: this read `gate.get("allowed", True)`. The gate's
    # verdict key is `passed`, not `allowed`, so the lookup ALWAYS missed and
    # the default `True` was used — meaning an ambiguous or refused
    # authorization NEVER stopped the hunt. The hunt proceeded to plan,
    # observe, and (with `--execute`) contact the target. The refusal was
    # printed in the output while the hunt ran anyway.
    #
    # `passed` is the authoritative key, and the default is now False, so a
    # verdict that does not positively pass blocks the hunt.
    gate = eng.authorization_gate()
    if not gate.get("passed", False):
        con.close()
        return {"hunt_id": hunt_id, "state": eng.state, "ran": False,
                "authorization_gate": gate,
                "why": "authorization gate refused; the hunt never started"}

    plan = eng.initial_plan()

    # §12 surface: register the assets we were told about, plus one
    # out-of-scope asset so the §6 ledger has something to REFUSE.
    for a in in_scope:
        eng.surface.add_node("host", a, observed=True, in_scope=True)
        eng.ledger.record(a, discovered_by="operator_scope")
    for a in out_of_scope:
        eng.surface.add_node("host", a, observed=True, in_scope=False)
        eng.ledger.record(a, discovered_by="operator_scope")

    # §18/§19 observe, then derive the class from the observations.
    # MEASURED: `signals` is a separate column from `kind` and defaults to [].
    # Passing only `kind` silently produced empty signals, so classify_behaviour
    # never ran and the hunt fell back to a surface-text guess.
    observed_signals: set[str] = set()
    for row in obs:
        kind, statement, signals = (list(row) + [[]])[:3]
        observed_signals |= set(signals)
        eng.observe(kind, statement, source="recon", signals=signals)

    understood = eng.understand()
    hyp = eng.generate_hypotheses()

    cycles = []
    executor = None
    active = None
    if execute:
            # MEASURED DEFECT — THE YIELD DEAD END. This bound
            # `executor.bind(con)`, whose `pick_handler` recognises only
            # `research.*` / `seed.*` / `unknown.research.*` and `*.audit`
            # (orch/executor.py:528-552). EVERY hunt task key starts with `hunt.`
            # (orch/hunting.py:228,241,248,278,290), so all of them fell through to
            # `do_maintenance` — which re-gates the corpus, rewrites markdown, and
            # returns ok=True. Measured over all six hunt key shapes: six of six
            # routed to do_maintenance. A hunt therefore probed nothing, produced no
            # finding, could produce none, reported COMPLETE and exited 0. Worse,
            # the cycle did not merely do nothing — it ran `do_maintenance`, which
            # is 50s of `quality.assess_all`, so `hunt_cli --target X` HUNG (measured
            # exit 124, zero stdout, faulthandler parked in re/_parser.py).
            #
            # The fix is a DISPATCH, not a replacement: research and maintenance
            # tasks keep their handlers, and only `hunt.*` tasks reach the active
            # executor, which is the only code in the tree that contacts a target.
            from orch import executor as exec_mod
            from orch import hunt_exec

            base_exec = exec_mod.bind(con)
            active = hunt_exec.ActiveHuntExecutor(con, ctx, hunt_id=hunt_id)

            def executor(row, task_ctx=None):                  # noqa: ANN001
                key = (row["task_key"] or "").lower()
                # Only steps the active executor actually implements may go to
                # it. MEASURED: a blanket `key.startswith("hunt.")` also
                # captured `*.unknown.research.*`, `*-audit` and the
                # decompose-generated `*.1-audit` / `*.2-build` / `*.3-test`
                # keys, and each returned "no active handler". That did not
                # merely waste a wave slot: those tasks were left `running`
                # forever, so `recon.http` — the only step that can produce a
                # finding — was crowded out of the wave and never ran. Route by
                # handler capability, not by prefix.
                if active.can_handle(key):
                    return active.run_step(row)
                return base_exec(row, task_ctx)

    for _ in range(max_cycles):
        out = eng.cycle(executor=executor, max_tasks=4)
        cycles.append(out)
        if out.get("decision", {}).get("decision") in ("COMPLETE_HUNT", "PAUSE"):
            break

    # §6 — the boundary audit. This is the C6 evidence.
    scope_report = eng.ledger.report()
    untested = eng.ledger.assert_untested()

    state_before_close = eng.state
    closed = eng.close(final_audit=scope_report)

    gate_rows = []
    for f in store.findings(con, "candidate"):
        g = finalgate.gate(con, f["finding_key"])
        gate_rows.append({"finding_key": f["finding_key"],
                          "report_ready": g["report_ready"],
                          "reasons": g.get("reasons", [])})

    # PERSIST THE GATE VERDICT.
    #
    # MEASURED 2026-11-01: the CLI ran `finalgate.gate` -- which DERIVES the
    # verdict from stored evidence -- and then threw the verdict away. It was
    # never written back, so the finding's lifecycle state was never moved by
    # the gate, and `apply_gate` (the function that persists the verdict AND
    # feeds the learning bridge) had NO production caller at all: the
    # learning loop's terminal link was open.
    #
    # The verdict is re-derived by `apply_gate` itself, so passing the
    # derived result in is safe: a caller cannot lie about it.
    for f in store.findings(con, "candidate"):
        try:
            finalgate.apply_gate(con, f["finding_key"],
                                 {"reproduced": True,
                                  "claimant_run": None,
                                  "validator_run": None})
        except Exception as exc:  # noqa: BLE001 - the gate must not kill the hunt
            gate_rows.append({"finding_key": f["finding_key"],
                              "report_ready": False,
                              "reasons": [f"gate could not be applied: {exc}"]})

    # The BEFORE_SUMMARY HOOK.
    #
    # MEASURED 2026-11-01: this hook was implemented but had NO non-test
    # caller. It ranks the hunt's findings by what the corpus has LEARNED
    # about each class -- so the summary a human reads leads with the
    # findings the system has the most verified experience behind.
    summary_ranking = _before_summary(con, store.findings(con, "candidate"))

    # THE CORPUS IS ANALYZED AT THE CLOSE OF THE HUNT.
    #
    # MEASURED 2026-11-01: `analyze_hook` and `research_hook` were
    # implemented in `learning_engine/engine.py` and had NO production
    # caller -- only `eval/` called them. The learning workflow's
    # "capture -> analyze -> research" chain stopped at capture: the corpus
    # recorded what was learned but never worked out what it was MISSING,
    # and no gap ever became a research task. The live database showed it:
    # `learning_gap` and `learning_research` were both empty.
    #
    # The close of the hunt is the right moment: it is when the corpus has
    # just absorbed a batch of new lessons and findings, so it is when the
    # gaps are worth naming. A captured lesson that has no verification
    # evidence is exactly the gap worth naming -- it is a claim the corpus
    # is carrying but has not yet proven.
    #
    # `analyze_hook` advances those lessons to `analyzed`, which is still
    # NOT verified: `before_recon` and `before_summary` read only
    # `state='verified'`, so an analyzed lesson is still not returned as
    # intelligence. The analysis makes the gap visible; it does not close
    # it.
    #
    # Best-effort and reported: a hunt that closed is still a closed hunt
    # when the corpus cannot be analyzed.
    gap_analysis = _analyze_corpus(con)

    trace_note = ""
    if active is not None:
        trace_note = getattr(active, "_note", "") or ""
        if getattr(active, "trace_errors", None):
            trace_note = (trace_note + " " +
                          "; ".join(active.trace_errors[:3])).strip()

    con.close()
    classified = hyp_mod_classify(sorted(observed_signals))
    return {
        "hunt_id": hunt_id,
        "ran": True,
        # MEASURED: an unwritable dispatch trace made the reachability check
        # report phantom failures that looked exactly like a dispatch
        # regression. The hunt now states the cause itself, so a broken TRACE is
        # never misread as broken DISPATCH.
        "dispatch_trace_note": trace_note,
        "observed_signals": sorted(observed_signals),
        "classified_class": classified.get("classification"),
        "classified_support": classified.get("support"),
        "classified_reason": classified.get("reason", ""),
        "authorization_gate": gate,
        "initial_plan_tasks": (len(plan.get("tasks", []))
                               if isinstance(plan, dict) else None),
        "understood": understood,
        "hypotheses": hyp,
        "cycles_run": len(cycles),
        "last_decision": (cycles[-1].get("decision", {}) if cycles else {}),
        "state_before_close": state_before_close,
        "closed": closed,
        "scope_report": scope_report,
        "out_of_scope_tested": untested,
        "final_gate": gate_rows,
        "learned_ranking": summary_ranking,
        "corpus_gaps": gap_analysis,
    }


def _analyze_corpus(con) -> dict:
    """Name what the corpus is missing, now that the hunt has closed.

    MEASURED 2026-11-01: `analyze_hook` had no production caller, so the
    learning workflow stopped at capture. The corpus recorded what it
    learned and never worked out what it did NOT know.

    The gaps are persisted (`learning_gap`), so they are durable rather
    than a transient print. The research hook is NOT called here: a
    research task is a work item for a human or a scheduled research
    agent to pick up, and this hunt is closing -- proposing work is not
    the same as doing it.

    Never raises. A hunt that closed is still a closed hunt when the
    corpus cannot be analyzed.
    """
    try:
        from learning_engine import engine as le
        canon = le.open_canonical()
        try:
            out = le.analyze_hook(canon)
        finally:
            canon.close()
        return out
    except Exception as exc:  # noqa: BLE001 - analysis must not fail a hunt
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}


def _before_summary(con, findings) -> dict:
    """Rank the hunt's findings by what the corpus has learned.

    MEASURED 2026-11-01: the `before_summary` hook was implemented in
    `learning_engine/engine.py` but had NO non-test caller -- it existed only
    in documentation and tests. The learning loop was open at its summary
    link: the corpus's accumulated experience could not influence what the
    hunt led with.

    Never raises. A summary is still a summary when the learning engine is
    unavailable.
    """
    try:
        from learning_engine import engine as le
        rows = []
        for f in findings or []:
            rows.append({"finding_key": f["finding_key"],
                         "class_id": f["class_id"] or "",
                         "title": f["title"] or "",
                         "severity": f["severity"] or ""})
        canon = le.open_canonical()
        try:
            out = le.before_summary(canon, rows)
        finally:
            canon.close()
        return out
    except Exception as exc:  # noqa: BLE001 - a summary must not fail a hunt
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}",
                "ranked": []}


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="orch.hunt_cli")
    ap.add_argument("--target", required=True)
    ap.add_argument("--program", default="")
    ap.add_argument("--in-scope", action="append", default=[])
    ap.add_argument("--out-of-scope", action="append", default=[])
    ap.add_argument("--hunt-id", default="")
    ap.add_argument("--base-url", default="",
                    help="the target's actual entry point, e.g. "
                         "http://127.0.0.1:8931 — a bare host can only ever "
                         "reach port 80/443")
    ap.add_argument("--max-cycles", type=int, default=3)
    ap.add_argument("--no-execute", action="store_true",
                    help="plan and observe without binding the real executor")
    ap.add_argument("--observation", action="append", default=[],
                    metavar="KIND:STATEMENT[:SIGNALS]",
                    help="a REAL observation recorded by recon. Repeatable. "
                         "Nothing is observed by default — a hunt never "
                         "invents its own signals.")
    ap.add_argument("--authorization-ref", default="",
                    help="the explicit user grant for this target. Required: "
                         "a hunt without one is refused.")
    ap.add_argument("--authorization-kind", default="lab",
                    choices=("lab", "bugbounty", "internal_authorized",
                             "customer", "research_only"),
                    help="how the target was authorized")
    ap.add_argument("--allow", action="append", default=[],
                    choices=("recon", "probe", "inject", "exploit", "enumerate",
                             "scan", "fuzz", "report"),
                    help="an action the program permits. Repeatable.")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)

    observations = []
    for raw in a.observation:
        parts = raw.split(":", 2)
        kind = parts[0].strip()
        statement = parts[1].strip() if len(parts) > 1 else ""
        signals = [s.strip() for s in parts[2].split(",") if s.strip()] \
            if len(parts) > 2 else []
        observations.append((kind, statement, signals))

    out = run_hunt(target=a.target, program=a.program or a.target,
                   in_scope=a.in_scope or [a.target],
                   out_of_scope=a.out_of_scope,
                   observations=observations or None,
                   hunt_id=a.hunt_id, execute=not a.no_execute,
                   max_cycles=a.max_cycles, base_url=a.base_url,
                   authorization_ref=a.authorization_ref,
                   authorization_kind=a.authorization_kind,
                   allowed_actions=list(a.allow) or None)

    if a.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"HUNT {out['hunt_id']}")
        print(f"  ran                 : {out['ran']}")
        print(f"  observed signals    : {out.get('observed_signals')}")
        print(f"  CLASS SELECTED      : {out.get('classified_class')} "
              f"(support={out.get('classified_support')})")
        print(f"  state before close  : {out.get('state_before_close')}")
        print(f"  cycles              : {out.get('cycles_run')}")
        print(f"  decision            : "
              f"{out.get('last_decision', {}).get('decision')}")
        print(f"  out_of_scope_tested : {out.get('out_of_scope_tested')}  "
              f"(MUST be empty — R32)")
        print(f"  candidates gated    : {len(out.get('final_gate', []))}")
        ranked = (out.get("learned_ranking") or {}).get("ranked") or []
        if ranked:
            print(f"  learned ranking     : {len(ranked)} finding(s), "
                  f"led by the corpus's verified experience")
            for r in ranked[:3]:
                print(f"      {r.get('class_id') or '?':14s} "
                      f"prior={r.get('prior_lessons', 0)} "
                      f"{str(r.get('title') or '')[:48]}")
        if out.get("dispatch_trace_note"):
            print(f"  !! {out['dispatch_trace_note']}")
        for g in out.get("final_gate", []):
            print(f"      {g['finding_key']} report_ready={g['report_ready']}")

    # C5: the criterion is that the WORKFLOW runs to a terminal state. A hunt
    # that finds nothing is a legitimate terminal outcome.
    return 0 if out.get("ran") else 2


if __name__ == "__main__":
    raise SystemExit(main())
