"""Final validation gate and report quality (master prompt §36, §48, §50).

§48 is the last thing that may say yes:

    Candidate Finding
      -> Technical Validation      -> scope validation
      -> Program Rule Validation   -> duplicate validation
      -> Impact Validation         -> evidence validation
      -> Reproduction Validation   -> FINAL REPORT GATE

"If a critical validation condition fails: NO REPORT", and the finding returns
to whichever state is appropriate — testing, research, revalidation, or
evidence collection. This module IS that gate. Its distinguishing property is
that `gate()` returns a verdict derived from stored state, never from the
caller's opinion, exactly like `orch.validate.apply_validation` re-derives its
verdict.

`validate` (§36) is where the "multiple independent validation paths" lives:
`validation_paths()` enumerates the paths a finding can be proved by and
`required_paths()` demands several for anything important. A finding proved by
one path is explicitly reported as single-path, not as validated — because the
most expensive failure in a report is a finding a triager throws out.

`report_quality` (§50) is a checklist that must be able to fail. It reads the
artifact and returns the items it could NOT verify, so a report marked
REPORT_READY has had each of §50's eleven items checked against something real.
"""
from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from . import agentkit
from . import fp_checklist
from . import lifecycle as lifecycle_mod
from . import store, validate as v1

# ---------------------------------------------------------------------------
# §48 gate stages, in order. `critical` marks a stage whose failure means NO
# REPORT regardless of what the others say.
# ---------------------------------------------------------------------------

GATE_STAGES = (
    ("technical", True, "L1-L2: the claim is well-formed and falsifiable"),
    ("reproduction", True, "L3: a reproduction was actually observed"),
    ("independence", True, "L4: an agent other than the claimant validated it"),
    ("evidence", True, "L5: substantive, inspectable evidence with hashes"),
    ("scope", True, "the asset is inside the confirmed authorization boundary"),
    ("program_rules", True, "no prohibited technique; every action was allowed"),
    ("duplicate", True, "the §38 ladder was walked and the verdict is recorded"),
    ("false_positive", True, "the project's FP checklists are answered and pass"),
    ("origin", True, "the finding's origin is eligible to be reported"),
    ("impact", False, "L6: impact is stated and consistent with severity"),
    ("retest", False, "§40 retest recorded where one was warranted"),
)

# Where a failed gate returns the finding.
RETURN_TO = {
    "technical": "TESTING",
    "reproduction": "TESTING",
    "independence": "TESTING",
    "evidence": "EVIDENCE_COMPLETE",
    "scope": "ABANDONED",
    "program_rules": "ABANDONED",
    "duplicate": "DUPLICATE",
    # A failed FP check is NOT a duplicate and NOT a false positive -- it is
    # a claim that has not been shown to be real. The rules say "ANY NO ->
    # downgrade to LEAD/OBSERVATION", so it returns to TESTING, where the
    # missing checks can be answered with real evidence.
    "false_positive": "TESTING",
    # An INELIGIBLE ORIGIN does not go back for more work: more work
    # cannot make test output into a reportable finding. It is ABANDONED
    # as a reporting candidate, and the record is retained.
    "origin": "ABANDONED",
    "impact": "TESTING",
    "retest": "RETESTED",
}

CRITICAL_STAGES = tuple(n for n, crit, _ in GATE_STAGES if crit)


# THE PROGRAM'S VERDICT, IN THE CORPUS'S VOCABULARY.
#
# `after_triage` accepts four feedback types: accepted, duplicate,
# informative, false_positive. They are NOT interchangeable, and conflating
# them teaches the corpus the wrong thing:
#
#   accepted        -- the finding survived the gate and is reportable.
#   duplicate       -- the finding was REAL but not novel. The technique
#                      works; the corpus must not treat it as a new class.
#   false_positive  -- the finding was not real. The lesson is pushed down
#                      and its state becomes `rejected`, so it never
#                      reaches the corpus.
#   informative     -- the finding was real but not reportable on its own.
#                      The lesson stays, at a slightly lower score.
#
# The mapping is by the FAILED STAGE, not by the coarse verdict, because
# the verdict only says REPORT_READY or NO_REPORT -- it does not say WHY.
# The stage names are the reason.
_FEEDBACK_FOR_FAILED_STAGE = {
    "duplicate": "duplicate",
    "false_positive": "false_positive",
    "scope": "informative",
    "program_rules": "informative",
    "technical": "informative",
    "reproduction": "informative",
    "independence": "informative",
    "evidence": "informative",
    "impact": "informative",
    "retest": "informative",
}


def _feedback_for(fresh: dict) -> str | None:
    """The corpus's feedback vocabulary for this gate outcome.

    A finding that passed every stage is `accepted`. A finding sent back
    for a duplicate is `duplicate`. A finding whose FP check failed is a
    `false_positive`. Anything else that came back is `informative` -- the
    finding is not disproved, it is just not ready, and the corpus should
    not learn that the class is worthless from a technical gap.

    `accepted` IS A CLAIM ABOUT PRODUCTION IMPACT.
    --------------------------------------------
    MEASURED 2026-11-02: `after_triage` gives `accepted` a score delta of
    +0.3, and a verified lesson's score is what `before_recon` and
    `before_summary` rank the next hunt by. So `accepted` means "this class
    produced a reportable production finding" -- and the function returned
    it for ANY finding that cleared the gate, including one whose origin
    was EVAL_TEST.

    The origin is now part of the answer: only an IMPACT-ELIGIBLE origin
    (PRODUCTION_HUNT, MANUAL_ENTRY) may be recorded as `accepted`. An
    ineligible origin is `informative` -- the finding is not disproved, but
    it is not production impact either, and the corpus must not learn that
    its class produced impact.
    """
    verdict = str(fresh.get("verdict") or "")
    failed = [str(s) for s in (fresh.get("failed_critical")
                               or fresh.get("failed_other") or [])]
    if verdict == "REPORT_READY":
        # REPORT_READY already implies the origin stage passed, which
        # implies an impact-eligible origin. The check is repeated here
        # because `_feedback_for` is also reachable from a hand-built
        # verdict dict, and this function must not trust one.
        stages = fresh.get("stages") or {}
        origin_stage = stages.get("origin") or {}
        if origin_stage.get("passed") is False:
            return "informative"
        return "accepted"
    for stage in failed:
        fb = _FEEDBACK_FOR_FAILED_STAGE.get(stage)
        if fb:
            return fb
    return None


def _ensure(con: sqlite3.Connection) -> None:
    """Create the tables this module reads.

    `validation_paths` inspects the agent-result and dedup ledgers, and
    `_duplicate_verdict` inspects the dedup ledger. Neither owns those tables —
    `agentkit` and `lifecycle` do — so this module must not create them, but it
    must also not assume they exist. Without this, `validation_paths` raised
    NameError on any database where no agent had yet reported, which is a
    report of "no paths" disguised as a crash: the caller could not tell a
    missing ledger from a missing path.
    """
    from . import agentkit as _agentkit
    from . import lifecycle as _lifecycle
    _agentkit._ensure(con)
    _lifecycle._ensure(con)


def gate(con: sqlite3.Connection, finding_key: str, *,
         reproduced: bool = False,
         claimant_run: str | None = None,
         validator_run: str | None = None) -> dict[str, Any]:
    """The FINAL REPORT GATE. Derived from stored state; the caller cannot lie.

    Every stage returns `(passed, detail)` and every failure names where the
    finding goes next. A finding that passes every CRITICAL stage is
    `report_ready`; anything else is `no_report` with the return state.
    """
    _ensure(con)
    lc = lifecycle_mod.FindingLifecycle(con)

    # Re-derive L1-L6 through the existing validator. Never trust the caller.
    vec = v1.validate_finding(con, finding_key, reproduced=reproduced,
                              claimant_run=claimant_run,
                              validator_run=validator_run)

    stages: dict[str, dict[str, Any]] = {}

    def rec(name: str, ok: bool, detail: str) -> None:
        stages[name] = {"passed": bool(ok), "detail": detail,
                        "critical": name in CRITICAL_STAGES}

    rec("technical", vec["results"]["L1"]["passed"]
        and vec["results"]["L2"]["passed"],
        f"L1 {vec['results']['L1']['detail']} | L2 "
        f"{vec['results']['L2']['detail']}")
    rec("reproduction", vec["results"]["L3"]["passed"],
        vec["results"]["L3"]["detail"])
    rec("independence", vec["results"]["L4"]["passed"],
        vec["results"]["L4"]["detail"])
    rec("evidence", vec["results"]["L5"]["passed"],
        vec["results"]["L5"]["detail"])
    rec("impact", vec["results"]["L6"]["passed"],
        vec["results"]["L6"]["detail"])

    f = con.execute("SELECT * FROM finding WHERE finding_key=?",
                    (finding_key,)).fetchone()

    # scope: the asset must resolve to `in_scope` in the recorded ledger.
    rec("scope", _scope_ok(con, f), _scope_detail(con, f))

    # program rules: no prohibited technique recorded for this finding's tasks.
    rec("program_rules", _program_rules_ok(con, finding_key),
        _program_rules_detail(con, finding_key))

    # duplicate: the ladder must have been walked and recorded.
    dup = _duplicate_verdict(con, finding_key)
    rec("duplicate", dup["resolved"], dup["detail"])

    # retest: warranted only when something warrants it.
    retests = con.execute(
        "SELECT count(*) n FROM retest_record WHERE finding_key=?",
        (finding_key,)).fetchone()["n"]
    state = lc.state(finding_key)
    needs = state in ("RETESTED", "EVIDENCE_COMPLETE", "REPORT_READY")
    rec("retest", (retests > 0) if needs else True,
        (f"{retests} retest record(s); state={state}"
         if needs else f"no retest warranted at state {state}"))

    # THE ORIGIN STAGE.
    #
    # MEASURED 2026-11-02: the final gate checked technical merit, evidence,
    # scope and program rules -- and never checked WHERE THE FINDING CAME
    # FROM. So a finding produced by the test suite, or by the exam
    # harness, could pass every stage and be written out as a report. The
    # origin was tracked in the corpus, but no gate ever read it.
    #
    # The stage is CRITICAL, and it is the one stage that cannot be
    # answered by more work: no amount of additional evidence turns test
    # output into a reportable production finding.
    #
    # EXAM_FIXTURE is eligible for the EXAM harness and ineligible for
    # REPORTING. The exam writes its own reports through its own path, so
    # refusing an exam fixture here does not break the exam -- it stops
    # the exam's fixture from being mistaken for a production finding.
    origin_ok, origin_detail = _origin_ok(con, f)
    rec("origin", origin_ok, origin_detail)

    # The FALSE-POSITIVE GATE.
    #
    # MEASURED 2026-11-01: the project's own rules state FOUR FP
    # checklists (AGENTS.md:111-115, agent-briefing.md:104-109,
    # prioritization.md:83-94, AGENTS.md:117-119) and NONE of them was
    # implemented, so the final gate could report a finding as
    # REPORT_READY without answering a single one of the project's own FP
    # questions. `orch/fp_checklist.py` implements the union of all four
    # (14 checks) and this stage runs it.
    #
    # The stage is CRITICAL: "ANY NO -> downgrade to LEAD/OBSERVATION.
    # Never report."
    fp_result = fp_checklist.run_fp_gate(con, finding_key)
    rec("false_positive", fp_result["passed"],
        (f"{len(fp_result['failed'])} of {len(fp_result['checks'])} FP checks "
         f"failed: {fp_result['failed']}"
         if not fp_result["passed"] else
         f"all {len(fp_result['checks'])} FP checks passed"))
    # MEASURED 2026-11-01: the stage recorded only `passed`, so a MISSING
    # finding and a finding that FAILED the FP checklist produced the same
    # stage shape. The outcome distinguishes them, and it is what
    # `orch.omh.qa_finding` reads to refuse a certification of a finding
    # that was never checked.
    stages["false_positive"]["outcome"] = fp_result.get("outcome")

    failed = [n for n in CRITICAL_STAGES if not stages[n]["passed"]]
    other_failed = [n for n, _, _ in GATE_STAGES
                    if n not in CRITICAL_STAGES and not stages[n]["passed"]]
    report_ready = not failed and not other_failed
    return_state = RETURN_TO.get(failed[0] if failed else
                                  (other_failed[0] if other_failed else ""),
                                  "TESTING")

    return {
        "finding_key": finding_key,
        "verdict": "REPORT_READY" if report_ready else "NO_REPORT",
        "report_ready": report_ready,
        # The origin, surfaced at the top level: the report states it, and
        # a caller can ask "may this count as production impact?" without
        # reaching into `stages`.
        "origin": (vec.get("origin") or "UNKNOWN"),
        "origin_detail": stages["origin"]["detail"],
        "impact_eligible": bool(vec.get("impact_eligible")),
        "authorization_backed": bool(vec.get("authorization_backed")),
        # The outcome of the FP stage, surfaced at the top level so a caller
        # can tell a MISSING finding from a finding that FAILED validation
        # without reaching into `stages`.
        "outcome": fp_result.get("outcome"),
        "stages": stages,
        "failed_critical": failed,
        "failed_other": other_failed,
        "return_to": None if report_ready else return_state,
        "lifecycle_state": lc.state(finding_key),
        "validation_vector": {k: {"passed": v["passed"], "detail": v["detail"]}
                              for k, v in vec["results"].items()},
        "score": vec["score"],
        "note": ("verdict is derived from stored evidence; a caller-supplied "
                 "verdict is ignored (§48)"),
    }


def apply_gate(con: sqlite3.Connection, finding_key: str, result: dict[str, Any],
               *, changed_by: str = "orch.finalgate") -> str:
    """Persist the gate verdict. The verdict is RE-DERIVED here, not taken."""
    # The ledgers must exist before the verdict can be recorded against them:
    # on a database where no agent has reported, applying the gate raised
    # "no such table" instead of clearing it.
    _ensure(con)
    fresh = gate(con, finding_key,
                 reproduced=bool(result.get("reproduced")),
                 claimant_run=result.get("claimant_run"),
                 validator_run=result.get("validator_run"))
    lc = lifecycle_mod.FindingLifecycle(con)
    if fresh["report_ready"]:
        # MEASURED DEFECT: this called `lc.transition(finding_key,
        # "REPORT_READY")` directly. `REPORT_READY` is legal only from
        # EVIDENCE_COMPLETE or RETESTED, but a real candidate sits at
        # CANDIDATE — so the success path raised IllegalTransition, and it was
        # NOT caught (only the failure branch had a try/except). The single
        # most valuable action in the module could not complete.
        #
        # The finding now WALKS the chain the state machine defines. Each step
        # is attempted, an illegal step is reported rather than raised, and the
        # finding only reaches REPORT_READY if the whole legal path exists.
        cleared = sum(1 for n in CRITICAL_STAGES if fresh["stages"][n]["passed"])
        reason = (f"final gate cleared {cleared}/"
                  f"{len(CRITICAL_STAGES)} critical stages")
        # The evidence the walk cites. MEASURED 2026-11-01: the walk called
        # `lc.transition(...)` with no `evidence_ids`, and the promotion gate
        # (added with the evidence-gated state machine) REFUSES a promotion
        # to VALIDATED/EVIDENCE_COMPLETE/RETESTED/REPORT_READY that cites no
        # evidence. The gate had already verified the evidence -- L5 passed,
        # the FP gate passed, the finding has stored reproductions -- so the
        # walk must CITE it, or the success path cannot complete.
        ev_ids = _evidence_ids(con, finding_key)
        walked: list[str] = []
        # The walk starts at CANDIDATE.
        #
        # MEASURED 2026-11-01: the walk started at TESTING, and
        # `OBSERVED -> TESTING` is not a legal move -- OBSERVED may only go
        # to CANDIDATE, OUT_OF_SCOPE, ABANDONED or RESEARCH_REQUIRED. A
        # finding that had never been through the state machine therefore
        # broke the walk on its first step.
        #
        # The bug was masked: `state()` used to map the legacy
        # `status='candidate'` -- the SCHEMA DEFAULT -- to CANDIDATE, so
        # every fresh finding looked already-promoted. Correcting that
        # inference (a finding with no `finding_state` row has never been
        # through the machine, so it is OBSERVED) exposed the illegal move.
        for step in ("CANDIDATE", "TESTING", "VALIDATED", "EVIDENCE_COMPLETE",
                     "RETESTED", "REPORT_READY"):
            try:
                lc.transition(finding_key, step, reason=reason,
                              changed_by=changed_by, evidence_ids=ev_ids)
                walked.append(step)
            except lifecycle_mod.IllegalTransition as e:
                # A finding already further along (e.g. it was retested
                # earlier) must not be dragged backwards. A no-op write is
                # legal, so this only fires for a genuinely wrong direction.
                if lc.state(finding_key) == step:
                    walked.append(step)
                    continue
                fresh.setdefault("walk_errors", []).append(
                    f"{step}: {e}")
                break
            except lifecycle_mod.PromotionNotSupported as e:
                # The evidence the gate verified is not the evidence the
                # promotion gate accepts -- which must not happen, because
                # the same database holds both. It is reported rather than
                # raised, so the verdict is still recorded.
                fresh.setdefault("walk_errors", []).append(
                    f"{step}: {e}")
                break
        fresh["walked"] = walked
    elif fresh["return_to"]:
        gate_reason = ("final gate: " + ", ".join(fresh["failed_critical"] or
                                                  fresh["failed_other"] or
                                                  [fresh["verdict"]]))
        try:
            lc.transition(finding_key, fresh["return_to"],
                          reason=gate_reason,
                          changed_by=changed_by,
                          levels_failed=[n.upper() for n in fresh["failed_critical"]])
        except lifecycle_mod.IllegalTransition:
            # A finding already terminal (e.g. DUPLICATE) stays where it is;
            # the verdict is recorded either way.
            lc._write(finding_key, lc.state(finding_key), changed_by,
                      gate_reason, None, None)
        except lifecycle_mod.PromotionNotSupported as e:
            # The move is legal in shape but not supported by the evidence
            # presented.
            #
            # MEASURED 2026-11-01: this exception was NOT caught, and the
            # CLI hunt path crashed with an unhandled
            # IllegalTransition/PromotionNotSupported when the gate sent a
            # finding back to a state its evidence did not support. The
            # hunt died at its reporting step, after all its recon work,
            # because a gate verdict could not be recorded.
            #
            # A gate verdict that cannot be written is RECORDED as a
            # verdict, not raised. The finding stays where it is and the
            # reason is recorded, so the work is not lost.
            lc._write(finding_key, lc.state(finding_key), changed_by,
                      f"{gate_reason} (promotion not supported: {e})",
                      None, None)
            fresh.setdefault("walk_errors", []).append(str(e))

    # MEASURED DEFECT (the learning loop's missing terminal link): the gate
    # decided a finding's fate and recorded it, and NOTHING fed that outcome
    # into the learning corpus. MEASURED: no module under `orch/`, `wks/` or
    # `scripts/` imported `learning_engine`, so a confirmed finding produced
    # no lesson and a false positive produced no rejection. The doctrine's
    # loop ends "... -> report -> LEARN", and the LEARN step had no
    # implementation for the hunting half of the corpus.
    #
    # `apply_gate` is the right place: it is where the terminal state is
    # decided and persisted, so the lesson records the state the finding
    # actually reached — not the state a caller asserted.
    #
    # The bridge's result is attached to the verdict rather than swallowed. A
    # bridge that silently drops a lesson looks exactly like a bridge that
    # found nothing to learn.
    try:
        from . import learning_bridge
        lesson = learning_bridge.record_hunt_outcome(
            con, finding_key, lifecycle_state=lc.state(finding_key))
    except Exception as exc:  # pragma: no cover - defensive
        lesson = {"ok": False, "reason": f"learning bridge failed: {exc}"}
    fresh["learning"] = lesson

    # THE PROGRAM'S VERDICT GOES BACK TO THE CORPUS.
    #
    # MEASURED 2026-11-01: `learning_bridge.record_triage_feedback` -- the
    # function that records a program's verdict on a lesson and RECALIBRATES
    # its score -- had no production caller. Only `eval/` called it. So the
    # gate decided a finding's fate and the corpus never heard about it: the
    # `lesson_feedback` table stayed empty, and a lesson the program had
    # rejected as a duplicate kept its score.
    #
    # The verdict the gate just derived is the program's verdict. It is
    # mapped onto the doctrine's feedback vocabulary and recorded against
    # the lesson the bridge produced. A duplicate teaches the corpus that
    # the finding was real but not novel -- which is a DIFFERENT lesson
    # from "this was a false positive", and the two must not be conflated.
    #
    # The feedback is best-effort and REPORTED: the verdict is already
    # persisted on the finding, so a failure here must not undo it.
    verdict = str(fresh.get("verdict") or "")
    fb_type = _feedback_for(fresh)
    if fb_type and lesson.get("ok") and lesson.get("lesson_key"):
        try:
            from . import learning_bridge as _lb
            fb = _lb.record_triage_feedback(
                con, finding_key, feedback_type=fb_type,
                notes=(f"final gate verdict {verdict}"
                       + (f"; failed {', '.join(fresh.get('failed_critical') or fresh.get('failed_other') or [])}"
                          if (fresh.get("failed_critical")
                              or fresh.get("failed_other")) else "")))
            fresh["triage_feedback"] = fb
        except Exception as exc:  # pragma: no cover - defensive
            fresh["triage_feedback"] = {
                "ok": False,
                "reason": f"triage feedback failed: {exc}"}
    return fresh["verdict"]


# ---------------------------------------------------------------------------
# §36 multiple independent validation paths
# ---------------------------------------------------------------------------

VALIDATION_PATHS = (
    "primary_reproduction",
    "independent_reproduction",
    "alternative_method",
    "impact_confirmation",
    "dedup_confirmation",
)

# Paths available for a finding, from what is actually recorded.
PATH_EVIDENCE = {
    "primary_reproduction": ("agent_result", ("CANDIDATE_FINDING",
                                              "OBSERVATION")),
    "independent_reproduction": ("dedup_decision", ()),
    "alternative_method": ("agent_result", ("RESEARCH_RESULT",)),
    "impact_confirmation": ("evidence", ()),
    "dedup_confirmation": ("dedup_decision", ()),
}


def validation_paths(con: sqlite3.Connection, finding_key: str
                     ) -> dict[str, Any]:
    """Which independent validation paths this finding actually has."""
    # The tables are created here rather than assumed: an inspection function
    # that raised "no such table" on a database where no agent had yet reported
    # would report an absence of paths where the truth is an absence of DATA —
    # indistinguishable, and the more flattering of the two.
    _ensure(con)
    have: dict[str, bool] = {}
    # primary: the finding has EITHER evidence attached OR a typed agent result
    # naming it. The earlier form joined `agent_run.finding_key`, a column that
    # does not exist -- agent_run carries task_key, and a run never owned a
    # finding. It raised on every call, so §36's path accounting was the one
    # thing nobody could actually run.
    have["primary_reproduction"] = bool(con.execute(
        "SELECT 1 FROM evidence WHERE finding_id=(SELECT id FROM finding"
        " WHERE finding_key=?) LIMIT 1", (finding_key,)).fetchone()) or bool(
        con.execute("SELECT 1 FROM agent_result WHERE payload LIKE ? LIMIT 1",
                    (f"%{finding_key}%",)).fetchone())
    # independent: a second run validated it (L4's evidence, stored)
    v = con.execute(
        "SELECT validation_json FROM finding WHERE finding_key=?",
        (finding_key,)).fetchone()
    have["independent_reproduction"] = bool(
        v and v["validation_json"] and '"L4"' in v["validation_json"]
        and '"passed": true' in (v["validation_json"] or "").replace(
            "'", '"'))
    have["alternative_method"] = bool(con.execute(
        "SELECT 1 FROM agent_result WHERE type='RESEARCH_RESULT' AND payload"
        " LIKE ? LIMIT 1", (f"%{finding_key}%",)).fetchone())
    have["impact_confirmation"] = bool(con.execute(
        "SELECT 1 FROM evidence WHERE finding_id=(SELECT id FROM finding"
        " WHERE finding_key=?) AND kind IN ('repro','screenshot','response')"
        " LIMIT 1", (finding_key,)).fetchone())
    have["dedup_confirmation"] = bool(con.execute(
        "SELECT 1 FROM dedup_decision WHERE finding_key=? OR vs_key=? LIMIT 1",
        (finding_key, finding_key)).fetchone())

    got = [k for k, v in have.items() if v]
    return {"paths": have, "count": len(got), "present": got,
            "missing": [k for k, v in have.items() if not v],
            "single_path": len(got) < 2,
            "note": ("§36 asks for multiple INDEPENDENT paths; a finding proved "
                     "by one path is reported as single-path, never as "
                     "validated on that basis alone")}


def required_paths(*, important: bool = False) -> int:
    return 3 if important else 2


# ---------------------------------------------------------------------------
# §50 report quality — a checklist that must be able to fail
# ---------------------------------------------------------------------------

REPORT_CHECKS = (
    ("scope", r"(?i)scope|in.scope|authorization"),
    ("technical_correctness", r"(?i)root cause|technical|mechanism"),
    ("reproduction", r"(?i)reproduc|steps to reproduce|proof of concept"),
    ("impact", r"(?i)impact|consequence|risk"),
    ("evidence", r"(?i)evidence|request|response|screenshot"),
    ("root_cause", r"(?i)root cause|origin|because"),
    ("affected_component", r"(?i)affected|component|endpoint|asset|host"),
    ("attack_path", r"(?i)attack path|entry point|chain|via"),
    ("severity_rationale", r"(?i)severity|cvss|rating"),
    ("program_compliance", r"(?i)program|policy|compliance|rate limit"),
    ("duplicate_status", r"(?i)duplicate|known issue|previously reported"),
)


def report_quality(path: str | Path, *, program_requirements: dict[str, Any]
                   | None = None) -> dict[str, Any]:
    """Check each §50 item against the ACTUAL text. Returns the misses."""
    p = Path(path)
    if not p.exists():
        return {"ok": False, "reason": f"report not found: {p}",
                "checks": {}}
    text = p.read_text(encoding="utf-8", errors="replace")
    checks: dict[str, dict[str, Any]] = {}
    for name, pattern in REPORT_CHECKS:
        found = bool(re.search(pattern, text))
        # A program may require a section we did not think of; those are added
        # as extra requirements rather than assumed satisfied.
        checks[name] = {"satisfied": found,
                        "basis": ("matched the report text" if found else
                                  "no matching section in the report")}
    extra: dict[str, dict[str, Any]] = {}
    for req, spec in (program_requirements or {}).items():
        if isinstance(spec, dict) and spec.get("required_section"):
            needle = str(spec["required_section"])
            present = needle.lower() in text.lower()
            extra[req] = {"satisfied": present, "basis": f"required {needle!r}"}
        elif spec is True:
            extra[req] = {"satisfied": False,
                          "basis": "program requires this; not checkable "
                                   "automatically"}

    allc = {**checks, **extra}
    missed = [k for k, v in allc.items() if not v["satisfied"]]
    return {"ok": not missed, "checks": allc, "missed": missed,
            "chars": len(text),
            "note": ("only then may the finding be marked REPORT_READY (§50); "
                     "a report with only validated claims still needs its "
                     "scope, duplicate and compliance sections")}


# ---------------------------------------------------------------------------

def _evidence_ids(con: sqlite3.Connection, finding_key: str) -> list[int]:
    """The ids of the evidence rows stored against a finding.

    The promotion gate requires a promotion to cite its evidence, and the
    final gate's walk must therefore cite the evidence the gate itself
    verified. The ids are the `evidence.id` values, which is what
    `finding_state.evidence_refs` records.
    """
    row = con.execute("SELECT id FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if not row:
        return []
    ids = [int(r["id"]) for r in con.execute(
        "SELECT id FROM evidence WHERE finding_id=? ORDER BY id", (row["id"],))]
    return ids


def _origin_ok(con: sqlite3.Connection, f: sqlite3.Row | None) -> tuple[bool, str]:
    """Is this finding's origin eligible to be REPORTED?

    MEASURED 2026-11-02: the gate never read the origin. A finding
    produced by the test suite or the exam harness could pass every
    technical stage and be rendered as a report, because nothing in the
    gate asked where the finding came from.

    The rule is the project's own vocabulary, in one place
    (`orch/provenance.py`):

      PRODUCTION_HUNT     reportable -- a real finding from a real,
                          authorized hunt
      MANUAL_ENTRY        reportable -- a human filed it, outside any hunt
      IMPORTED_RESEARCH   NOT reportable as a finding: it is research
                          derived from a write-up, not an observation
      EXAM_FIXTURE        NOT reportable: it is the exam harness's own
                          assessment material
      EVAL_TEST           NOT reportable: it is test output
      UNKNOWN             NOT reportable: the origin could not be
                          established, and an absent origin is not a
                          weaker one

    A PRODUCTION_HUNT finding additionally requires its RECEIPT: a
    validated `hunt_authorization` row for its hunt. The origin column
    alone is a claim; the receipt is the proof. A finding whose origin
    says PRODUCTION_HUNT but whose receipt is missing is refused --
    otherwise the column could be set by hand and the gate would have
    nothing left to check.
    """
    from . import provenance as _prov
    if f is None:
        return False, "finding does not exist"
    raw = f["provenance"] if "provenance" in f.keys() else None
    origin = _prov.normalise(raw)
    if origin == _prov.PRODUCTION_HUNT:
        hunt_id = f["hunt_id"] if "hunt_id" in f.keys() else None
        target = f["target"] if "target" in f.keys() else None
        backed, why = _prov.authorization_backs(con, hunt_id=hunt_id,
                                                target=target)
        if not backed:
            return False, (f"origin claims {origin} but the claim is "
                           f"unbacked: {why}")
        return True, f"origin={origin}; {why}"
    if origin == _prov.MANUAL_ENTRY:
        return True, f"origin={origin}: filed by a human, outside any hunt"
    if origin == _prov.IMPORTED_RESEARCH:
        return False, (f"origin={origin}: research derived from a write-up "
                       "is not itself a reportable finding")
    if origin == _prov.EXAM_FIXTURE:
        return False, (f"origin={origin}: the exam harness's own assessment "
                       "material is not a reportable finding")
    if origin == _prov.EVAL_TEST:
        return False, (f"origin={origin}: test output is not a reportable "
                       "finding")
    return False, (f"origin={origin}: the origin could not be established, "
                   "and an absent origin cannot be reported")


def _scope_ok(con: sqlite3.Connection, f: sqlite3.Row | None) -> bool:
    if not f:
        return False
    row = None
    try:
        row = con.execute(
            "SELECT verdict FROM scope_observation WHERE asset IN (?, ?)",
            ((f["target"] or "").lower(), (f["asset"] or "").lower())
        ).fetchone()
    except sqlite3.Error:
        # NO LEDGER, NO LEDGER ROW.
        #
        # MEASURED 2026-11-02: this query raised "no such table:
        # scope_observation" on a fresh database, because the table was
        # created at RUNTIME by `ScopeLedger._ensure` and declared in no
        # schema file. The gate CRASHED rather than judging -- and a gate
        # that crashes is a gate that cannot be relied on to refuse.
        #
        # The table is now declared in `orch/schema.sql`, AND the read
        # fails closed: an absent ledger is treated as an absent ledger
        # row, which falls through to the scope_grant check below.
        row = None
    if row:
        return row["verdict"] == "in_scope"
    # No ledger row: the fallback is the scope_grant table, and only an
    # explicit grant counts.
    try:
        g = con.execute(
            "SELECT offensive_allowed FROM scope_grant WHERE lower(trim(target))=?",
            ((f["target"] or "").lower(),)).fetchone()
    except sqlite3.Error:
        return False
    return bool(g)


def _scope_detail(con: sqlite3.Connection, f: sqlite3.Row | None) -> str:
    if not f:
        return "finding does not exist"
    try:
        row = con.execute(
            "SELECT verdict, tested FROM scope_observation WHERE asset IN (?, ?)",
            ((f["target"] or "").lower(), (f["asset"] or "").lower())
        ).fetchone()
    except sqlite3.Error:
        row = None
    if row:
        return (f"scope_ledger verdict={row['verdict']} tested={row['tested']}")
    try:
        g = con.execute(
            "SELECT scope_key, offensive_allowed FROM scope_grant WHERE"
            " lower(trim(target))=?",
            ((f["target"] or "").lower(),)).fetchone()
    except sqlite3.Error:
        g = None
    return (f"scope_grant {g['scope_key']} offensive={g['offensive_allowed']}"
            if g else "NO authorization record names this target")


def _program_rules_ok(con: sqlite3.Connection, finding_key: str) -> bool:
    n = con.execute(
        "SELECT count(*) n FROM tool_attempt WHERE outcome IN"
        " ('refused','substituted') AND target IN"
        " (SELECT target FROM finding WHERE finding_key=?)",
        (finding_key,)).fetchone()["n"]
    # A substituted attempt is not a violation IF the substitution is the §7
    # permitted equivalent, which resolve() only produces for a prohibited
    # technique. A REFUSED attempt followed by more work on the same target is
    # a real program-rule violation, so only refusals count here.
    return n == 0


def _program_rules_detail(con: sqlite3.Connection, finding_key: str) -> str:
    rows = con.execute(
        "SELECT tool, outcome, detail FROM tool_attempt WHERE outcome="
        "'refused' AND target IN (SELECT target FROM finding"
        " WHERE finding_key=?)", (finding_key,)).fetchall()
    if rows:
        return "; ".join(f"{r['tool']} REFUSED: {r['detail'][:120]}" for r in rows)
    return "no refused tool attempt against this finding's target"


def _duplicate_verdict(con: sqlite3.Connection, finding_key: str
                       ) -> dict[str, Any]:
    rows = con.execute(
        "SELECT verdict, rung, reason FROM dedup_decision WHERE finding_key=?",
        (finding_key,)).fetchall()
    if not rows:
        return {"resolved": False,
                "detail": "the §38 dedup ladder has not been walked for this "
                          "finding"}
    verdicts = {r["verdict"] for r in rows}
    if "independent" in verdicts or "variant" in verdicts:
        return {"resolved": True,
                "detail": "; ".join(f"{r['verdict']} via {r['rung']}: "
                                    f"{r['reason']}" for r in rows)}
    return {"resolved": True,
            "detail": f"duplicate via {rows[0]['rung']}: {rows[0]['reason']}"}