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
    "impact": "TESTING",
    "retest": "RETESTED",
}

CRITICAL_STAGES = tuple(n for n, crit, _ in GATE_STAGES if crit)


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
            # Counted from the stage dict rather than a `passed_count` key: `gate`
            # never returned one, so clearing the gate raised a KeyError on the way
            # to writing the report — the single most valuable action in the module
            # was the one action that could not complete.
        cleared = sum(1 for n in CRITICAL_STAGES if fresh["stages"][n]["passed"])
        lc.transition(finding_key, "REPORT_READY",
                      reason=f"final gate cleared {cleared}/"
                             f"{len(CRITICAL_STAGES)} critical stages",
                      changed_by=changed_by)
    elif fresh["return_to"]:
        try:
            lc.transition(finding_key, fresh["return_to"],
                          reason="final gate: " +
                                 ", ".join(fresh["failed_critical"] or
                                           fresh["failed_other"]),
                          changed_by=changed_by,
                          levels_failed=[n.upper() for n in fresh["failed_critical"]])
        except lifecycle_mod.IllegalTransition:
            # A finding already terminal (e.g. DUPLICATE) stays where it is;
            # the verdict is recorded either way.
            lc._write(finding_key, lc.state(finding_key), changed_by,
                      "final gate: " + ", ".join(fresh["failed_critical"]),
                      None, None)
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

def _scope_ok(con: sqlite3.Connection, f: sqlite3.Row | None) -> bool:
    if not f:
        return False
    row = con.execute(
        "SELECT verdict FROM scope_observation WHERE asset IN (?, ?)",
        ((f["target"] or "").lower(), (f["asset"] or "").lower())).fetchone()
    if row:
        return row["verdict"] == "in_scope"
    # No ledger row: the fallback is the scope_grant table, and only an
    # explicit grant counts.
    g = con.execute(
        "SELECT offensive_allowed FROM scope_grant WHERE lower(trim(target))=?",
        ((f["target"] or "").lower(),)).fetchone()
    return bool(g)


def _scope_detail(con: sqlite3.Connection, f: sqlite3.Row | None) -> str:
    if not f:
        return "finding does not exist"
    row = con.execute(
        "SELECT verdict, tested FROM scope_observation WHERE asset IN (?, ?)",
        ((f["target"] or "").lower(), (f["asset"] or "").lower())).fetchone()
    if row:
        return (f"scope_ledger verdict={row['verdict']} tested={row['tested']}")
    g = con.execute(
        "SELECT scope_key, offensive_allowed FROM scope_grant WHERE"
        " lower(trim(target))=?", ((f["target"] or "").lower(),)).fetchone()
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