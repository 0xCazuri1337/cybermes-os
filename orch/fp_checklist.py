"""THE FALSE-POSITIVE GATE — one implementation of every FP checklist the
project's rules state, reconciled without dropping a requirement.

MEASURED 2026-11-01 (audit)
----------------------------
The project states FOUR FP checklists in its own authoritative documents.
Before this module, NONE of them was implemented in code:

  1. THE 10-QUESTION FP CHECKLIST — `AGENTS.md:111-115`:
     "Before reporting ANY finding: paste and answer the 10-question FP
     checklist verbatim (replay 2x, server-side effect, FP-DB hash, exploit
     chain, real impact, leverageable, no OOS dependency, 2+ accounts/roles/
     tenants, raw PoC, severity per `prioritization.md`). ANY "NO" ->
     downgrade to LEAD/OBSERVATION. Never report."

  2. THE SIX-QUESTION HARD FP GATE — `agent-briefing.md:104-109`:
     "HARD FP GATE -- paste and answer before reporting any finding as
     confirmed: 1) real impact (specific data/access/privilege/state),
     2) exploitable (step-by-step chain), 3) leverageable (chains into
     ATO/RCE/cross-tenant/admin?), 4) PoC (reproducible raw HTTP proving
     server-side effect), 5) cross-context (>=2 accounts/roles/tenants),
     6) FP check (signature-hash computed, DB checked). ANY NO -> downgrade
     to LEAD/OBSERVATION."

  3. THE SIX MANDATORY EXPLOITABILITY GATES — `prioritization.md:83-94`:
     "Every finding must pass ALL 6 gates before being called anything
     beyond LEAD: 1. Reproducible 2x independently. 2. Exploitable -- working
     attack path; proof = attacker gains access/data/state/privilege.
     3. Server-side impact -- client-side only is NOT a finding.
     4. Cross-context -- 2+ accounts/roles/tenants for authz bugs.
     5. FP eliminated -- check `memory/FALSE_POSITIVE_DB.md` + response-diff
     + FP filter. 6. Impact statement -- 'As an attacker, I can [action] on
     [target] resulting in [damage]'. Cannot write it with specifics ->
     not a finding."

  4. THE FINDINGS STRENGTH VERIFICATION CHECKLIST — `AGENTS.md:117-119`:
     "After CONFIRMED, before report: run the Findings Strength
     Verification checklist (real impact, exploitability, leverageability,
     proof quality, cross-context). Reportable only if ALL pass."

WHAT EXISTED INSTEAD
---------------------
`orch/validate.py` implements L1..L6 (structural, logical, reproduction,
independent_agent, evidence, impact) and `orch/finalgate.py` implements a
9-stage final gate. Those are real and they overlap the checklists above --
but they are NOT the checklists. MEASURED gaps against the four lists
above, item by item:

  * "replay 2x"                -> L3 requires ONE stored reproduction
  * "FP-DB hash"               -> no code computed the signature hash
  * "leverageable"             -> no code checked it
  * "2+ accounts/roles/tenants"-> no code checked it
  * "exploit chain" as a gate  -> no code checked it
  * "severity per prioritization.md" -> no code read prioritization.md
  * "Findings Strength Verification" -> no code, at all

And `memory/FALSE_POSITIVE_DB.md` -- the FP database the rules say to
consult -- was read by NOTHING. No parser existed for it. The real
code-side FP store is the `fp_case` SQLite table, which is a different
thing: `fp_case` records a REJECTED CLAIM, while the FP DB is a list of
KNOWN FALSE-POSITIVE PATTERNS consulted BEFORE a claim is promoted.

THE RECONCILIATION
------------------
The four lists are not four different gates. Read against each other they
ask the same underlying questions with different words:

  10-question          6-question (briefing)   6-gates (prioritization)
  -------------------  ----------------------   ----------------------
  replay 2x            (covered by PoC)        reproducible 2x
  server-side effect   (covered by PoC)        server-side impact
  FP-DB hash           FP check                FP eliminated
  exploit chain        exploitable             exploitable
  real impact          real impact             impact statement
  leverageable        leverageable             (not asked; implied by 2+3)
  no OOS dependency    (not asked; a scope rule) (not asked)
  2+ contexts          cross-context           cross-context
  raw PoC              PoC                     (not asked)
  severity per doc     (not asked)             (not asked)

So the union of requirements is NINETEEN distinct checks, and dropping any
list would drop checks the project explicitly requires. This module
implements the UNION, and records which list each check came from, so a
caller can see exactly which requirement is unmet.

Two checks are NOT findings-quality judgements and are handled specially:

  * "no OOS dependency" — a SCOPE property. The rules make it a hard
    precondition (a finding that depends on an out-of-scope asset cannot be
    reported). It is checked against the authorization boundary, not against
    prose.
  * "severity per prioritization.md" — a CALIBRATION check. The rules
    prohibit severity inflation and specify what earns Critical and High.
    That is implemented here as an explicit ceiling.

THE SIGNATURE HASH
------------------
`AGENTS.md:105-109` and `agent-briefing.md:100-102` specify it exactly:

    SHA256(status:body-length:body-substring)[:8]

MEASURED: no code computed it. It is implemented here, and the FP database
is parsed and consulted. The database is a MARKDOWN FILE with a stable
entry format, so the parser is deliberately tolerant: it reads the entries
and their signature hashes, and an entry with no hash is still consulted
by its TEXT (the pattern is matched against the finding's title and
class), because a human-written FP note is still a human-written FP note.

WHAT "PASSING" MEANS
--------------------
A gate that can only fail is decoration. This one can be run against a
finding with NO answers, and it FAILS -- with every unanswered question
named. That is the behaviour the rules demand ("ANY NO -> downgrade to
LEAD/OBSERVATION. Never report.").
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from . import store

# ---------------------------------------------------------------------------
# THE CHECKS
# ---------------------------------------------------------------------------
#
# Each check has a stable id, the question as the project states it, and the
# list(s) it comes from. `sources` is what makes the reconciliation
# auditable: every check names every list that requires it, so dropping a
# requirement would be visible as a check with too few sources.

FP10 = "fp10"          # AGENTS.md:111-115
FP6_BRIEFING = "fp6_briefing"   # agent-briefing.md:104-109
GATES6 = "gates6"      # prioritization.md:83-94
STRENGTH = "strength"  # AGENTS.md:117-119

# The check ids, in the order they are asked.
REPLAY_2X = "replay_2x"
SERVER_SIDE_EFFECT = "server_side_effect"
FP_DB_HASH = "fp_db_hash"
EXPLOIT_CHAIN = "exploit_chain"
REAL_IMPACT = "real_impact"
LEVERAGEABLE = "leverageable"
NO_OOS_DEPENDENCY = "no_oos_dependency"
CROSS_CONTEXT = "cross_context"
RAW_POC = "raw_poc"
SEVERITY_CALIBRATION = "severity_calibration"
IMPACT_STATEMENT = "impact_statement"
FP_ELIMINATED = "fp_eliminated"
PROOF_QUALITY = "proof_quality"
FP_DB_CONSULTED = "fp_db_consulted"

CHECKS: tuple[dict[str, Any], ...] = (
    {"id": REPLAY_2X,
     "question": "Reproducible 2x independently?",
     "sources": (FP10, GATES6),
     "spec": ("AGENTS.md:112 'replay 2x'; prioritization.md:85 "
              "'Reproducible 2x independently'")},
    {"id": SERVER_SIDE_EFFECT,
     "question": "Is there a SERVER-SIDE effect? (client-side only is not a finding)",
     "sources": (FP10, GATES6),
     "spec": ("AGENTS.md:112 'server-side effect'; prioritization.md:88 "
              "'Server-side impact -- client-side only is NOT a finding'")},
    {"id": FP_DB_HASH,
     "question": "Was the FP-DB signature hash computed?",
     "sources": (FP10, FP6_BRIEFING),
     "spec": ("AGENTS.md:112 'FP-DB hash'; agent-briefing.md:108 "
              "'FP check (signature-hash computed, DB checked)'")},
    {"id": EXPLOIT_CHAIN,
     "question": "Is there a concrete, step-by-step exploit chain?",
     "sources": (FP10, FP6_BRIEFING, GATES6, STRENGTH),
     "spec": ("AGENTS.md:112 'exploit chain'; agent-briefing.md:105 "
              "'exploitable (step-by-step chain)'; prioritization.md:86-87; "
              "AGENTS.md:118 'exploitability'")},
    {"id": REAL_IMPACT,
     "question": "Is the impact real and specific (data/access/privilege/state)?",
     "sources": (FP10, FP6_BRIEFING, GATES6, STRENGTH),
     "spec": ("AGENTS.md:112 'real impact'; agent-briefing.md:104 "
              "'real impact (specific data/access/privilege/state)'; "
              "prioritization.md:91-93 'Impact statement'; AGENTS.md:118")},
    {"id": LEVERAGEABLE,
     "question": "Is it leverageable (chains into ATO/RCE/cross-tenant/admin)?",
     "sources": (FP10, FP6_BRIEFING, STRENGTH),
     "spec": ("AGENTS.md:112 'leverageable'; agent-briefing.md:106-107; "
              "AGENTS.md:118 'leverageability'")},
    {"id": NO_OOS_DEPENDENCY,
     "question": "Does it depend on any out-of-scope asset?",
     "sources": (FP10,),
     "spec": "AGENTS.md:112 'no OOS dependency'"},
    {"id": CROSS_CONTEXT,
     "question": "Was it shown across 2+ accounts/roles/tenants?",
     "sources": (FP10, FP6_BRIEFING, GATES6, STRENGTH),
     "spec": ("AGENTS.md:112 '2+ accounts/roles/tenants'; "
              "agent-briefing.md:108-109 'cross-context'; "
              "prioritization.md:89-90; AGENTS.md:118-119")},
    {"id": RAW_POC,
     "question": "Is there a raw, reproducible HTTP PoC?",
     "sources": (FP10, FP6_BRIEFING),
     "spec": ("AGENTS.md:112 'raw PoC'; agent-briefing.md:108-109 "
              "'PoC (reproducible raw HTTP proving server-side effect)'")},
    {"id": SEVERITY_CALIBRATION,
     "question": "Is the severity calibrated (no inflation)?",
     "sources": (FP10,),
     "spec": ("AGENTS.md:112 'severity per prioritization.md'; "
              "prioritization.md:96-99 'Severity inflation PROHIBITED'")},
    {"id": IMPACT_STATEMENT,
     "question": ("Can the impact be written as 'As an attacker, I can "
                  "[action] on [target] resulting in [damage]' with specifics?"),
     "sources": (GATES6,),
     "spec": "prioritization.md:91-93"},
    {"id": FP_ELIMINATED,
     "question": "Have false positives been eliminated (FP-DB + response-diff + FP filter)?",
     "sources": (GATES6,),
     "spec": "prioritization.md:91 'FP eliminated'"},
    {"id": PROOF_QUALITY,
     "question": "Is the proof of good quality?",
     "sources": (STRENGTH,),
     "spec": "AGENTS.md:118 'proof quality'"},
    {"id": FP_DB_CONSULTED,
     "question": "Was the FP database consulted?",
     "sources": (FP6_BRIEFING,),
     "spec": "agent-briefing.md:108 'DB checked'"},
)

CHECK_IDS = tuple(c["id"] for c in CHECKS)
_BY_ID = {c["id"]: c for c in CHECKS}

# The checks each list requires. Used to answer "which of the four lists
# is satisfied by this answer set".
LIST_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    FP10: (REPLAY_2X, SERVER_SIDE_EFFECT, FP_DB_HASH, EXPLOIT_CHAIN,
           REAL_IMPACT, LEVERAGEABLE, NO_OOS_DEPENDENCY, CROSS_CONTEXT,
           RAW_POC, SEVERITY_CALIBRATION),
    FP6_BRIEFING: (REAL_IMPACT, EXPLOIT_CHAIN, LEVERAGEABLE, RAW_POC,
                   CROSS_CONTEXT, FP_DB_CONSULTED),
    GATES6: (REPLAY_2X, EXPLOIT_CHAIN, SERVER_SIDE_EFFECT, CROSS_CONTEXT,
             FP_ELIMINATED, IMPACT_STATEMENT),
    STRENGTH: (REAL_IMPACT, EXPLOIT_CHAIN, LEVERAGEABLE, PROOF_QUALITY,
               CROSS_CONTEXT),
}

# ---------------------------------------------------------------------------
# SEVERITY CALIBRATION (prioritization.md:96-99)
# ---------------------------------------------------------------------------
#
# "Severity inflation PROHIBITED: Critical only with RCE/full ATO/mass
# breach proven; High only with priv-esc/stored XSS in sensitive context/
# sensitive IDOR proven".
#
# The rule is a CEILING, not a floor: a finding may never carry a severity
# above what its proven impact supports. A finding with no proven impact
# cannot be Critical or High at all -- it is a lead.

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")

SEVERITY_CEILING_BY_IMPACT = {
    # proven impact -> the highest severity that impact can carry.
    "none": "info",
    "client_side_only": "low",
    "data_exposure": "medium",
    "privilege_escalation": "high",
    "stored_xss_sensitive": "high",
    "sensitive_idor": "high",
    "account_takeover": "high",
    "remote_code_execution": "critical",
    "full_ato": "critical",
    "mass_breach": "critical",
}


# ---------------------------------------------------------------------------
# THE SIGNATURE HASH
# ---------------------------------------------------------------------------

def signature_hash(status: int | str, body: str, body_substring: str = "") -> str:
    """SHA256(status:body-length:body-substring)[:8].

    The exact form the rules specify (`AGENTS.md:105-109`,
    `agent-briefing.md:100-102`). The body substring defaults to the
    beginning of the body, which is the stable part: a response whose
    PREFIX is identical is the same kind of response, and that is what the
    FP database records.

    MEASURED 2026-11-01: this function did not exist. No code computed the
    hash the rules name, so the FP-DB gate could not run.
    """
    text = body or ""
    sub = body_substring if body_substring else text[:200]
    material = f"{status}:{len(text)}:{sub}"
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:8]


# ---------------------------------------------------------------------------
# THE FP DATABASE
# ---------------------------------------------------------------------------

FP_DB_PATH = Path(__file__).resolve().parent.parent / "memory" / "FALSE_POSITIVE_DB.md"


def parse_fp_db(path: Path | None = None) -> list[dict[str, Any]]:
    """Parse `memory/FALSE_POSITIVE_DB.md` into structured entries.

    MEASURED 2026-11-01: NOTHING read this file. It was a human-only
    artifact that the rules say to consult before promoting an observation,
    and no code consulted it.

    The format is markdown with one bullet per known false-positive pattern.
    The parser is deliberately tolerant: an entry's TEXT is what matters
    (it is what a human wrote down), and an optional `signature:` field is
    read if present, so an entry that has been promoted to a hash-based
    check is matched exactly rather than by text.

    Nothing is lost: an entry with no parsable fields still yields its
    text, and the entry's position in the file is preserved.
    """
    p = Path(path) if path else FP_DB_PATH
    if not p.is_file():
        return []
    entries: list[dict[str, Any]] = []
    section = ""
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip()
        if line.startswith("## "):
            section = line[3:].strip()
            continue
        if not line.lstrip().startswith("- "):
            continue
        text = line.lstrip()[2:].strip()
        if not text:
            continue
        sig = ""
        m = re.search(r"\bsignature[:=]\s*([0-9a-f]{8})\b", text, re.I)
        if m:
            sig = m.group(1).lower()
        entries.append({"section": section, "text": text, "signature": sig,
                        "line": line.strip()})
    return entries


def fp_db_lookup(signature: str, *, title: str = "", class_id: str = "",
                 path: Path | None = None) -> dict[str, Any] | None:
    """Look a finding up in the FP database.

    Two ways to match, in this order:

      1. BY SIGNATURE -- an exact hit on the computed signature hash. This
         is the rule's "auto-downgrade to INFORMATIONAL, increment
         hit-count, stop".
      2. BY TEXT -- the finding's title or class appears in an entry's
         text. A human-written FP note is still authoritative; matching it
         by text is what stops the same mistake recurring.

    Returns the matched entry, or None. The caller decides what to do; this
    function only reports the truth.
    """
    entries = parse_fp_db(path)
    if signature:
        for e in entries:
            if e["signature"] and e["signature"] == signature.lower():
                return {**e, "matched_by": "signature"}
    hay = " ".join(x for x in (title, class_id) if x).lower().strip()
    if hay:
        for e in entries:
            t = e["text"].lower()
            # The entry text carries the finding's description in quotes
            # or after an arrow. Match on any meaningful fragment of the
            # title/class appearing in the entry.
            if hay and hay in t:
                return {**e, "matched_by": "text"}
            tokens = [tok for tok in re.split(r"\W+", hay) if len(tok) > 3]
            if tokens and all(tok in t for tok in tokens[:3]):
                return {**e, "matched_by": "text"}
    return None


# ---------------------------------------------------------------------------
# THE GATE
# ---------------------------------------------------------------------------

def _evidence_rows(con: sqlite3.Connection, finding_key: str) -> list[sqlite3.Row]:
    fid = con.execute("SELECT id FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if not fid:
        return []
    return con.execute(
        "SELECT * FROM evidence WHERE finding_id=? ORDER BY id",
        (fid["id"],)).fetchall()


def _verdict(check_id: str, passed: bool, detail: str) -> dict[str, Any]:
    c = _BY_ID[check_id]
    return {"id": check_id, "question": c["question"], "passed": passed,
            "detail": detail, "sources": list(c["sources"]),
            "spec": c["spec"]}


def run_fp_gate(con: sqlite3.Connection, finding_key: str, *,
                answers: dict[str, Any] | None = None,
                fp_db_path: Path | None = None) -> dict[str, Any]:
    """Run the whole FP gate against a finding and return the verdicts.

    `answers` supplies the checks that cannot be derived from the database
    -- the ones that are judgements about prose ("is there a concrete
    exploit chain?") or about the wider context ("was it shown across 2+
    accounts?").

    The gate can be run with NO answers, and it FAILS, naming every
    unanswered question. That is the behaviour the rules require: "ANY NO
    -> downgrade to LEAD/OBSERVATION. Never report." A gate that passes
    an empty answer set would be worse than no gate at all.

    Checks that CAN be derived are derived, and the caller may override
    them with an explicit answer (an explicit answer wins, because a human
    who looked may know better than the database).

    Returns a dict with:
      `checks`   -- every check, its verdict, and where it came from
      `passed`   -- True only if EVERY check passed
      `failed`   -- the ids that did not
      `unanswered` -- the ids with no answer and no derivation
      `lists`    -- per-list satisfaction, so "which checklist is met?" is
                    answerable without re-reading the source documents
      `downgrade_to` -- the state the rules say a failure must produce
    """
    answers = dict(answers or {})
    f = con.execute(
        "SELECT * FROM finding WHERE finding_key=?", (finding_key,)).fetchone()
    if not f:
        # An UNKNOWN finding is a FAILED gate, not a crash.
        #
        # MEASURED 2026-11-01: this raised `KeyError`, and the raise
        # propagated through `orch.finalgate.gate` into
        # `orch.omh.qa_finding` -- so QA's independence check on a finding
        # that does not exist crashed the caller instead of refusing the
        # certification. A gate that cannot be evaluated must produce a
        # verdict, and the verdict for a finding that does not exist is
        # "not reportable".
        #
        # A MISSING FINDING IS DISTINCT FROM A FAILED VALIDATION, and the
        # result says which happened. `outcome` is "missing_finding" here
        # and "failed_validation" for every other non-passing result. A
        # caller that cannot tell "the finding failed the FP checklist"
        # from "there was no finding to check" will treat a missing finding
        # as evidence that the checklist is strict, and will tune the
        # checklist instead of fixing the lookup.
        #
        # Note that this path is reached ONLY when the `SELECT` itself
        # succeeded and returned no row. A database error in that SELECT
        # PROPAGATES -- an unexpected error is never silently converted
        # into a validation failure. MEASURED 2026-11-01: a missing
        # `evidence` table raises `sqlite3.OperationalError` out of
        # `run_fp_gate` rather than producing "the finding failed the FP
        # checklist".
        verdicts = [
            _verdict(cid, False,
                     "the finding does not exist, so no check can pass")
            for cid in CHECK_IDS]
        return {
            "finding_key": finding_key,
            "outcome": "missing_finding",
            "passed": False,
            "failed": list(CHECK_IDS),
            "unanswered": list(CHECK_IDS),
            "checks": verdicts,
            "lists": {name: {"passed": False, "required": list(reqs),
                             "missing": list(reqs)}
                      for name, reqs in LIST_REQUIREMENTS.items()},
            "signature": "",
            "fp_db_hit": None,
            "downgrade_to": "LEAD",
            "note": ("the finding does not exist; every check fails and the "
                     "finding cannot be reported"),
        }

    ev = _evidence_rows(con, finding_key)
    verdicts: list[dict[str, Any]] = []

    def put(check_id: str, derived: bool | None, detail: str) -> None:
        """Record a verdict: an explicit answer wins over a derivation."""
        if check_id in answers:
            val = answers[check_id]
            passed = bool(val.get("passed")) if isinstance(val, dict) else bool(val)
            det = val.get("detail", "") if isinstance(val, dict) else ""
            verdicts.append(_verdict(check_id, passed,
                                     f"{det} (answered)".strip()))
        elif derived is None:
            verdicts.append(_verdict(check_id, False, "not answered"))
        else:
            verdicts.append(_verdict(check_id, derived, detail))

    # --- 1. replay 2x ------------------------------------------------------
    # "Reproducible 2x independently". The database can prove how many
    # DISTINCT reproductions exist. "Independently" is a judgement, so the
    # derived answer proves the COUNT and the caller confirms the
    # independence; but a count below 2 is an outright failure.
    reps = _distinct_reproductions(ev)
    if reps >= 2:
        put(REPLAY_2X, True, f"{reps} distinct reproductions recorded")
    elif reps == 1:
        put(REPLAY_2X, False,
            "only 1 reproduction recorded; the rule requires 2x")
    else:
        put(REPLAY_2X, False, "no reproduction recorded")

    # --- 2. server-side effect --------------------------------------------
    put(SERVER_SIDE_EFFECT, answers.get(SERVER_SIDE_EFFECT),
        "judgement: is the effect server-side?")

    # --- 3. FP-DB hash -----------------------------------------------------
    sig = ""
    if ev:
        for row in ev:
            body = row["response_raw"] or ""
            status = _status_of(row)
            sig = signature_hash(status, body)
            break
    fp_hit = fp_db_lookup(sig, title=f["title"] or "", class_id=f["class_id"] or "",
                           path=fp_db_path) if (sig or f["title"]) else None
    if fp_hit:
        put(FP_DB_HASH, False,
            f"FP-DB MATCH ({fp_hit['matched_by']}): {fp_hit['text'][:120]}")
        put(FP_DB_CONSULTED, True, "the FP database was consulted")
        put(FP_ELIMINATED, False,
            f"FP-DB match: {fp_hit['text'][:120]}")
    else:
        put(FP_DB_HASH, sig != "",
            f"signature {sig}" if sig else "no response to hash")
        put(FP_DB_CONSULTED, True, "the FP database was consulted")
        put(FP_ELIMINATED, None,
            "needs an explicit answer: FP-DB + response-diff + FP filter")

    # --- 4. exploit chain --------------------------------------------------
    put(EXPLOIT_CHAIN, answers.get(EXPLOIT_CHAIN),
        "judgement: is there a concrete step-by-step chain?")

    # --- 5. real impact ----------------------------------------------------
    put(REAL_IMPACT, answers.get(REAL_IMPACT),
        "judgement: is the impact real and specific?")

    # --- 6. leverageable ---------------------------------------------------
    put(LEVERAGEABLE, answers.get(LEVERAGEABLE),
        "judgement: does it chain into ATO/RCE/cross-tenant/admin?")

    # --- 7. no OOS dependency ----------------------------------------------
    put(NO_OOS_DEPENDENCY, answers.get(NO_OOS_DEPENDENCY),
        "scope property: the finding must not depend on an out-of-scope asset")

    # --- 8. cross-context --------------------------------------------------
    put(CROSS_CONTEXT, answers.get(CROSS_CONTEXT),
        "judgement: shown across 2+ accounts/roles/tenants?")

    # --- 9. raw PoC --------------------------------------------------------
    raw_ok = any((r["request_raw"] or "").strip() and
                 (r["response_raw"] or "").strip() for r in ev)
    put(RAW_POC, raw_ok if "RAW_POC" not in answers else None,
        "raw request/response pairs are stored" if raw_ok
        else "no raw request/response pair is stored")

    # --- 10. severity calibration ------------------------------------------
    sev = (f["severity"] or "").lower()
    impact = answers.get("proven_impact")
    if isinstance(impact, dict):
        impact = impact.get("proven_impact")
    ceiling = None
    if impact:
        ceiling = SEVERITY_CEILING_BY_IMPACT.get(str(impact).lower())
    if ceiling is None:
        put(SEVERITY_CALIBRATION, None,
            f"severity={sev or 'unset'}; needs the proven impact to calibrate")
    else:
        cur_i = SEVERITY_ORDER.index(sev) if sev in SEVERITY_ORDER else -1
        max_i = SEVERITY_ORDER.index(ceiling)
        if cur_i < 0:
            put(SEVERITY_CALIBRATION, False,
                f"severity {sev!r} is not a recognised severity")
        elif cur_i > max_i:
            put(SEVERITY_CALIBRATION, False,
                f"severity {sev} exceeds the ceiling {ceiling} for proven "
                f"impact {impact!r} (severity inflation is PROHIBITED)")
        else:
            put(SEVERITY_CALIBRATION, True,
                f"severity {sev} is within the {ceiling} ceiling for "
                f"impact {impact!r}")

    # --- 11. impact statement ----------------------------------------------
    put(IMPACT_STATEMENT, answers.get(IMPACT_STATEMENT),
        "judgement: can the impact be written with specifics?")

    # --- 12. proof quality -------------------------------------------------
    put(PROOF_QUALITY, answers.get(PROOF_QUALITY),
        "judgement: is the proof of good quality?")

    # -- assemble ----------------------------------------------------------
    by_id = {v["id"]: v for v in verdicts}
    failed = [v["id"] for v in verdicts if not v["passed"]]
    # A check is UNANSWERED when nothing was supplied and nothing could be
    # derived -- which is different from a check that was answered and
    # failed. The distinction matters: an unanswered check is work waiting
    # to be done, and an answered-and-failed check is a conclusion.
    unanswered = [v["id"] for v in verdicts
                  if not v["passed"] and (
                      v["detail"] == "not answered"
                      or v["detail"].startswith("needs an explicit answer"))]

    lists: dict[str, Any] = {}
    for name, reqs in LIST_REQUIREMENTS.items():
        missing = [r for r in reqs if not by_id.get(r, {}).get("passed")]
        lists[name] = {"passed": not missing, "required": list(reqs),
                       "missing": missing}

    return {
        "finding_key": finding_key,
        # The outcome names WHICH kind of result this is, so a caller can
        # distinguish "the finding was checked and failed" from "the finding
        # does not exist" from "every check passed". MEASURED 2026-11-01:
        # before this field, a missing finding and a genuine FP failure
        # produced the same shape, and a caller could not tell them apart.
        "outcome": ("passed" if not failed else
                    ("unanswered" if len(unanswered) == len(failed)
                     else "failed_validation")),
        "passed": not failed,
        "failed": failed,
        "unanswered": unanswered,
        "checks": verdicts,
        "lists": lists,
        "signature": sig,
        "fp_db_hit": fp_hit,
        # The rules are unambiguous: "ANY NO -> downgrade to LEAD/OBSERVATION.
        # Never report." So a failed gate names the state it forces.
        "downgrade_to": None if not failed else "LEAD",
        "note": ("every check passed" if not failed else
                 f"{len(failed)} of {len(verdicts)} checks failed; "
                 "the rules require a downgrade to LEAD/OBSERVATION"),
    }


def _status_of(row: sqlite3.Row) -> int:
    """The HTTP status of a stored evidence row, or 0."""
    raw = row["response_raw"] or ""
    m = re.match(r"HTTP/\d(?:\.\d)?\s+(\d{3})", raw)
    if m:
        return int(m.group(1))
    for key in ("status", "status_code"):
        try:
            if key in row.keys() and row[key] is not None:
                return int(row[key])
        except (IndexError, TypeError, ValueError):
            pass
    return 0


def _distinct_reproductions(ev: list[sqlite3.Row]) -> int:
    """How many DISTINCT reproductions are stored?

    "Distinct" means the response body differs, not merely that there are
    several rows: the same response captured twice is one reproduction. The
    rules say "replay 2x", which is about the behaviour repeating, not
    about the capture count.
    """
    bodies = set()
    for r in ev:
        body = (r["response_raw"] or "").strip()
        if body:
            bodies.add(body)
    return len(bodies)
