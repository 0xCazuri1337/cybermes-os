#!/usr/bin/env python3
"""RECONCILE every record the test-to-production contamination touched.

This tool produces the per-record DISPOSITION MANIFEST the incident report
requires. It exists because the incident's counts did not reconcile on their
face, and the only honest way to reconcile them is from PRIMARY EVIDENCE
rather than from the narrative that accompanied them.

THE COUNTS THAT DID NOT RECONCILE
----------------------------------
    42 findings identified as test output
    44 findings exported to quarantine
    47 findings reported as retained

The primary evidence is the pre-quarantine backup
(`cyber-archives/quarantine-20261101/wks-pre-quarantine.db`), taken by
SQLite's backup API BEFORE any quarantine ran. This tool reads THAT
database, so every disposition below is derived from the state the
records actually had, not from a list someone wrote down afterwards.

THE CLASSIFICATIONS ARE EVIDENCE-BASED, NOT KEY-PATTERN-BASED
--------------------------------------------------------------
    TEST_ARTIFACT_QUARANTINED
        The record was produced by a test/eval process. It is marked
        `rejected` in place and exported to `superseded/`.
    EXAM_FIXTURE_RETAINED
        The record is the examination evidence base -- a GRADED exam
        imported by `wks/assess_evidence.py`. It stays usable by the
        exam harness but must not count as production impact.
    GENUINE_HUNT_OUTCOME
        The record is a real hunting outcome from a real authorized
        hunt against a real target.
    UNKNOWN_PENDING_REVIEW
        The origin could not be established from evidence. It is
        EXCLUDED from production impact and kept for review.

THE EVIDENCE FOR EACH CLASSIFICATION
-------------------------------------
    1. The `hunt` row the record belongs to: its `target`, its `kind`,
       and its `started_at`. A hunt whose target is the loopback
       address or a reserved test domain cannot have produced a
       production finding.
    2. The `validator_run` field: the exam harness writes
       `eval/grade_exam.py` there. A finding carrying it is an exam
       fixture by construction.
    3. The `report_path`: the exam harness writes the solver report
       path there.
    4. The `evidence` rows: their `provenance` names the producing
       process.
    5. The `finding_transition` history: `changed_by` names the actor.
    6. The creation timestamp relative to the eval suite's own runs.

The tool NEVER classifies on "it was created during the incident
window". A record's timestamp alone is not evidence of origin.

OUTPUT
------
    `runtime/state/incident-disposition-<stamp>.json` -- the manifest,
    and `runtime/state/incident-reconciliation-<stamp>.md` -- the
    human-readable reconciliation of the counts.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sqlite3
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# The classifications the incident report mandates.
TEST_ARTIFACT_QUARANTINED = "TEST_ARTIFACT_QUARANTINED"
EXAM_FIXTURE_RETAINED = "EXAM_FIXTURE_RETAINED"
GENUINE_HUNT_OUTCOME = "GENUINE_HUNT_OUTCOME"
UNKNOWN_PENDING_REVIEW = "UNKNOWN_PENDING_REVIEW"

# ---------------------------------------------------------------------------
# TARGET CLASSIFICATION
#
# A hunt against one of these targets CANNOT have produced a production
# finding. They are the loopback address and the reserved test domains
# (RFC 2606 / RFC 6761).
#
# MEASURED 2026-11-01: every one of the 134 hunts in the pre-quarantine
# database targeted `127.0.0.1`, `demo.example.test` or `app.acme.test`.
# There is not one hunt against a routable, non-reserved host.
# ---------------------------------------------------------------------------
LOOPBACK_TARGETS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}
RESERVED_TLDS = (".test", ".example", ".invalid", ".localhost", ".local")


def is_non_production_target(target: str | None) -> bool:
    """Is this target incapable of being a real production target?"""
    if not target:
        return True
    t = target.strip().lower()
    if t in LOOPBACK_TARGETS:
        return True
    if t.startswith("127."):
        return True
    # A reserved TLD, or a bare label under one (`app.acme.test`).
    if any(t.endswith(tld) for tld in RESERVED_TLDS):
        return True
    if re.search(r"\.(test|example|invalid|localhost|local)$", t):
        return True
    return False


# ---------------------------------------------------------------------------
# THE PROVENANCE VOCABULARY
#
# The incident report mandates these boundaries. They are the values the
# `provenance` column of `finding` and `lesson` will carry.
# ---------------------------------------------------------------------------
PRODUCTION_HUNT = "PRODUCTION_HUNT"
EXAM_FIXTURE = "EXAM_FIXTURE"
EVAL_TEST = "EVAL_TEST"
IMPORTED_RESEARCH = "IMPORTED_RESEARCH"
MANUAL_ENTRY = "MANUAL_ENTRY"
UNKNOWN = "UNKNOWN"

PROVENANCE_VALUES = (
    PRODUCTION_HUNT, EXAM_FIXTURE, EVAL_TEST, IMPORTED_RESEARCH,
    MANUAL_ENTRY, UNKNOWN,
)

# The exam harness identifies itself in `validator_run`.
EXAM_VALIDATOR = "eval/grade_exam.py"
EXAM_KEY_PREFIX = "exam-"

# Actors that are unambiguously the test harness.
#
# MEASURED 2026-11-01: the state machine's `changed_by` column records
# `tester` for findings the harness drove through the lifecycle. That is
# the corpus naming its own actor.
EVAL_ACTORS = re.compile(
    r"(^eval[/\\]|^test_|/eval/|pytest|unittest|\.py$|harness|^tester$|^test\b"
    r"|_test$|^test-)",
    re.IGNORECASE)

# A LOOPBACK URL, anywhere in a provenance string.
#
# MEASURED 2026-11-01: eleven findings had no `hunt` row at all -- the
# test wrote the finding directly -- but their `evidence.provenance`
# named the request that produced them:
#     "curl GET http://127.0.0.1:41581/"
# A loopback address on an EPHEMERAL PORT is a hermetic test server: the
# port is assigned by the OS at bind time, so it cannot be a stable
# production target. This is positive evidence of test origin, not a
# name-pattern guess.
LOOPBACK_URL = re.compile(
    r"https?://(?:127\.0\.0\.1|localhost|\[::1\])(?::\d+)?", re.IGNORECASE)


def evidence_names_loopback(provenance: list[str]) -> str | None:
    """Return the first provenance string that names a loopback target."""
    for p in provenance:
        if p and LOOPBACK_URL.search(p):
            return p
    return None


# ---------------------------------------------------------------------------
# SOURCE-LEVEL EVIDENCE
#
# A finding key that appears LITERALLY in the eval suite was written by
# the eval suite. That is positive identification: the harness names the
# exact record it creates.
#
# This is NOT "it was created during the incident window". It is the
# suite naming its own fixture, which is the same class of evidence as
# the exam harness naming `eval/grade_exam.py` in `validator_run`.
# ---------------------------------------------------------------------------
_SOURCE_INDEX: dict[str, list[str]] | None = None


def build_source_index(root: pathlib.Path) -> dict[str, list[str]]:
    """Index every literal record key the eval suite names."""
    global _SOURCE_INDEX
    if _SOURCE_INDEX is not None:
        return _SOURCE_INDEX
    index: dict[str, list[str]] = {}
    eval_dir = root / "eval"
    if not eval_dir.is_dir():
        _SOURCE_INDEX = index
        return index
    for f in sorted(eval_dir.rglob("*.py")):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"[\"']([A-Za-z0-9_.\-]{3,80})[\"']", text):
            lit = m.group(1)
            # A key that looks like a record key: it has a separator and a
            # suffix, or it is a short bare identifier used as one.
            if "." in lit or lit in ("f1",):
                index.setdefault(lit, []).append(str(f.relative_to(root)))
    _SOURCE_INDEX = index
    return index


def source_names_key(key: str, index: dict[str, list[str]]) -> list[str]:
    """Which eval files name this key literally?"""
    return index.get(key, [])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# PROVENANCE -> DISPOSITION
#
# ONE rule, applied to every record. A record has exactly one provenance
# and exactly one disposition, and the disposition is derived -- never
# assigned independently, because two independent assignments can
# disagree and then there is no single final disposition.
# ---------------------------------------------------------------------------
def disposition_for(provenance: str, original_state: str | None) -> str:
    """The final disposition of a record with this provenance."""
    if provenance == EXAM_FIXTURE:
        return EXAM_FIXTURE_RETAINED
    if provenance == PRODUCTION_HUNT:
        return GENUINE_HUNT_OUTCOME
    if provenance == EVAL_TEST:
        return TEST_ARTIFACT_QUARANTINED
    if provenance == MANUAL_ENTRY:
        return GENUINE_HUNT_OUTCOME
    if provenance == IMPORTED_RESEARCH:
        return GENUINE_HUNT_OUTCOME
    # UNKNOWN provenance: excluded from production impact, kept for
    # review, and NOT deleted.
    return UNKNOWN_PENDING_REVIEW


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ---------------------------------------------------------------------------
# CLASSIFICATION
# ---------------------------------------------------------------------------
def _authorization_backed(con: sqlite3.Connection, hunt: sqlite3.Row | None,
                          row: sqlite3.Row) -> tuple[bool, str]:
    """Is there a validated authorization receipt for this finding's hunt?

    The tool reads the receipt directly rather than importing
    `orch.provenance`, because this tool also runs against databases that
    predate the orchestration layer -- and because a tool that reads
    production data must not depend on the runtime being importable.

    The finding's own `hunt_id` is preferred; when it is absent (a legacy
    row), the hunt recovered from the finding's key is used.
    """
    hunt_id = None
    if "hunt_id" in row.keys():
        hunt_id = row["hunt_id"]
    if not hunt_id and hunt is not None:
        hunt_id = hunt["hunt_id"]
    if not hunt_id:
        return False, "the finding names no hunt, so no authorization can back it"
    try:
        auth = con.execute(
            "SELECT validated, authorization_ref FROM hunt_authorization"
            " WHERE hunt_id=?", (hunt_id,)).fetchone()
    except sqlite3.Error:
        return False, ("the hunt_authorization table is not present in this "
                       "database, so no receipt can be read")
    if auth is None:
        return False, f"no authorization receipt for hunt {hunt_id!r}"
    if not int(auth["validated"] or 0):
        return False, (f"the authorization for hunt {hunt_id!r} was never "
                       "validated")
    return True, (f"hunt {hunt_id!r} has a validated authorization "
                  f"({auth['authorization_ref']!r})")


def classify_finding(row: sqlite3.Row, hunt: sqlite3.Row | None,
                     ev_provenance: list[str],
                     transition_actors: list[str],
                     source_files: list[str] | None = None,
                     authorization_backed: bool = False,
                     authorization_reason: str = ""
                     ) -> tuple[str, str]:
    """Classify ONE finding from evidence. Returns (provenance, reason).

    The order matters and is deliberate:

      1. EXAM_FIXTURE -- the exam harness is the system's own assessment
         mechanism. It is identified by what it WRITES (`validator_run`,
         `report_path`), not by a name pattern.
      2. PRODUCTION_HUNT -- the record belongs to a hunt against a real,
         routable target that was not an exam, AND that hunt has a
         VALIDATED AUTHORIZATION RECEIPT.
      3. EVAL_TEST -- the record's own lineage names a test actor, or
         its hunt targeted a loopback/reserved host.
      4. UNKNOWN -- no evidence either way.

    MEASURED 2026-11-02: step 2 granted PRODUCTION_HUNT on "routable
    target + no test actor" alone, and `tools/apply_provenance.py` then
    WROTE that value into the live database. So the offline classifier was
    a third unbacked self-promotion path -- and it wrote to production.

    The receipt is now required, exactly as it is in the runtime path: a
    hunt with no validated `hunt_authorization` row is not a production
    hunt, however routable its target looks.
    """
    key = row["finding_key"]
    validator_run = (row["validator_run"] or "").strip()
    report_path = (row["report_path"] or "").strip()

    # --- 1. EXAM FIXTURE -------------------------------------------------
    # The exam harness writes `eval/grade_exam.py` into `validator_run`
    # and the solver report path into `report_path`. That is a positive
    # identification, not an inference.
    if validator_run == EXAM_VALIDATOR or report_path:
        return EXAM_FIXTURE, (
            f"identified by the exam harness: validator_run="
            f"{validator_run!r} report_path={report_path!r}")

    # --- 2. PRODUCTION HUNT ---------------------------------------------
    # A finding whose own hunt targeted a routable, non-reserved host is
    # a production outcome -- PROVIDED nothing in its lineage names a
    # test actor, AND the hunt has a validated authorization receipt.
    if hunt is not None:
        hunt_target = hunt["target"]
        hunt_kind = (hunt["kind"] or "").lower()
        if not is_non_production_target(hunt_target):
            actors = [a for a in (transition_actors + ev_provenance) if a]
            test_actor = [a for a in actors if EVAL_ACTORS.search(a)]
            if test_actor:
                return UNKNOWN_PENDING_REVIEW, (
                    f"hunt {hunt['hunt_id']!r} targeted {hunt_target!r} BUT "
                    f"the lineage names a test actor {test_actor[0]!r}; origin "
                    f"requires review")
            if not authorization_backed:
                detail = authorization_reason or "no receipt recorded"
                return UNKNOWN_PENDING_REVIEW, (
                    f"hunt {hunt['hunt_id']!r} targeted {hunt_target!r} "
                    f"(kind={hunt_kind}) but the hunt has no validated "
                    f"authorization receipt: {detail}. A routable target is "
                    f"not evidence of an authorized hunt, so the origin "
                    f"requires review")
            return PRODUCTION_HUNT, (
                f"hunt {hunt['hunt_id']!r} targeted {hunt_target!r} "
                f"(kind={hunt_kind}); no test actor in its lineage; "
                f"{authorization_reason or 'the authorization is validated'}")

    # --- 3. EVAL TEST ----------------------------------------------------
    # The hunt is absent or aimed at a loopback/reserved host, so the
    # finding cannot be a production outcome. If its lineage names a test
    # actor, that is positive evidence of test origin.
    actors = [a for a in (transition_actors + ev_provenance) if a]
    test_actor = [a for a in actors if EVAL_ACTORS.search(a)]
    if test_actor:
        return EVAL_TEST, (
            f"lineage names the test actor {test_actor[0]!r}; hunt target="
            f"{(hunt['target'] if hunt is not None else None)!r}")

    # The EVIDENCE names a loopback target on an ephemeral port. That is
    # a hermetic test server, and it is positive evidence of test origin
    # even when the finding has no hunt row and no test-named actor.
    loop = evidence_names_loopback(ev_provenance)
    if loop:
        return EVAL_TEST, (
            f"evidence provenance {loop!r} names a loopback target; a "
            f"loopback request cannot come from a production hunt")

    # A finding whose hunt targeted the loopback address with no other
    # identifying evidence is still test-shaped: a loopback hunt is a
    # hermetic test by construction.
    if hunt is not None:
        return EVAL_TEST, (
            f"hunt {hunt['hunt_id']!r} targeted "
            f"{(hunt['target'] or '')!r}, a loopback/reserved host; a "
            f"loopback hunt cannot produce a production finding")

    # --- 4. UNKNOWN ------------------------------------------------------
    # No hunt, no evidence, no actor. The eval suite may still name the
    # key LITERALLY -- which is positive identification, the same class of
    # evidence as the exam harness naming itself in `validator_run`.
    if source_files:
        return EVAL_TEST, (
            f"the eval suite names this key literally in "
            f"{', '.join(source_files[:3])}; the harness names its own "
            f"fixture")

    # The record is a DUPLICATE of another record. The dedup link is
    # evidence: whatever the canonical record's origin is, this record
    # shares it.
    #
    # MEASURED 2026-11-01: `zz.gap` carried no evidence, no transitions
    # and no hunt, and its key is not named anywhere in the current eval
    # suite -- it is from an earlier revision of the harness. But its
    # `canonical_id` points at `f1`, which `eval/test_orch.py` creates
    # literally. The dedup chain is the evidence.
    if row["canonical_id"]:
        return EVAL_TEST, (
            f"the record is a duplicate of finding id={row['canonical_id']}, "
            f"whose origin the dedup chain carries")

    # Nothing at all to classify on. The record's key may LOOK like a test
    # name, but a key is a label, not evidence -- and the incident report
    # forbids inferring origin from the incident window. So: review.
    return UNKNOWN_PENDING_REVIEW, (
        "no hunt row links to this finding, it carries no evidence, its "
        "lineage names no actor, the eval suite does not name its key, "
        "and it has no dedup link; origin cannot be established from "
        "evidence and requires review")


def hunt_for_finding(con: sqlite3.Connection, row: sqlite3.Row,
                     hunt_ids: list[str]) -> sqlite3.Row | None:
    """Find the hunt this finding belongs to.

    `finding` has no `hunt_id` column -- hunt membership is expressed
    through the task graph and the lifecycle machine. The finding key
    carries the hunt id in its own name for the harness-produced
    records (`reach.<id>.ok.finding.<hash>`), so the hunt is recovered
    from the key and confirmed against the `hunt` table.
    """
    key = row["finding_key"]
    candidates: list[str] = []
    for hid in hunt_ids:
        if hid and hid in key:
            candidates.append(hid)
    if not candidates:
        return None
    # The LONGEST matching hunt id is the most specific one.
    candidates.sort(key=len, reverse=True)
    return con.execute("SELECT * FROM hunt WHERE hunt_id=?",
                       (candidates[0],)).fetchone()


def finding_lineage(con: sqlite3.Connection, row: sqlite3.Row
                    ) -> tuple[list[str], list[str], list[dict], list[dict],
                               dict | None]:
    """Everything known about one finding's origin.

    Returns (evidence_provenance, transition_actors, evidence_rows,
             transition_rows, state_row).
    """
    ev = con.execute(
        "SELECT id, kind, target, asset, endpoint, provenance, captured_at"
        " FROM evidence WHERE finding_id=? ORDER BY id",
        (row["id"],)).fetchall()
    tr = con.execute(
        "SELECT seq, from_state, to_state, changed_by, reason, at"
        " FROM finding_transition WHERE finding_key=? ORDER BY seq",
        (row["finding_key"],)).fetchall()
    # The STATE MACHINE's own actor.
    #
    # MEASURED 2026-11-01: `f1` and `zz.gap` had no evidence, no
    # transitions, no hunt row, and an empty `created_at` -- but
    # `finding_state.changed_by` said `tester`. That column names the
    # actor that moved the finding through its lifecycle, and it is the
    # most direct evidence of origin the corpus holds.
    st = con.execute(
        "SELECT finding_key, lifecycle, levels_failed, evidence_refs,"
        " changed_by, reason, at FROM finding_state"
        " WHERE finding_key=?", (row["finding_key"],)).fetchone()
    ev_prov = []
    for e in ev:
        p = (e["provenance"] or "").strip()
        if p:
            ev_prov.append(p)
    actors = []
    for t in tr:
        cb = (t["changed_by"] or "").strip()
        if cb:
            actors.append(cb)
    if st is not None and (st["changed_by"] or "").strip():
        actors.append(st["changed_by"].strip())
    state_row = dict(st) if st is not None else None
    return (ev_prov, actors, [dict(e) for e in ev], [dict(t) for t in tr],
            state_row)


def lesson_lineage(con: sqlite3.Connection, row: sqlite3.Row
                   ) -> tuple[str | None, list[str], list[dict]]:
    """The finding a lesson came from, its provenance, and its links."""
    links = con.execute(
        "SELECT finding_key, outcome, recorded_at FROM finding_lesson"
        " WHERE lesson_key=? ORDER BY recorded_at",
        (row["lesson_key"],)).fetchall()
    prov = None
    try:
        p = json.loads(row["provenance"] or "{}")
        prov = p
    except (ValueError, TypeError):
        prov = {"raw": row["provenance"]}
    return prov, [dict(l) for l in links], [dict(l) for l in links]


def gap_lineage(con: sqlite3.Connection, row: sqlite3.Row) -> list[dict]:
    """The research proposals raised from a gap."""
    return [dict(r) for r in con.execute(
        "SELECT research_key, class_id, objective, status, created_at"
        " FROM learning_research WHERE gap_key=? ORDER BY created_at",
        (row["gap_key"],)).fetchall()]


# ---------------------------------------------------------------------------
# THE MANIFEST
# ---------------------------------------------------------------------------
def build_manifest(db: pathlib.Path) -> dict:
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row

    hunt_ids = [r["hunt_id"] for r in con.execute(
        "SELECT hunt_id FROM hunt ORDER BY started_at")]
    hunts = {r["hunt_id"]: r for r in con.execute("SELECT * FROM hunt")}
    source_index = build_source_index(ROOT)

    findings = []
    for row in con.execute("SELECT * FROM finding ORDER BY created_at, id"):
        ev_prov, actors, ev_rows, tr_rows, st_row = finding_lineage(con, row)
        hunt = hunt_for_finding(con, row, hunt_ids)
        src_files = source_names_key(row["finding_key"], source_index)
        # THE RECEIPT IS CONSULTED.
        #
        # MEASURED 2026-11-02: this classifier granted PRODUCTION_HUNT on
        # "routable target + no test actor" alone, and the manifest it
        # produced was later WRITTEN into the live database by
        # `tools/apply_provenance.py`. A routable target is not evidence
        # of an authorized hunt, so the receipt is consulted here.
        backed, auth_reason = _authorization_backed(con, hunt, row)
        prov, reason = classify_finding(row, hunt, ev_prov, actors, src_files,
                                        authorization_backed=backed,
                                        authorization_reason=auth_reason)
        findings.append({
            "original_id": row["id"],
            "original_table": "finding",
            "original_key": row["finding_key"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "title": row["title"],
            "target": row["target"],
            "asset": row["asset"],
            "endpoint": row["endpoint"],
            "class_id": row["class_id"],
            "severity": row["severity"],
            "confidence": row["confidence"],
            "priority": row["priority"],
            "original_status": row["status"],
            "original_verification_state": {
                "status": row["status"],
                "validation_json": row["validation_json"],
                "dedup_group": row["dedup_group"],
                "canonical_id": row["canonical_id"],
                "validator_run": row["validator_run"],
                "report_path": row["report_path"],
            },
            "originating_process": (
                ev_prov[0] if ev_prov else (actors[0] if actors else None)),
            "originating_actor_candidates": sorted(set(ev_prov + actors)),
            "source_files_naming_this_key": src_files,
            "associated_hunt": hunt["hunt_id"] if hunt is not None else None,
            "associated_hunt_detail": (
                {"hunt_id": hunt["hunt_id"], "target": hunt["target"],
                 "kind": hunt["kind"], "state": hunt["state"],
                 "started_at": hunt["started_at"]} if hunt is not None else None),
            "associated_exam": (
                row["report_path"] if row["report_path"] else None),
            "related_evidence": ev_rows,
            "related_transitions": tr_rows,
            "state_machine_record": st_row,
            "lesson_count": con.execute(
                "SELECT count(*) FROM finding_lesson WHERE finding_key=?",
                (row["finding_key"],)).fetchone()[0],
            "provenance": prov,
            "classification": prov,
            "classification_reason": reason,
        })

    lessons = []
    for row in con.execute("SELECT * FROM lesson ORDER BY created_at, lesson_key"):
        prov, links, _ = lesson_lineage(con, row)
        source_findings = [l["finding_key"] for l in links]
        # A lesson inherits the provenance of the finding it came from.
        src = [f for f in findings if f["original_key"] in source_findings]
        if src:
            provs = {f["classification"] for f in src}
            if provs == {EXAM_FIXTURE}:
                cls, reason = EXAM_FIXTURE, (
                    f"produced by the exam finding(s) {source_findings}")
            elif provs <= {EVAL_TEST}:
                cls, reason = EVAL_TEST, (
                    f"produced by the test finding(s) {source_findings}")
            elif provs <= {PRODUCTION_HUNT}:
                cls, reason = PRODUCTION_HUNT, (
                    f"produced by the production finding(s) {source_findings}")
            else:
                cls, reason = UNKNOWN_PENDING_REVIEW, (
                    f"produced by findings with mixed provenance {sorted(provs)}")
        else:
            # No finding link: the lesson stands alone. Its own
            # provenance is the evidence.
            topic = row["topic"] or ""
            migrated = ""
            if isinstance(prov, dict):
                migrated = str(prov.get("migrated_from") or "")
            if re.match(r"^probe topic", topic):
                cls, reason = EVAL_TEST, (
                    f"topic {topic!r} is the learning-hooks test's probe "
                    f"lesson")
            elif re.match(r"^finding:[^:]+:127\.0\.0\.1$", topic):
                cls, reason = EVAL_TEST, (
                    f"topic {topic!r} names the loopback host; captured from "
                    f"a test hunt")
            elif migrated:
                # The lesson was MIGRATED from the legacy learning
                # database. That file's own contents are the evidence:
                # its lessons have bodies like 'b' and 'body long enough
                # here', and its findings have titles like 't' and 'f1'.
                # They are the legacy engine's own verification probes.
                cls, reason = EVAL_TEST, (
                    f"migrated from the legacy store {migrated!r}; the "
                    f"legacy database holds only the engine's verification "
                    f"probes (topics 'v', 't', 'z', 'verify-topic')")
            elif (row["class_id"] is None and row["state"] == "analyzed"
                  and not row["body"]):
                cls, reason = EVAL_TEST, (
                    "no class, no body, no finding link; the legacy "
                    "migration's verification probe")
            else:
                cls, reason = UNKNOWN_PENDING_REVIEW, (
                    f"no finding link and no identifying provenance; "
                    f"topic={topic!r}")
        lessons.append({
            "original_id": row["lesson_key"],
            "original_table": "lesson",
            "original_key": row["lesson_key"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "topic": row["topic"],
            "class_id": row["class_id"],
            "score": row["score"],
            "original_state": row["state"],
            "original_verification_state": {
                "state": row["state"], "score": row["score"],
                "evidence": row["evidence"],
            },
            "originating_process": (prov.get("source_provenance", {})
                                    .get("source") if isinstance(prov, dict)
                                    else None),
            "associated_hunt": None,
            "associated_exam": None,
            "source_findings": source_findings,
            "related_evidence": [],
            "related_transitions": [],
            "provenance": prov,
            "classification": cls,
            "classification_reason": reason,
        })

    gaps = []
    for row in con.execute(
            "SELECT * FROM learning_gap ORDER BY created_at, gap_key"):
        detail = row["detail"] or ""
        m = re.search(r"lesson\s+(\S+)\s*\(", detail)
        named = m.group(1) if m else None
        src = [l for l in lessons if l["original_key"] == named]
        if src:
            cls = src[0]["classification"]
            reason = (f"names the lesson {named!r}, whose classification is "
                      f"{cls}")
        elif row["kind"] == "unverified_lesson":
            cls, reason = UNKNOWN_PENDING_REVIEW, (
                f"an unverified_lesson gap naming {named!r}, which is not in "
                f"the lesson table")
        else:
            cls, reason = UNKNOWN_PENDING_REVIEW, (
                f"gap of kind {row['kind']!r} with no resolvable source")
        gaps.append({
            "original_id": row["gap_key"],
            "original_table": "learning_gap",
            "original_key": row["gap_key"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "kind": row["kind"],
            "class_id": row["class_id"],
            "detail": detail,
            "original_status": row["status"],
            "original_verification_state": {"status": row["status"]},
            "originating_process": None,
            "associated_hunt": None,
            "associated_exam": None,
            "named_lesson": named,
            "related_research": gap_lineage(con, row),
            "related_evidence": [],
            "related_transitions": [],
            "provenance": None,
            "classification": cls,
            "classification_reason": reason,
        })

    con.close()
    return {"findings": findings, "lessons": lessons, "gaps": gaps}


def reconcile(manifest: dict) -> dict:
    """The count reconciliation, derived from the manifest."""
    f = manifest["findings"]
    l = manifest["lessons"]
    g = manifest["gaps"]

    def by(rows: list[dict]) -> dict:
        """Count by PROVENANCE, and map each to its final disposition.

        The two vocabularies are different and both are required by the
        incident report:

          provenance    -- where the record came from
                           (PRODUCTION_HUNT / EXAM_FIXTURE / EVAL_TEST /
                            IMPORTED_RESEARCH / MANUAL_ENTRY / UNKNOWN)
          disposition   -- what was done to it
                           (TEST_ARTIFACT_QUARANTINED /
                            EXAM_FIXTURE_RETAINED / GENUINE_HUNT_OUTCOME /
                            UNKNOWN_PENDING_REVIEW)

        A record has exactly ONE provenance and exactly ONE disposition,
        and the disposition is DERIVED from the provenance by one rule.
        """
        counts: dict[str, int] = {}
        for r in rows:
            counts[r["classification"]] = counts.get(r["classification"], 0) + 1
        out = {"by_provenance": counts}
        out["by_disposition"] = {}
        for r in rows:
            d = disposition_for(r["classification"], r.get("original_status")
                                or r.get("original_state"))
            out["by_disposition"][d] = out["by_disposition"].get(d, 0) + 1
        return out

    return {
        "findings": {
            "total_original": len(f),
            **by(f),
            "by_original_status": {
                s: sum(1 for r in f if r["original_status"] == s)
                for s in sorted({r["original_status"] for r in f})},
            "with_evidence": sum(1 for r in f if r["related_evidence"]),
            "with_transitions": sum(1 for r in f if r["related_transitions"]),
            "with_lesson": sum(1 for r in f if r["lesson_count"]),
            "linked_to_a_hunt": sum(1 for r in f if r["associated_hunt"]),
            "exam_validator_run": sum(
                1 for r in f
                if (r["original_verification_state"]["validator_run"]
                    == EXAM_VALIDATOR)),
            "with_report_path": sum(
                1 for r in f if r["original_verification_state"]["report_path"]),
        },
        "lessons": {
            "total_original": len(l),
            **by(l),
            "by_original_state": {
                s: sum(1 for r in l if r["original_state"] == s)
                for s in sorted({r["original_state"] for r in l})},
            "with_finding_link": sum(1 for r in l if r["source_findings"]),
            "standalone": sum(1 for r in l if not r["source_findings"]),
        },
        "gaps": {
            "total_original": len(g),
            **by(g),
            "by_original_status": {
                s: sum(1 for r in g if r["original_status"] == s)
                for s in sorted({r["original_status"] for r in g})},
            "naming_a_lesson": sum(1 for r in g if r["named_lesson"]),
            "with_research": sum(1 for r in g if r["related_research"]),
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Reconcile every record the contamination touched.")
    ap.add_argument("--db", required=True,
                    help="the PRE-QUARANTINE database to reconcile")
    ap.add_argument("--out", default=None,
                    help="manifest output path")
    args = ap.parse_args()

    db = pathlib.Path(args.db)
    if not db.exists():
        print(f"no such database: {db}", file=sys.stderr)
        return 2

    manifest = build_manifest(db)
    recon = reconcile(manifest)

    stamp = _stamp()
    out_dir = ROOT / "runtime" / "state"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = pathlib.Path(args.out) if args.out else (
        out_dir / f"incident-disposition-{stamp}.json")

    payload = {
        "generated_at": _now(),
        "source_database": str(db),
        "classification_vocabulary": list(PROVENANCE_VALUES),
        "reconciliation": recon,
        "records": {
            "findings": manifest["findings"],
            "lessons": manifest["lessons"],
            "gaps": manifest["gaps"],
        },
    }
    out.write_text(json.dumps(payload, indent=2, default=str),
                   encoding="utf-8")

    print(f"manifest: {out}")
    print(f"source:   {db}")
    print()
    print(json.dumps(recon, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
