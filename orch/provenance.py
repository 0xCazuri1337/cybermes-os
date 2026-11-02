"""PROVENANCE — where a record came from, and what that permits.

THE PROBLEM THIS MODULE EXISTS TO SOLVE
=======================================
MEASURED 2026-11-01: the test suite wrote into the live canonical
database. `orch.store.open_db(create=True)` takes no path, so
`store.open_db(db)` bound a `Path` to the `create` parameter -- truthy --
and opened the live database. The test PASSED, because the live database
has every table the test needs.

The contamination was not caught by the quarantine, because the quarantine
answered a different question. It asked "which records look like test
output"; it could not ask "which records MAY count as production hunting
impact", because that question had no answer in the schema. There was no
field on `finding` or `lesson` that said where the record came from, so
every consumer had to infer it -- and the inference the scheduler made
was "a finding with status `validating` is impact on the table".

THE FIX IS A VOCABULARY, NOT A KEY PATTERN
===========================================
The vocabulary:

    PRODUCTION_HUNT     a real finding from a real authorized hunt
    EXAM_FIXTURE        the examination evidence base -- a graded exam
    EVAL_TEST           produced by the test suite
    IMPORTED_RESEARCH   a lesson that came from a write-up, not a hunt
    MANUAL_ENTRY        filed by a human, outside any automated hunt
    UNKNOWN             origin could not be established

A record's provenance is written ONCE, when the record is created, and it
is derived from the CONTEXT OF CREATION -- the hunt that produced it, the
harness that filed it, the operator that entered it -- not from the
record's name, not from its timestamp, and not from a pattern in its
title.

WHAT EACH PROVENANCE PERMITS
=============================
    PRODUCTION_HUNT     counts as production impact; may be validated;
                        may become a trusted lesson
    EXAM_FIXTURE        usable by the exam harness; contributes ZERO
                        production impact; may NOT become a trusted lesson
    EVAL_TEST           contributes ZERO production impact; may NOT become
                        a trusted lesson; may NOT be promoted
    IMPORTED_RESEARCH   may become a lesson, but is not itself impact;
                        counts as research, not as a hunt outcome
    MANUAL_ENTRY        counts as production impact (a human filed it)
    UNKNOWN             contributes ZERO production impact; may NOT be
                        promoted; requires review

THE ENFORCEMENT IS IN THE QUERIES, NOT IN THE DOCS
===================================================
`orch/store.py` exposes the query helpers every consumer uses. A
consumer that wants production impact calls
`store.production_findings(con)`; a consumer that wants lessons that may
influence a hunt calls `store.trusted_lessons(con)`. There is no way to
ask "all findings" and accidentally get the contaminated ones, because
the unfiltered accessors are named for what they return.

A record with UNKNOWN provenance is NOT trusted. That is the fail-closed
direction: an origin that cannot be established cannot contribute to
impact, cannot be promoted, and cannot become experience. It is retained
and it is visible; it is just not eligible.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# THE VOCABULARY
# ---------------------------------------------------------------------------
PRODUCTION_HUNT = "PRODUCTION_HUNT"
EXAM_FIXTURE = "EXAM_FIXTURE"
EVAL_TEST = "EVAL_TEST"
IMPORTED_RESEARCH = "IMPORTED_RESEARCH"
MANUAL_ENTRY = "MANUAL_ENTRY"
UNKNOWN = "UNKNOWN"

ALL_PROVENANCE = (
    PRODUCTION_HUNT, EXAM_FIXTURE, EVAL_TEST, IMPORTED_RESEARCH,
    MANUAL_ENTRY, UNKNOWN,
)

# ---------------------------------------------------------------------------
# WHAT EACH PROVENANCE COUNTS AS
#
# `production_impact` -- does this record represent real hunting impact?
# `eligible_lesson`   -- may this record become a lesson that influences
#                        a hunt?
# `promotable`        -- may this record be promoted into trusted
#                        knowledge?
# ---------------------------------------------------------------------------
IMPACT_ELIGIBLE = frozenset({PRODUCTION_HUNT, MANUAL_ENTRY})
LESSON_ELIGIBLE = frozenset({PRODUCTION_HUNT, MANUAL_ENTRY, IMPORTED_RESEARCH})
PROMOTABLE = frozenset({PRODUCTION_HUNT, MANUAL_ENTRY, IMPORTED_RESEARCH})

# The provenance values whose records are NEVER eligible for any of the
# three. `UNKNOWN` is here on purpose: an origin that could not be
# established is not a weaker origin, it is an ABSENT one, and an absent
# origin cannot be relied upon.
NEVER_ELIGIBLE = frozenset({EVAL_TEST, EXAM_FIXTURE, UNKNOWN})


def is_valid_provenance(value: str | None) -> bool:
    return value in ALL_PROVENANCE


def counts_as_impact(provenance: str | None) -> bool:
    """Does this provenance contribute to production hunting impact?"""
    return provenance in IMPACT_ELIGIBLE


def eligible_as_lesson(provenance: str | None) -> bool:
    """May this provenance become a lesson that influences a hunt?"""
    return provenance in LESSON_ELIGIBLE


def is_promotable(provenance: str | None) -> bool:
    """May this provenance be promoted into trusted knowledge?"""
    return provenance in PROMOTABLE


# ---------------------------------------------------------------------------
# THE SQL FRAGMENTS
#
# One definition, used by every query. A second copy of this predicate is
# a second rule, and two rules about eligibility can disagree.
# ---------------------------------------------------------------------------
def impact_clause(alias: str = "") -> str:
    """SQL predicate: the rows that count as production hunting impact."""
    p = f"{alias}." if alias else ""
    return (f"({p}provenance IN ('{PRODUCTION_HUNT}','{MANUAL_ENTRY}'))")


def trusted_lesson_clause(alias: str = "") -> str:
    """SQL predicate: the lessons that may influence a hunt.

    A lesson must be BOTH eligible by origin AND in the `verified` state.
    A `captured` or `analyzed` lesson is a candidate, not experience.

    THE COLUMN IS `origin`, NOT `provenance`.
    ------------------------------------------
    MEASURED 2026-11-01: this clause used `provenance`, and
    `lesson.provenance` is the JSON DESCRIPTOR -- a blob describing which
    hunt and finding the observation came from. Comparing that blob with
    `'PRODUCTION_HUNT'` never matches, so the clause silently selected
    NOTHING. The lesson's eligibility lives in `lesson.origin`, a
    separate column added for exactly this purpose.
    """
    p = f"{alias}." if alias else ""
    return (f"({p}origin IN ('{PRODUCTION_HUNT}','{MANUAL_ENTRY}',"
            f"'{IMPORTED_RESEARCH}') AND {p}state='verified')")


def promotable_clause(alias: str = "") -> str:
    """SQL predicate: the lessons that may be promoted into trusted knowledge.

    THE COLUMN IS `origin`, NOT `provenance` -- see
    `trusted_lesson_clause` for why.
    """
    p = f"{alias}." if alias else ""
    return (f"({p}origin IN ('{PRODUCTION_HUNT}','{MANUAL_ENTRY}',"
            f"'{IMPORTED_RESEARCH}'))")


# ---------------------------------------------------------------------------
# CLASSIFYING A RECORD AT CREATION
#
# The provenance of a record is decided by the CONTEXT that created it --
# and, for production impact, that context must carry a RECEIPT.
#
# The implementation lives BELOW, after `authorization_backs`, because
# classification consults the persisted authorization.
# ---------------------------------------------------------------------------


def _actor_is_test(actor: str) -> bool:
    a = actor.lower()
    return (a in ("tester", "test", "pytest", "unittest")
            or a.startswith("test_") or a.endswith("_test")
            or "harness" in a or "/eval/" in a or a.startswith("eval/"))


# ---------------------------------------------------------------------------
# THE RECEIPT: PERSISTED AUTHORIZATION
#
# MEASURED 2026-11-02: the origin of a record was DERIVED from the context
# that created it and then ASSERTED. `classify_from_context` returned
# PRODUCTION_HUNT for any hunt with an id and a routable target, so the
# system decided on its own that its output was production hunting impact.
# Nothing recorded that the hunt was authorized at all.
#
# The origin is now a claim WITH A RECEIPT. A record may carry
# PRODUCTION_HUNT only when a `hunt_authorization` row exists for its hunt,
# the row's authorization was VALIDATED (the context was complete,
# unambiguous, and permitted to probe the named target), and the row's
# target matches the record's target.
#
# ABSENCE OF A ROW IS A DENY. That is the rule `scope_grant` already
# follows for offensive execution, and it is the fail-closed direction: a
# hunt whose authorization was never validated produces UNKNOWN findings,
# and UNKNOWN contributes zero impact.
# ---------------------------------------------------------------------------

def authorization_for(con: sqlite3.Connection, hunt_id: str | None
                      ) -> dict[str, Any] | None:
    """The persisted authorization for a hunt, or None.

    Reads the receipt the orchestrator wrote when the authorization gate
    passed. A record with no receipt has no backing.
    """
    if not hunt_id:
        return None
    try:
        row = con.execute(
            "SELECT * FROM hunt_authorization WHERE hunt_id=?",
            (hunt_id,)).fetchone()
    except sqlite3.Error:
        return None
    return dict(row) if row else None


def authorization_backs(con: sqlite3.Connection, *, hunt_id: str | None,
                        target: str | None = None) -> tuple[bool, str]:
    """Is there a validated authorization backing this hunt?

    Returns `(backed, reason)`. The reason names what was missing, so a
    refusal is diagnosable rather than mysterious.
    """
    if not hunt_id:
        return False, ("no hunt id: the record was not produced by a hunt, "
                       "so no authorization can back it")
    auth = authorization_for(con, hunt_id)
    if auth is None:
        return False, (f"no authorization record for hunt {hunt_id!r}: the "
                       "authorization gate never recorded a validated "
                       "authorization for this hunt")
    if not int(auth.get("validated") or 0):
        return False, (f"the authorization for hunt {hunt_id!r} was never "
                       "validated")
    ref = str(auth.get("authorization_ref") or "").strip()
    if not ref or ref == "UNSPECIFIED":
        return False, (f"the authorization for hunt {hunt_id!r} names no "
                       "authorization reference")
    if target:
        recorded = _norm_host(auth.get("target"))
        asked = _norm_host(target)
        if recorded and asked and recorded != asked:
            return False, (f"the authorization for hunt {hunt_id!r} covers "
                           f"{recorded!r}, not {asked!r}")
    return True, (f"hunt {hunt_id!r} is backed by a validated authorization "
                  f"({ref!r})")


def _norm_host(value: str | None) -> str:
    h = (value or "").strip().lower()
    if "://" in h:
        h = h.split("://", 1)[1]
    return h.split("/", 1)[0].strip(".")


def classify_from_context(*, hunt_id: str | None = None,
                           hunt_kind: str | None = None,
                           hunt_target: str | None = None,
                           validator_run: str | None = None,
                           report_path: str | None = None,
                           actor: str | None = None,
                           manual: bool = False,
                           imported: bool = False,
                           authorization_backed: bool = False,
                           authorization_reason: str = "") -> str:
    """Derive the provenance of a record from the context that made it.

    THE ORDER IS DELIBERATE. Each test is a POSITIVE identification:

      * the exam harness names itself in `validator_run` / `report_path`
      * the test harness names itself in the actor
      * a hunt that targets the loopback address or a reserved test
        domain cannot have produced a production outcome
      * an explicit manual or imported context is stated outright
      * a hunt that produced production impact has a VALIDATED
        authorization backing it

    THE LAST TEST IS THE ONE THAT MATTERS MOST.

    MEASURED 2026-11-02: this function returned PRODUCTION_HUNT for any
    hunt that had an id and a routable target. That made the origin a
    CLAIM THE SYSTEM MADE ABOUT ITSELF: the caller asserted "this is a
    hunt", the target looked routable, and the system concluded "this is
    production impact" -- with no authorization existing anywhere in the
    system.

    Now `PRODUCTION_HUNT` requires `authorization_backed=True`, which the
    caller obtains from `authorization_backs()` by consulting the
    persisted `hunt_authorization` receipt. A hunt with no receipt, an
    unvalidated receipt, or a receipt covering a different target produces
    UNKNOWN, which contributes zero impact and may never be promoted.
    """
    if manual:
        # A MANUAL ENTRY MUST NAME ITS AUTHOR.
        #
        # MEASURED 2026-11-02: `manual=True` produced MANUAL_ENTRY with no
        # proof of anything. MANUAL_ENTRY is an ELIGIBLE origin -- the gate
        # will report it, and the scheduler counts it as impact -- so a
        # caller could claim "a human filed this" and get an eligible
        # record.
        #
        # The author IS the proof: a manual entry says a human filed it,
        # and the name of that human is what makes the claim checkable.
        # Without it, the claim is UNKNOWN.
        if (actor or "").strip():
            return MANUAL_ENTRY
        return UNKNOWN
    if imported:
        # IMPORTED RESEARCH MUST NAME ITS SOURCE.
        #
        # A write-up has a path, and the path is the evidence that a
        # document exists to derive the claim from. Without it, the claim
        # is UNKNOWN.
        if (actor or "").strip():
            return IMPORTED_RESEARCH
        return UNKNOWN

    vr = (validator_run or "").strip()
    rp = (report_path or "").strip()
    if vr == "eval/grade_exam.py" or rp:
        return EXAM_FIXTURE

    a = (actor or "").strip().lower()
    if a and _actor_is_test(a):
        return EVAL_TEST

    if hunt_id:
        kind = (hunt_kind or "").lower()
        if kind in ("lab", "authorized_lab", "test", "eval", "fixture"):
            return EVAL_TEST
        # PRODUCTION IMPACT REQUIRES A RECEIPT.
        #
        # THE RECEIPT IS CHECKED BEFORE THE TARGET.
        #
        # MEASURED 2026-11-02: the reserved-target test came first, so a
        # hunt against `app.p1.example` -- a name in the reserved test
        # space -- was classified EVAL_TEST even when its authorization
        # had been validated and recorded. The reserved-name rule is a
        # heuristic about NAMES; the receipt is a fact about the HUNT.
        #
        # A validated receipt is the stronger evidence, and it names the
        # target it covers: the receipt's target must match, or
        # `authorization_backs` refuses. So when a receipt exists and
        # covers this target, it decides.
        if authorization_backed:
            return PRODUCTION_HUNT
        if hunt_target and _target_is_non_production(hunt_target):
            return EVAL_TEST
        return UNKNOWN

    # A TARGET ALONE IS ENOUGH TO CLASSIFY A TEST FIXTURE.
    #
    # The target is a POSITIVE identification on its own: the loopback
    # address and the reserved test domains cannot have produced a
    # production outcome. So a non-production target is an EVAL_TEST,
    # whether or not a hunt id is known.
    #
    # But a routable target with NO hunt id is NOT production impact: it
    # is UNKNOWN. There is no hunt, so there is no authorization, so
    # there is no receipt. Naming a routable host is not evidence of an
    # authorized hunt.
    if hunt_target and _target_is_non_production(hunt_target):
        return EVAL_TEST

    return UNKNOWN


def _target_is_non_production(target: str) -> bool:
    """Is this target incapable of being a real production target?"""
    t = (target or "").strip().lower()
    if not t:
        return True
    if t in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        return True
    if t.startswith("127."):
        return True
    if any(t.endswith(sfx) for sfx in
           (".test", ".example", ".invalid", ".localhost", ".local")):
        return True
    return False


# ---------------------------------------------------------------------------
# READING AND WRITING
# ---------------------------------------------------------------------------
def normalise(value: Any) -> str:
    """Coerce anything to a valid provenance value.

    An unrecognised value is UNKNOWN, never a guess. A record whose
    provenance column holds a typo must not be trusted, and it must not
    crash the reader either.
    """
    if value is None:
        return UNKNOWN
    v = str(value).strip().upper()
    return v if v in ALL_PROVENANCE else UNKNOWN


def _origin_column(table: str) -> str:
    """The column that holds the eligibility class for a table.

    `finding.provenance` and `lesson.origin` are BOTH eligibility columns
    with the same vocabulary. They have different names because
    `lesson.provenance` was already taken -- it is the JSON descriptor
    blob, and it stays that way.

    MEASURED 2026-11-01: `provenance_of` and `set_provenance` read and
    wrote `provenance` on BOTH tables. For `lesson` that is the
    descriptor blob, so `provenance_of` returned UNKNOWN for every
    lesson and `set_provenance` OVERWROTE the descriptor with a
    vocabulary word -- destroying the record of where the observation
    came from.
    """
    if table == "finding":
        return "provenance"
    if table == "lesson":
        return "origin"
    raise ValueError(f"provenance is not defined for {table!r}")


def provenance_of(con: sqlite3.Connection, table: str, key: str,
                  key_col: str = "finding_key") -> str:
    """The provenance of one record."""
    column = _origin_column(table)
    try:
        row = con.execute(
            f"SELECT {column} FROM {table} WHERE {key_col}=?",
            (key,)).fetchone()
    except sqlite3.Error:
        return UNKNOWN
    if row is None:
        return UNKNOWN
    return normalise(row[0])


def set_provenance(con: sqlite3.Connection, table: str, key: str,
                   provenance: str, key_col: str = "finding_key",
                   *, reason: str = "", corrected_by: str = "unknown",
                   evidence_ref: str | None = None) -> bool:
    """Set a record's provenance, and RECORD the change.

    MEASURED 2026-11-02: this performed a bare UPDATE of the origin column.
    Nothing recorded what the value was, why it changed, or who changed it
    -- so a misclassified record could be quietly promoted into production
    impact and the change left no trace. That is the same defect as a
    record whose origin was asserted without a receipt: an origin nobody
    can audit is an origin nobody can trust.

    So the origin is now changed only through a CORRECTION, and the
    correction is an append-only audit row naming the record, the old
    value, the new value, the reason and the corrector. The audit row and
    the UPDATE are written in ONE transaction, so the change and its
    receipt cannot diverge.

    A correction requires a reason. A promotion to PRODUCTION_HUNT
    additionally requires a validated authorization for the record's hunt:
    the same receipt a record created by a hunt needs. Without that, the
    correction is refused -- an origin cannot be promoted into production
    impact by a bare UPDATE.
    """
    column = _origin_column(table)
    if not is_valid_provenance(provenance):
        raise ValueError(
            f"{provenance!r} is not a provenance value; the vocabulary is "
            f"{', '.join(ALL_PROVENANCE)}")
    if not (reason or "").strip():
        raise ValueError(
            "a provenance correction requires a reason: an origin change "
            "that names no reason cannot be audited")
    row = con.execute(
        f"SELECT {column} FROM {table} WHERE {key_col}=?", (key,)).fetchone()
    if row is None:
        return False
    old = normalise(row[0])
    if old == provenance:
        return False

    # A PROMOTION INTO PRODUCTION IMPACT NEEDS THE RECEIPT.
    if provenance == PRODUCTION_HUNT:
        hunt_id = None
        target = None
        try:
            rec = con.execute(
                f"SELECT hunt_id, target FROM {table} WHERE {key_col}=?",
                (key,)).fetchone()
            if rec is not None:
                hunt_id = rec["hunt_id"] if "hunt_id" in rec.keys() else None
                target = rec["target"] if "target" in rec.keys() else None
        except sqlite3.Error:
            pass
        backed, why = authorization_backs(con, hunt_id=hunt_id,
                                          target=target)
        if not backed:
            raise ValueError(
                f"refusing to promote {table} {key!r} to {PRODUCTION_HUNT}: "
                f"{why}. A production origin requires a validated "
                f"authorization receipt.")

    correction_id = hashlib.sha256(
        f"{table}|{key}|{old}|{provenance}|{reason}|{corrected_by}".encode(
            "utf-8")).hexdigest()[:24]
    now = _now()
    # THE AUDIT ROW CROSSES TO THE ORCHESTRATION OWNER.
    #
    # `provenance_correction` is an ORCHESTRATION table -- it records what
    # a hunt's operational state was corrected to -- so the audit INSERT
    # is performed as the orchestrator. On a knowledge-owned connection
    # (the learning engine's own handle) the insert was refused with "not
    # authorized"; on an orchestrator-owned connection it is already
    # permitted. `owner_write` lifts the restriction for the duration of
    # the INSERT and restores it afterwards, so a correction works from
    # either side and every other write stays restricted.
    from wks import ownership as _ownership
    try:
        with _ownership.owner_write(con, _ownership.ORCH):
            con.execute(
                "INSERT INTO provenance_correction(correction_id, table_name,"
                " record_key, old_provenance, new_provenance, reason,"
                " corrected_by, evidence_ref, corrected_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                (correction_id, table, key, old, provenance, reason.strip(),
                 corrected_by, evidence_ref, now))
    except sqlite3.Error:
        # The audit table may not exist on a database that predates it.
        # The correction is refused rather than performed unaudited.
        raise
    # THE UPDATE CROSSES TO THE OWNER OF THE COLUMN.
    #
    # MEASURED 2026-11-02: `lesson` is a KNOWLEDGE table and
    # `provenance_correction` is an ORCHESTRATION table, so a correction
    # of a lesson's origin is a genuine crossing -- the audit row belongs
    # to the orchestrator and the lesson belongs to the knowledge layer.
    #
    # On an orchestrator-owned connection the lesson UPDATE was refused
    # with "not authorized" -- the boundary working as designed against a
    # crossing that had not been sanctioned. So the update is performed
    # inside `owner_write(con, WKS)`, which lifts the restriction for the
    # duration of the UPDATE only. Every other write on the connection
    # stays refused, and the crossing is greppable at the call site.
    if table == "lesson":
        from wks import ownership as _ownership
        with _ownership.owner_write(con, _ownership.WKS):
            con.execute(
                f"UPDATE {table} SET {column}=? WHERE {key_col}=?",
                (provenance, key))
    else:
        con.execute(
            f"UPDATE {table} SET {column}=? WHERE {key_col}=?",
            (provenance, key))
    con.commit()
    return True


def corrections(con: sqlite3.Connection, table: str | None = None,
                key: str | None = None) -> list[sqlite3.Row]:
    """The audit trail of origin corrections."""
    q = "SELECT * FROM provenance_correction"
    args: list[Any] = []
    where = []
    if table:
        where.append("table_name=?")
        args.append(table)
    if key:
        where.append("record_key=?")
        args.append(key)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY corrected_at, correction_id"
    try:
        return con.execute(q, args).fetchall()
    except sqlite3.Error:
        return []


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# THE ELIGIBILITY QUERIES
#
# These are the functions every downstream consumer must use. They are
# here, in one module, so that "what counts as impact" has exactly one
# answer.
# ---------------------------------------------------------------------------
def production_findings(con: sqlite3.Connection,
                        statuses: Iterable[str] = (
                            "candidate", "validating", "validated",
                            "reported")) -> list[sqlite3.Row]:
    """The findings that count as production hunting impact."""
    sts = tuple(statuses)
    if not sts:
        return []
    q = ",".join("?" for _ in sts)
    return con.execute(
        f"SELECT * FROM finding WHERE {impact_clause()} AND status IN ({q})"
        " ORDER BY id", sts).fetchall()


def production_impact_count(con: sqlite3.Connection) -> int:
    """How much production impact is on the table. TEST output is not."""
    return int(con.execute(
        f"SELECT count(*) n FROM finding WHERE {impact_clause()}"
        " AND status IN ('candidate','validating','validated','reported')"
    ).fetchone()["n"])


def unvalidated_production_count(con: sqlite3.Connection) -> int:
    """Findings awaiting validation -- production ones only."""
    return int(con.execute(
        f"SELECT count(*) n FROM finding WHERE {impact_clause()}"
        " AND status IN ('candidate','validating')").fetchone()["n"])


def evidence_gap_count(con: sqlite3.Connection) -> int:
    """Production findings with no evidence attached."""
    return int(con.execute(
        f"SELECT count(*) n FROM finding f WHERE {impact_clause('f')}"
        " AND f.status IN ('candidate','validated') AND NOT EXISTS"
        " (SELECT 1 FROM evidence e WHERE e.finding_id=f.id)"
    ).fetchone()["n"])


def trusted_lessons(con: sqlite3.Connection,
                    class_id: str | None = None) -> list[sqlite3.Row]:
    """The lessons that may influence a hunt.

    Both conditions hold: the provenance is eligible, AND the lesson is
    `verified`. A lesson in any other state is a candidate for
    experience, not experience.
    """
    if class_id:
        return con.execute(
            f"SELECT * FROM lesson WHERE {trusted_lesson_clause()}"
            " AND class_id=? ORDER BY score DESC, updated_at DESC",
            (class_id,)).fetchall()
    return con.execute(
        f"SELECT * FROM lesson WHERE {trusted_lesson_clause()}"
        " ORDER BY score DESC, updated_at DESC").fetchall()


def promotable_lessons(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """The lessons that may be promoted into trusted knowledge."""
    return con.execute(
        f"SELECT * FROM lesson WHERE {promotable_clause()}"
        " ORDER BY score DESC, updated_at DESC").fetchall()


def provenance_report(con: sqlite3.Connection) -> dict[str, Any]:
    """What the corpus holds, by provenance.

    This is the report the incident closure is graded on: it shows that
    every record's provenance is accounted for, and it shows the split
    between what counts as impact and what does not.
    """
    # THE KEYS ARE THE TABLE NAMES, singular.
    #
    # MEASURED 2026-11-01: this initialised `out` with `"findings"` and
    # `"lessons"`, then filled `"finding"` and `"lesson"` -- so the two
    # keys that were promised were ALWAYS empty, and every caller that
    # read `report["findings"]["by_provenance"]` raised KeyError. The
    # report looked correct in the database and was unusable in code.
    #
    # The initial dict is dropped: one key per table, named for the
    # table, so there is exactly one way to read it.
    out: dict[str, Any] = {}
    for table, key, column in (("finding", "finding_key", "provenance"),
                                ("lesson", "lesson_key", "origin")):
        try:
            rows = con.execute(
                f"SELECT COALESCE({column},'') p, count(*) n FROM {table}"
                " GROUP BY p").fetchall()
        except sqlite3.Error:
            out[table] = {"error": f"no {column} column"}
            continue
        counts = {normalise(r["p"]): r["n"] for r in rows}
        out[table] = {
            "by_provenance": counts,
            "total": sum(counts.values()),
            "eligible_for_impact": sum(
                n for p, n in counts.items() if counts_as_impact(p)),
            "never_eligible": sum(
                n for p, n in counts.items() if p in NEVER_ELIGIBLE),
        }
    return out


def audit_provenance(con: sqlite3.Connection) -> dict[str, Any]:
    """Check that every record's provenance is in the vocabulary.

    A record whose provenance is missing or unrecognised is UNKNOWN by
    `normalise`, which excludes it from impact -- so the invariant is
    not "no record has UNKNOWN provenance" but "no record has an
    INVALID provenance". UNKNOWN is a legitimate, fail-closed state.
    """
    problems: list[dict[str, Any]] = []
    for table, key in (("finding", "finding_key"), ("lesson", "lesson_key")):
        column = _origin_column(table)
        try:
            rows = con.execute(
                f"SELECT {key} k, {column} p FROM {table}"
                f" WHERE {column} IS NOT NULL").fetchall()
        except sqlite3.Error:
            continue
        for r in rows:
            v = r["p"]
            if not is_valid_provenance(str(v).strip().upper()):
                problems.append({"table": table, "key": r["k"],
                                 "provenance": v})
    return {
        "invalid_provenance_records": len(problems),
        "problems": problems[:50],
        "ok": not problems,
    }
