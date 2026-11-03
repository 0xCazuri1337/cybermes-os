"""Cyber OS learning engine — the five adaptive-memory hooks.

Where this writes
-----------------
The CANONICAL database, `db/wks.db`, and nothing else.

MEASURED DEFECT (the reason this module was rewritten): the engine kept its
own `learning_engine/memory/learning.db`. That file was a second source of
truth with its own `lessons` and `findings` tables, its own connection code,
and no reader outside the package. The canonical corpus — `db/wks.db` — had
no learning tables at all, so "the learning loop improves the corpus" had no
mechanism, and the hooks named in
`skills/learning-engine-integration.md` (`before_recon`, `during_testing`,
`after_finding`, `after_triage`, `before_summary`) did not exist in any
callable form. A grep for them across `orch/`, `wks/`, `eval/`, `scripts/`
and `tools/` returned nothing: five documented integration points, zero
implementations.

The old `learning.db` is retained as a LEGACY artifact (nothing is deleted —
the mission constraint) and its contents are migrated ONCE, transactionally,
into the canonical database. It is not opened for writing again.

The five hooks
--------------
    capture_hook   record an observed outcome/lesson
    analyze_hook   identify what is missing from what was captured
    research_hook  turn a gap into a concrete research task
    verify_hook    record verification evidence for a lesson
    update_hook    refresh the canonical projection after a verified change

Every hook is idempotent: the same input twice produces the same rows, not
two. Every hook refuses to promote anything on its own authority — a lesson
only becomes `verified` when evidence is attached, and only an item that
passed the WKS quality gate is ever written to the corpus.

Every hook takes an explicit `con` so a caller can point it at a scratch
database in a test. The default is the canonical one.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from wks import store as wks_store  # noqa: E402


# ---------------------------------------------------------------------------
# schema
# ---------------------------------------------------------------------------

SCHEMA = """
-- What was learned, and how strongly it is trusted.
CREATE TABLE IF NOT EXISTS lesson (
  lesson_key  TEXT PRIMARY KEY,      -- deterministic: hash of topic+body
  topic       TEXT NOT NULL,
  body        TEXT NOT NULL,
  class_id    TEXT,
  score       REAL DEFAULT 0.0,
  state       TEXT NOT NULL DEFAULT 'captured',
              -- captured | analyzed | research_proposed | verified | rejected
  provenance  TEXT,                   -- JSON: where the observation came from
              -- `provenance` DESCRIBES the observation: which hunt, which
              -- finding, what evidence. It does NOT say whether the
              -- lesson may be trusted.
  origin      TEXT NOT NULL DEFAULT 'UNKNOWN',
              -- MEASURED 2026-11-01: the lesson table had no field that
              -- said whether a lesson was PRODUCTION, an EXAM FIXTURE, an
              -- EVAL TEST, IMPORTED RESEARCH, a MANUAL ENTRY, or UNKNOWN.
              -- `before_recon` and `before_summary` therefore returned
              -- every `verified` lesson regardless of origin -- so a
              -- lesson derived from a test run could steer the next hunt.
              --
              -- `origin` is the ELIGIBILITY field; `provenance` is the
              -- DESCRIPTION. They are not redundant: a lesson can be
              -- fully described (hunt id, finding key, evidence) and
              -- still be ineligible.
              --
              -- PRODUCTION_HUNT|EXAM_FIXTURE|EVAL_TEST|IMPORTED_RESEARCH|
              -- MANUAL_ENTRY|UNKNOWN
              --
              -- The vocabulary and the rules live in `orch/provenance.py`.
  evidence    TEXT,                   -- JSON: what verifies it
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_lesson_state ON lesson(state);
CREATE INDEX IF NOT EXISTS ix_lesson_class ON lesson(class_id);
-- The index on `lesson(origin)` is NOT created here.
--
-- MEASURED 2026-11-01: it was, and the script aborted with "no such
-- column: origin" on the live database, whose `lesson` table predated
-- the column -- because `CREATE TABLE IF NOT EXISTS` does not add a
-- column to a table that already exists. The index belongs in
-- `ensure_schema`, after the conditional ALTER, which is the only code
-- that knows whether the column is present.

-- A gap the analysis found: something the corpus does not know yet.
CREATE TABLE IF NOT EXISTS learning_gap (
  gap_key     TEXT PRIMARY KEY,
  class_id    TEXT,
  kind        TEXT NOT NULL,         -- unresearched_class | thin_coverage |
                                     -- unverified_lesson | missing_fp_rule
  detail      TEXT NOT NULL,
  status      TEXT NOT NULL DEFAULT 'open',   -- open | proposed | closed
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_gap_status ON learning_gap(status);

-- A concrete research task proposed FROM a gap.
CREATE TABLE IF NOT EXISTS learning_research (
  research_key TEXT PRIMARY KEY,
  gap_key      TEXT NOT NULL,
  class_id     TEXT,
  objective    TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'proposed',
  created_at   TEXT NOT NULL,
  updated_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_research_gap ON learning_research(gap_key);

-- Outcomes fed back by a program triage (accepted / duplicate / FP / ...).
CREATE TABLE IF NOT EXISTS lesson_feedback (
  feedback_key TEXT PRIMARY KEY,
  lesson_key   TEXT NOT NULL,
  feedback_type TEXT NOT NULL,
  notes        TEXT,
  provenance   TEXT,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_feedback_lesson ON lesson_feedback(lesson_key);

-- Lessons harvested from a write-up, routed to their destination class.
CREATE TABLE IF NOT EXISTS writeup_lesson (
  wl_key      TEXT PRIMARY KEY,
  source_path TEXT NOT NULL,
  class_id    TEXT,
  lesson_key  TEXT,
  kind        TEXT NOT NULL,         -- methodology | pattern | lesson | target
  summary     TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_wl_class ON writeup_lesson(class_id);

-- THE LESSON'S ORIGIN IS IMMUTABLE AT THE DATABASE LEVEL.
--
-- MEASURED 2026-11-02: `orch.provenance.set_provenance` was the only
-- sanctioned correction path, but nothing stopped a raw
-- `UPDATE lesson SET origin='PRODUCTION_HUNT'`. The audit trail recorded
-- the changes that went through the function; it did not prevent the ones
-- that did not -- and the lesson's origin is what decides whether it can
-- steer the next hunt.
--
-- The trigger permits the change ONLY when a matching
-- `provenance_correction` audit row exists, which `set_provenance` writes
-- in the same transaction, before the UPDATE. Without that row, SQLite
-- refuses the change itself.
--
-- The trigger is installed here rather than in `orch/schema.sql` because
-- `lesson` is a KNOWLEDGE table: this module owns it.
CREATE TRIGGER IF NOT EXISTS trg_lesson_origin_immutable
BEFORE UPDATE OF origin ON lesson
FOR EACH ROW
WHEN NEW.origin IS NOT OLD.origin
 AND NOT EXISTS (
   SELECT 1 FROM provenance_correction c
   WHERE c.table_name='lesson'
     AND c.record_key=OLD.lesson_key
     AND c.old_provenance=OLD.origin
     AND c.new_provenance=NEW.origin
 )
BEGIN
  SELECT RAISE(ABORT, 'the origin of a lesson may only change through a recorded provenance_correction: use orch.provenance.set_provenance');
END;
"""

LEGACY_DB = ROOT / "learning_engine" / "memory" / "learning.db"

# Why a legacy `findings` row is retained but not live.
#
# MEASURED 2026-10-31: the canonical `finding` table is the hunt's record
# of a finding, and every live finding must be backed by an `evidence` row.
# The legacy `learning.db` `findings` table had no evidence column at all --
# only a title, a class, a severity and a status -- so its rows cannot
# satisfy that invariant. Migrating them as live findings created seven
# findings with no proof behind them, and
# `eval/test_wks_integrity_repair.py` caught it (evidence=15, finding=22).
#
# The rows are RETAINED in `quarantine` with this verdict. Nothing is
# deleted.
LEGACY_FINDING_VERDICT = (
    "legacy finding record: the retired `learning.db` `findings` table "
    "carried no evidence, and every live finding in the canonical store "
    "must be backed by an `evidence` row. The row is retained verbatim in "
    "quarantine as history; it is not a live finding because there is "
    "nothing behind it.")


def _now() -> str:
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")


def ensure_schema(con: sqlite3.Connection) -> sqlite3.Connection:
    """Apply the learning schema, and migrate a legacy lesson table.

    MEASURED 2026-11-01: `CREATE TABLE IF NOT EXISTS` does not add a
    column to a table that already exists, so the live `lesson` table --
    created before `origin` existed -- kept its old shape. The
    `CREATE INDEX ix_lesson_origin` in SCHEMA then failed with "no such
    column: origin" and took the whole schema script with it.

    So the index is created only when the column is present, and the
    column is added here when it is absent. The learning engine owns the
    `lesson` table, so this is its migration to run.

    `orch.store._migrate_provenance` performs the same addition on the
    orchestrator's connection. Both are idempotent, so whichever runs
    first wins and the other finds the column already present.

    MEASURED 2026-11-02: the ORDER was still wrong. `executescript(SCHEMA)`
    ran FIRST, and the schema declares `CREATE INDEX ix_lesson_class ON
    lesson(class_id)`. A legacy `lesson` table without `class_id` -- which
    is exactly what a pre-taxonomy database has -- made that index
    statement fail with "no such column: class_id", and the failure
    aborted the WHOLE script before the migration below could add the
    column.
    #
    # So the MIGRATION runs before the SCHEMA. The columns the legacy
    # table is missing are added first, and only then is the script
    # applied -- by which time every index it declares has its column.
    # The script's remaining statements are all `IF NOT EXISTS`, so
    # running it after the ALTERs is still idempotent.
    """
    _migrate_legacy_lesson(con)
    con.executescript(SCHEMA)
    cols = {r["name"] for r in con.execute("PRAGMA table_info(lesson)")}
    if cols and "origin" not in cols:
        con.execute(
            "ALTER TABLE lesson ADD COLUMN origin TEXT NOT NULL"
            " DEFAULT 'UNKNOWN'")
    if "origin" in cols or cols:
        con.execute(
            "CREATE INDEX IF NOT EXISTS ix_lesson_origin ON lesson(origin)")
    con.commit()
    return con


# The columns a pre-taxonomy `lesson` table may be missing.
#
# MEASURED 2026-11-02: `class_id` was one of them, and the schema's
# `CREATE INDEX ix_lesson_class ON lesson(class_id)` failed on the legacy
# shape and took the whole script with it. `evidence` and `updated_at` are
# in the same position: the schema declares indexes and the capture path
# writes them, so a table without them is a table the current code cannot
# use.
_LEGACY_LESSON_COLUMNS: tuple[tuple[str, str], ...] = (
    ("class_id", "TEXT"),
    ("evidence", "TEXT"),
    ("updated_at", "TEXT"),
)


def _migrate_legacy_lesson(con: sqlite3.Connection) -> None:
    """Add the columns a legacy `lesson` table is missing.

    Idempotent, and a no-op on a database whose `lesson` table is already
    current -- which is every fresh install.
    """
    try:
        cols = {r["name"] for r in con.execute("PRAGMA table_info(lesson)")}
    except sqlite3.Error:
        return
    if not cols:
        # No `lesson` table yet: `executescript` will create it whole.
        return
    for name, decl in _LEGACY_LESSON_COLUMNS:
        if name in cols:
            continue
        try:
            con.execute(f"ALTER TABLE lesson ADD COLUMN {name} {decl}")
        except sqlite3.Error:
            # A concurrent migration may have added it first.
            pass


def open_canonical(create: bool = True) -> sqlite3.Connection:
    """The canonical database handle, with the learning schema applied."""
    con = wks_store.open_db(create=create)
    return ensure_schema(con)


def _key(*parts: str) -> str:
    raw = "␟".join(p or "" for p in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


# ---------------------------------------------------------------------------
# 1. capture
# ---------------------------------------------------------------------------

def capture_hook(con: sqlite3.Connection, *, topic: str, body: str,
                 class_id: str | None = None, score: float = 0.0,
                 provenance: dict[str, Any] | None = None,
                 origin: str | None = None,
                 hunt_id: str | None = None,
                 authorization_ref: str | None = None) -> dict[str, Any]:
    """Record an observed outcome as a lesson. Idempotent.

    The lesson starts in state `captured`. It is NOT verified, and it is NOT
    in the corpus — it is a claim that something was learned, recorded so the
    other hooks can reason about it.

    `origin` says WHERE THE OBSERVATION CAME FROM, and therefore whether
    the lesson may ever become hunting experience.

    MEASURED 2026-11-01: the lesson table had no such field, so a lesson
    captured from a test run was indistinguishable from one captured from
    a real hunt -- and `before_recon` returned every `verified` lesson to the
    next hunt regardless. The origin vocabulary lives in
    `orch/provenance.py`; the default is `UNKNOWN`, which is the
    fail-closed direction.

    A PRODUCTION ORIGIN REQUIRES A RECEIPT.
    --------------------------------------
    MEASURED 2026-11-02: `origin` was a plain argument, so any caller
    could assert `PRODUCTION_HUNT` and create a lesson that -- once
    verified -- became hunting experience for the next hunt. That was the
    second self-promotion path, and it was the worse of the two: the
    orchestrator's finding origin was derived (wrongly) rather than
    asserted, but here the origin was ASSERTED outright.

    So `PRODUCTION_HUNT` is now accepted only when the caller supplies a
    `hunt_id` AND an `authorization_ref` that MATCH a validated
    `hunt_authorization` row in the canonical database. The learning engine
    does not import the orchestrator -- it reads the receipt by table name,
    the same deliberate duplication the origin vocabulary already uses.
    A claim without a matching receipt is DOWNGRADED to UNKNOWN, and the
    downgrade is reported rather than silent.
    """
    topic = (topic or "").strip()
    body = (body or "").strip()
    if not topic or not body:
        return {"ok": False, "reason": "a lesson needs a topic and a body",
                "state": None, "lesson_key": None}
    # THE SCHEMA IS ENSURED HERE.
    #
    # MEASURED 2026-11-02: every sibling hook calls `ensure_schema(con)`
    # and this one did not, so `capture_hook` raised "no such table:
    # lesson" on any database where the learning schema had not already
    # been applied -- which is every fresh database. The capture path was
    # broken at its first step on a clean install, and the tests missed it
    # because they all opened the canonical database through
    # `open_canonical`, which applies the schema for them.
    ensure_schema(con)
    origin_value = _normalise_origin(origin)
    origin_downgraded = False
    if origin_value == "PRODUCTION_HUNT":
        ok, why = _production_origin_backed(
            con, hunt_id=hunt_id, authorization_ref=authorization_ref)
        if not ok:
            origin_value = "UNKNOWN"
            origin_downgraded = True
    elif origin_value == "IMPORTED_RESEARCH":
        # IMPORTED RESEARCH MUST NAME ITS SOURCE.
        #
        # MEASURED 2026-11-02: PRODUCTION_HUNT required a receipt, but
        # IMPORTED_RESEARCH -- an eligible origin that `before_recon` and
        # `_prior_for_signal` treat as intelligence -- was accepted as a
        # bare assertion. So the self-declaration defect had a second
        # door in it: a caller could claim "this is published research"
        # and get an eligible lesson.
        #
        # The source must be NAMED: a write-up has a path, and the path is
        # the evidence that a document exists to derive the claim from.
        # The write-up pipeline records it in the descriptor.
        descriptor_src = (provenance or {}).get("path") \
            or (provenance or {}).get("source_path")
        if not descriptor_src:
            origin_value = "UNKNOWN"
            origin_downgraded = True
    key = _key(topic, body)
    now = _now()
    # THE DESCRIPTOR RECORDS THE RECEIPT IT RELIES ON.
    #
    # MEASURED 2026-11-02: the lesson's descriptor blob did not name the
    # hunt, so `verify_hook` -- which now demands the receipt rather than
    # trusting the origin column -- had no way to find it. The receipt is
    # recorded in the descriptor at capture time, where it is known, and
    # the hunt id travels with it.
    descriptor = dict(provenance or {})
    if hunt_id and "hunt_id" not in descriptor:
        descriptor["hunt_id"] = hunt_id
    if authorization_ref and "authorization_ref" not in descriptor:
        descriptor["authorization_ref"] = authorization_ref
    existing = con.execute("SELECT lesson_key, state FROM lesson WHERE lesson_key=?",
                           (key,)).fetchone()
    if existing:
        # Idempotent: a repeat capture does not create a second row and does
        # not reset a lesson that has already advanced.
        return {"ok": True, "lesson_key": key, "state": existing["state"],
                "created": False, "idempotent": True, "origin": origin_value,
                "origin_downgraded": origin_downgraded}
    con.execute(
        "INSERT INTO lesson(lesson_key, topic, body, class_id, score, state,"
        " provenance, origin, evidence, created_at, updated_at)"
        " VALUES (?,?,?,?,?,'captured',?,?,NULL,?,?)",
        (key, topic, body, class_id, float(score or 0.0),
         json.dumps(descriptor, default=str), origin_value, now, now))
    con.commit()
    return {"ok": True, "lesson_key": key, "state": "captured",
            "created": True, "idempotent": False, "origin": origin_value,
            "origin_downgraded": origin_downgraded}


def _production_origin_backed(con: sqlite3.Connection, *,
                               hunt_id: str | None,
                               authorization_ref: str | None) -> tuple[bool, str]:
    """Is there a validated authorization receipt backing this lesson?

    The learning engine does NOT import the orchestrator -- they are two
    owners of one database, and an owner must not depend on the other. So
    the receipt is read BY TABLE NAME, the same deliberate duplication the
    origin vocabulary already uses.
    """
    if not hunt_id:
        return False, ("no hunt id: a production lesson must name the hunt "
                       "that produced it")
    if not authorization_ref:
        return False, ("no authorization reference: a production lesson must "
                       "name the authorization that permitted the hunt")
    try:
        row = con.execute(
            "SELECT validated, authorization_ref FROM hunt_authorization"
            " WHERE hunt_id=?", (hunt_id,)).fetchone()
    except sqlite3.Error:
        return False, ("the authorization receipt table is not available, so "
                       "the production origin cannot be verified")
    if row is None:
        return False, (f"no authorization receipt for hunt {hunt_id!r}: the "
                       "authorization gate never recorded one")
    if not int(row["validated"] or 0):
        return False, (f"the authorization for hunt {hunt_id!r} was never "
                       "validated")
    recorded = str(row["authorization_ref"] or "").strip()
    if recorded != str(authorization_ref).strip():
        return False, (f"the authorization reference does not match the "
                       f"receipt for hunt {hunt_id!r}")
    return True, (f"hunt {hunt_id!r} is backed by a validated authorization "
                  f"({recorded!r})")


# The origins whose lessons may steer a hunt or rank a finding.
#
# MEASURED 2026-11-01: every lesson query in this module filtered on
# `state='verified'` and nothing else, so a lesson captured from a test
# run was returned as intelligence. The origin filter is applied to each
# of them; the vocabulary is duplicated from `orch/provenance.py`
# deliberately, because the learning engine and the orchestrator are two
# owners of one database and an owner must not import the other.
# `eval/test_p2_provenance.py` asserts the two agree.
_ELIGIBLE_ORIGINS = ("PRODUCTION_HUNT", "MANUAL_ENTRY", "IMPORTED_RESEARCH")


def _eligible_origin_sql() -> str:
    """The `origin IN (...)` fragment, with its placeholders."""
    return ",".join("?" for _ in _ELIGIBLE_ORIGINS)


def _normalise_origin(value: str | None) -> str:
    """Coerce an origin to the vocabulary, defaulting to UNKNOWN.

    `orch.provenance` owns the vocabulary, but the learning engine must
    not import the orchestrator -- they are two owners of one database,
    and an owner must not depend on the other. So the normalisation is
    duplicated here DELIBERATELY, with the same semantics, and
    `eval/test_p2_provenance.py` asserts the two agree.
    """
    if value is None:
        return "UNKNOWN"
    v = str(value).strip().upper()
    valid = ("PRODUCTION_HUNT", "EXAM_FIXTURE", "EVAL_TEST",
             "IMPORTED_RESEARCH", "MANUAL_ENTRY", "UNKNOWN")
    return v if v in valid else "UNKNOWN"


# ---------------------------------------------------------------------------
# 2. analyze
# ---------------------------------------------------------------------------

def analyze_hook(con: sqlite3.Connection, *, class_id: str | None = None
                 ) -> dict[str, Any]:
    """Identify what the corpus is missing, relative to what was captured.

    Two kinds of gap are found:
      * a class the corpus has never researched (no gated items), and
      * a captured lesson that has no verification evidence.

    Both are persisted so they are durable, not just returned.
    """
    ensure_schema(con)
    now = _now()
    gaps: list[dict[str, Any]] = []

    # (a) classes with no gated items at all.
    if class_id:
        targets = [class_id]
    else:
        targets = [r["id"] for r in con.execute(
            "SELECT id FROM bug_class WHERE status!='retired' ORDER BY id")]
    for cid in targets:
        n = con.execute(
            "SELECT count(*) n FROM item WHERE class_id=? AND status='active'",
            (cid,)).fetchone()["n"]
        if n == 0:
            gaps.append({"class_id": cid, "kind": "unresearched_class",
                         "detail": f"class {cid!r} has no researched items"})

    # (b) captured lessons with no evidence.
    for r in con.execute(
            "SELECT lesson_key, topic, class_id FROM lesson"
            " WHERE state='captured'"):
        gaps.append({"class_id": r["class_id"], "kind": "unverified_lesson",
                     "detail": f"lesson {r['lesson_key']} ({r['topic']!r}) "
                               f"has no verification evidence",
                     "lesson_key": r["lesson_key"]})

    written: list[str] = []
    for g in gaps:
        gkey = _key(g["kind"], g.get("class_id") or "", g.get("lesson_key") or "",
                    g["detail"])
        con.execute(
            "INSERT INTO learning_gap(gap_key, class_id, kind, detail, status,"
            " created_at, updated_at) VALUES (?,?,?,?,'open',?,?)"
            " ON CONFLICT(gap_key) DO UPDATE SET detail=excluded.detail,"
            " updated_at=excluded.updated_at",
            (gkey, g.get("class_id"), g["kind"], g["detail"], now, now))
        written.append(gkey)

    # A captured lesson that the analysis has looked at advances to
    # `analyzed` — it is still not verified.
    con.execute("UPDATE lesson SET state='analyzed', updated_at=?"
                " WHERE state='captured'", (now,))
    con.commit()
    return {"ok": True, "gaps": gaps, "gap_keys": written,
            "classes_examined": len(targets)}


# ---------------------------------------------------------------------------
# 3. research
# ---------------------------------------------------------------------------

def research_hook(con: sqlite3.Connection, *, gap_key: str | None = None,
                  class_id: str | None = None,
                  objective: str = "") -> dict[str, Any]:
    """Turn a gap into a concrete research task. Idempotent.

    The proposal is PERSISTED, not merely returned: a gap that produced a
    proposal must remain open until the proposal is acted on.
    """
    ensure_schema(con)
    now = _now()
    gap = None
    if gap_key:
        gap = con.execute("SELECT * FROM learning_gap WHERE gap_key=?",
                          (gap_key,)).fetchone()
        if gap is None:
            return {"ok": False, "reason": f"no such gap: {gap_key}",
                    "research_key": None}
        class_id = class_id or gap["class_id"]
    if not class_id:
        return {"ok": False, "reason": "a research proposal needs a class",
                "research_key": None}
    if not objective:
        objective = (f"Research {class_id}: gather cited, quoted evidence for "
                     f"the class and close the recorded gap")
    rkey = _key("research", gap_key or "", class_id, objective)
    existing = con.execute(
        "SELECT research_key, status FROM learning_research WHERE research_key=?",
        (rkey,)).fetchone()
    if existing:
        return {"ok": True, "research_key": rkey, "status": existing["status"],
                "created": False, "idempotent": True}
    con.execute(
        "INSERT INTO learning_research(research_key, gap_key, class_id,"
        " objective, status, created_at, updated_at)"
        " VALUES (?,?,?,?,'proposed',?,?)",
        (rkey, gap_key or "", class_id, objective, now, now))
    if gap_key:
        con.execute("UPDATE learning_gap SET status='proposed', updated_at=?"
                    " WHERE gap_key=?", (now, gap_key))
    con.commit()
    return {"ok": True, "research_key": rkey, "status": "proposed",
            "created": True, "idempotent": False, "objective": objective}


# ---------------------------------------------------------------------------
# 4. verify
# ---------------------------------------------------------------------------

def verify_hook(con: sqlite3.Connection, *, lesson_key: str,
                evidence: str | dict[str, Any] | None = None,
                provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    """Record verification evidence for a lesson.

    A lesson with NO evidence is REFUSED. The lesson is not promoted, not
    written to the corpus, and the refusal says why. This is the hook that
    stops an unverified observation from becoming knowledge.
    """
    ensure_schema(con)
    row = con.execute("SELECT * FROM lesson WHERE lesson_key=?",
                      (lesson_key,)).fetchone()
    if row is None:
        return {"ok": False, "reason": f"no such lesson: {lesson_key}",
                "state": None, "verified": False}
    if not evidence:
        return {"ok": False, "verified": False, "state": row["state"],
                "reason": ("verification requires evidence; a lesson with no "
                           "evidence stays unverified and never reaches the "
                           "corpus")}

    # AN INELIGIBLE ORIGIN CANNOT BE VERIFIED.
    #
    # MEASURED 2026-11-01: `verify_hook` refused a lesson with no
    # evidence, and nothing else. Evidence proves a CLAIM; it says
    # nothing about where the claim came from. So a lesson captured from
    # a test run, given any evidence at all, was promoted to `verified` --
    # and `verified` is exactly the state `before_recon` and
    # `before_summary` read as intelligence for the next hunt.
    #
    # Evidence and origin are INDEPENDENT conditions. Both must hold.
    origin = _normalise_origin(
        row["origin"] if "origin" in row.keys() else None)
    # THE DESCRIPTOR BLOB IS READ ONCE, HERE.
    #
    # It says where the observation came from -- which hunt, which
    # finding -- and it is what the receipt check below consults. It is
    # read before any branch so the merge at the end can preserve it.
    blob: dict[str, Any] = {}
    try:
        raw = row["provenance"] if "provenance" in row.keys() else None
        parsed = json.loads(raw) if raw else {}
        if isinstance(parsed, dict):
            blob = parsed
    except (ValueError, TypeError):
        blob = {}
    if origin in ("EVAL_TEST", "EXAM_FIXTURE", "UNKNOWN"):
        return {"ok": False, "verified": False, "state": row["state"],
                "origin": origin,
                "reason": (f"verification refused: the lesson's origin is "
                           f"{origin!r}, which is not eligible to become "
                           f"hunting experience. Evidence proves the claim; "
                           f"it does not change where the claim came from.")}

    # A PRODUCTION LESSON MUST STILL HAVE ITS RECEIPT.
    #
    # MEASURED 2026-11-02: the origin column is guarded by a trigger, and
    # `capture_hook` refuses to create a PRODUCTION_HUNT lesson without a
    # receipt. But `verify_hook` read the origin and nothing else -- so it
    # trusted the column rather than checking the fact behind it.
    #
    # The lesson's descriptor blob names the hunt and the authorization
    # reference, so the receipt can be checked here: a validated
    # `hunt_authorization` row must exist for that hunt. Verification is
    # the LAST gate before a lesson becomes intelligence, so it is the
    # right place to demand the proof rather than the claim.
    if origin == "PRODUCTION_HUNT":
        hunt_id = blob.get("hunt_id")
        if not hunt_id:
            return {"ok": False, "verified": False, "state": row["state"],
                    "origin": origin,
                    "reason": ("verification refused: the lesson claims a "
                               "production origin but names no hunt, so no "
                               "authorization receipt can back it")}
        try:
            receipt = con.execute(
                "SELECT validated, authorization_ref FROM hunt_authorization"
                " WHERE hunt_id=?", (hunt_id,)).fetchone()
        except sqlite3.Error:
            receipt = None
        if receipt is None:
            return {"ok": False, "verified": False, "state": row["state"],
                    "origin": origin,
                    "reason": (f"verification refused: the lesson claims a "
                               f"production origin but hunt {hunt_id!r} has "
                               f"no authorization receipt")}
        if not int(receipt["validated"] or 0):
            return {"ok": False, "verified": False, "state": row["state"],
                    "origin": origin,
                    "reason": (f"verification refused: the authorization for "
                               f"hunt {hunt_id!r} was never validated")}

    now = _now()
    ev = evidence if isinstance(evidence, str) else json.dumps(
        evidence, default=str, sort_keys=True)
    # THE DESCRIPTOR IS MERGED, NOT REPLACED.
    #
    # MEASURED 2026-11-02: this wrote `provenance=?` with the caller's
    # verification provenance, replacing the lesson's DESCRIPTOR blob --
    # the record of which hunt and which finding the observation came
    # from. So verifying a lesson DESTROYED the evidence of where it came
    # from, and with it the hunt id that the receipt check above needs.
    #
    # The two payloads are different things and belong in the same blob
    # under different keys: the descriptor says where the observation came
    # from, the verification says what proved it. The descriptor's keys
    # are preserved and the verification is recorded alongside.
    merged = dict(blob)
    merged["verification"] = provenance or {}
    con.execute("UPDATE lesson SET state='verified', evidence=?, provenance=?,"
                " updated_at=? WHERE lesson_key=?",
                (ev, json.dumps(merged, default=str), now, lesson_key))
    con.commit()
    return {"ok": True, "verified": True, "state": "verified",
            "lesson_key": lesson_key, "origin": origin}


# ---------------------------------------------------------------------------
# 5. update
# ---------------------------------------------------------------------------

def update_hook(con: sqlite3.Connection, *, lesson_key: str | None = None,
                class_id: str | None = None) -> dict[str, Any]:
    """Refresh the canonical projection after a lesson changed a class.

    Only a VERIFIED lesson can update the projection. An unverified lesson is
    refused, because a projection is what the agent actually loads: letting
    an unverified observation rewrite it would put speculation in front of
    the model.

    THE LESSON BECOMES A KNOWLEDGE ITEM FIRST.
    --------------------------------------------
    MEASURED 2026-11-01: this hook called `project.refresh_class` and
    nothing else. But `wks.skillgen.render` builds the skill from
    `wks.retrieval.class_digest`, which reads the `item` and `fp_case`
    tables -- NOT the `lesson` table. So refreshing the projection after a
    lesson was verified re-rendered the skill from the corpus as it already
    stood: the lesson's content never appeared in the file an agent loads,
    and the lesson stopped one step short of the thing it was supposed to
    teach.

    So the lesson is first written into the corpus as an `item` -- a
    falsifiable claim of kind `technique`, carrying the lesson body -- and
    only then is the projection refreshed. The item is created in
    `discovered` state (via `wks.store.add_item`), which is the state
    `wks.quality` promotes; the learning engine does not get to decide
    that its own lesson is high quality. Promotion is quality.py's job
    alone, and that separation is what keeps the gate meaningful.

    The item is keyed by the lesson key, so re-running this hook does not
    create a second item.
    """
    ensure_schema(con)
    from wks import ownership as _ownership
    row = None
    if lesson_key:
        row = con.execute("SELECT * FROM lesson WHERE lesson_key=?",
                          (lesson_key,)).fetchone()
        if row is None:
            return {"ok": False, "reason": f"no such lesson: {lesson_key}",
                    "updated": False}
        if row["state"] != "verified":
            return {"ok": False, "updated": False, "state": row["state"],
                    "reason": ("only a VERIFIED lesson may update the "
                               "canonical projection")}
        class_id = class_id or row["class_id"]
    if not class_id:
        return {"ok": False, "updated": False,
                "reason": "no class to update"}

    # THE LESSON -> ITEM PROJECTION.
    #
    # Written through the knowledge owner, because `item` is a WKS table.
    # The claim is the lesson's own text: a lesson is a lesson because it
    # says something falsifiable, and the body carries the elaboration.
    item_id = None
    projection_error = None
    if lesson_key and row is not None:
        from wks import unified_ingest as _ui
        try:
            with _ownership.owner_write(con, _ownership.WKS):
                # Build a normalized candidate from the verified lesson.
                prov = {}
                try:
                    prov = json.loads(row["provenance"] or "{}")
                except (TypeError, ValueError):
                    prov = {}
                ev = {}
                try:
                    ev = json.loads(row["evidence"] or "{}")
                except (TypeError, ValueError):
                    ev = {}
                url = ""
                if not isinstance(ev, str):
                    url = str(ev.get("url") or "")
                if not url:
                    url = str(prov.get("url") or "")
                sources = []
                if url:
                    from urllib.parse import urlparse
                    _host = urlparse(url).hostname or ""
                    if _host:
                        sources.append({"url": url, "source_type": "writeup",
                                       "title": row["topic"] or "",
                                       "publisher": _host})
                candidate = {
                    "item_key": f"lesson.{lesson_key}",
                    "class_id": class_id,
                    "claim": (row["body"] or row["topic"] or "")[:2000],
                    "kind": "technique",
                    "body": (row["body"] or "")[:4000],
                    "hunting_value": 4,
                    "sources": sources,
                }
                verdict = _ui.ingest_candidate(con, candidate, origin="LEARNING",
                                               verify=False)
                item_id = None
                try:
                    r = wks_store.get_item(con, f"lesson.{lesson_key}")
                    item_id = int(r["id"]) if r is not None else None
                except Exception:
                    item_id = None
        except Exception as exc:  # noqa: BLE001 - reported, never swallowed
            projection_error = f"{type(exc).__name__}: {exc}"

    from wks import project
    # THE PROJECTION WRITES TO WKS TABLES.
    #
    # `project.refresh_class` updates `bug_class.methodology` when it
    # rewrites the assessment. That is a WKS table, and the runtime
    # ownership authorizer refuses it unless the write is made through the
    # owner's context. MEASURED 2026-11-01: the lesson->item projection was
    # wired and the refresh reported "assessment: DatabaseError: not
    # authorized" -- the item landed, the assessment did not.
    #
    # The whole refresh runs under the owner, so every writer inside it is
    # sanctioned. The projection writes FILES outside the database, and
    # those are unaffected either way.
    with _ownership.owner_write(con, _ownership.WKS):
        result = project.refresh_class(con, class_id)
    con.commit()
    # A REFUSED projection is not an update. Reporting `ok: True` for a write
    # that never happened is how a caller believes the canonical skill now
    # reflects a verified lesson when it does not.
    #
    # MEASURED 2026-10-31: the learning hooks are exercised against a scratch
    # database in eval/test_learning_hooks.py. That scratch connection is not
    # the canonical store, so `wks.project` refuses to project from it --
    # which is the CORRECT outcome, because the projection writes to the
    # canonical tree. Before the refusal existed, the scratch corpus (a bare
    # `sqli` class with zero items) was written straight over the real
    # 45-item sqli hunting skill.
    errors = list(result.get("errors", []))
    if projection_error:
        errors.append(f"lesson projection failed: {projection_error}")
    refused = [e for e in errors if e.startswith("projection refused:")]
    if refused:
        return {"ok": False, "updated": False, "class_id": class_id,
                "item_id": item_id, "reason": refused[0], "errors": errors}
    if projection_error:
        return {"ok": False, "updated": False, "class_id": class_id,
                "item_id": item_id,
                "reason": f"the lesson could not be written into the corpus: "
                          f"{projection_error}", "errors": errors}
    return {"ok": True, "updated": True, "class_id": class_id,
            "item_id": item_id,
            "changed": result.get("changed", []),
            "errors": errors}


# ---------------------------------------------------------------------------
# triage feedback
# ---------------------------------------------------------------------------

def after_triage(con: sqlite3.Connection, *, lesson_key: str,
                 feedback_type: str, notes: str = "",
                 provenance: dict[str, Any] | None = None) -> dict[str, Any]:
    """Record a program's verdict on a lesson and recalibrate its score.

    The feedback types are the ones the doctrine names: accepted, duplicate,
    informative, false_positive. A false_positive pushes the lesson down and
    it never reaches the corpus; an accepted one pushes it up.
    """
    ensure_schema(con)
    row = con.execute("SELECT * FROM lesson WHERE lesson_key=?",
                      (lesson_key,)).fetchone()
    if row is None:
        return {"ok": False, "reason": f"no such lesson: {lesson_key}"}
    fb = (feedback_type or "").strip().lower()
    # `ineligible_origin` records that a lesson was REFUSED because of
    # where it came from.
    #
    # MEASURED 2026-11-01: the learning bridge called
    # `after_triage(feedback_type="ineligible_origin")` for a lesson
    # whose origin was not eligible, and this whitelist did not contain
    # it -- so the call returned `{"ok": False, "reason": "unknown
    # feedback type"}` and the refusal was recorded NOWHERE. The lesson
    # stayed unverified (which is the property that matters) but the
    # reason it was refused was lost.
    #
    # The delta is ZERO: the origin, not the triage, is what disqualifies
    # the lesson. The feedback is a record, not a score change.
    if fb not in ("accepted", "duplicate", "informative", "false_positive",
                  "ineligible_origin"):
        return {"ok": False, "reason": f"unknown feedback type: {feedback_type!r}"}
    delta = {"accepted": 0.3, "informative": -0.05,
             "duplicate": -0.2, "false_positive": -0.5,
             "ineligible_origin": 0.0}[fb]
    new_score = max(0.0, min(1.0, float(row["score"] or 0.0) + delta))
    fkey = _key("feedback", lesson_key, fb, notes)
    now = _now()
    con.execute(
        "INSERT INTO lesson_feedback(feedback_key, lesson_key, feedback_type,"
        " notes, provenance, created_at) VALUES (?,?,?,?,?,?)"
        " ON CONFLICT(feedback_key) DO NOTHING",
        (fkey, lesson_key, fb, notes,
         json.dumps(provenance or {}, default=str), now))
    con.execute("UPDATE lesson SET score=?, updated_at=? WHERE lesson_key=?",
                (new_score, now, lesson_key))
    if fb == "false_positive":
        con.execute("UPDATE lesson SET state='rejected', updated_at=?"
                    " WHERE lesson_key=?", (now, lesson_key))
    con.commit()
    return {"ok": True, "feedback_type": fb, "score": new_score,
            "previous_score": float(row["score"] or 0.0), "delta": delta}


# ---------------------------------------------------------------------------
# the five named hooks, by their documented names
# ---------------------------------------------------------------------------

def before_recon(con: sqlite3.Connection, target: str,
                 technologies: Iterable[str] = ()) -> dict[str, Any]:
    """What the corpus already knows before a hunt starts.

    THE SCOPE IS CLASS-LEVEL, AND THAT IS DELIBERATE.
    -----------------------------------------------
    MEASURED 2026-11-01: this function took a `target` argument, echoed it
    back in its result, and never used it in any query. Every lesson the
    corpus held for ANY target was returned for EVERY target. A reader
    could reasonably have concluded the return was target-scoped, because
    the result said `"target": <the target>` right next to the lessons.

    The behaviour itself is RIGHT, and it is right for a reason worth
    stating: a verified lesson is class-level experience. A lesson that
    says "this CORS misconfiguration is real and reportable" is not
    about one host -- it is about the class. `ActiveHuntExecutor.
    _prior_classes` says it in the code: "a class with a verified lesson
    is a class this system has PROVEN exploitable before, so it is worth
    looking for again". Scoping the prior to the target would throw away
    exactly the intelligence the corpus accumulated.

    But a silent corpus-wide read presented as target-scoped is a
    misrepresentation, so the scope is now EXPLICIT in the result:

      * `scope` says what the prior actually is.
      * each lesson carries `scope`: `target` when the lesson is about
        THIS target, `class` when it is corpus-wide experience about the
        class.
      * `target_lessons` and `class_lessons` are separated, so a caller
        that wants only what is known about this host can take it, and a
        caller that wants the class prior can take that.

    A target-specific lesson is recognised by the topic the learning
    bridge writes: `outcome:{class_id}:{target}`. A write-up-derived
    lesson is class-scoped by nature -- a published advisory is not about
    one host -- and is recorded as such.
    """
    ensure_schema(con)
    # ONLY ELIGIBLE ORIGINS, AND ONLY VERIFIED LESSONS.
    #
    # MEASURED 2026-11-01: this returned every lesson in state
    # `verified`, with no question of where the lesson came from. A
    # lesson captured from a test run and verified by the bridge was
    # therefore returned as INTELLIGENCE to the next hunt -- the class
    # prior that steers a hunt was, in part, test output.
    #
    # Two independent conditions now hold:
    #   * `origin` is eligible (PRODUCTION_HUNT, MANUAL_ENTRY,
    #     IMPORTED_RESEARCH)
    #   * `state` is `verified`
    # Evidence proves a claim; the origin says whether the claim is
    # allowed to steer a hunt. Neither substitutes for the other.
    eligible_origins = ("PRODUCTION_HUNT", "MANUAL_ENTRY", "IMPORTED_RESEARCH")
    origin_sql = ",".join("?" for _ in eligible_origins)
    classes = [r["class_id"] for r in con.execute(
        f"SELECT DISTINCT class_id FROM lesson WHERE class_id IS NOT NULL"
        f" AND state='verified' AND origin IN ({origin_sql})",
        eligible_origins)]
    lessons = []
    target_lessons = []
    class_lessons = []
    target_key = (target or "").strip().lower()
    for cid in classes:
        for r in con.execute(
                f"SELECT topic, body, score FROM lesson WHERE class_id=?"
                f" AND state='verified' AND origin IN ({origin_sql})"
                " ORDER BY score DESC LIMIT 5",
                (cid, *eligible_origins)):
            lesson = {"class_id": cid, "topic": r["topic"],
                      "body": r["body"], "score": r["score"]}
            # The learning bridge's topic names the target it came from:
            # `outcome:{class_id}:{target}`.
            topic = str(r["topic"] or "")
            is_target = False
            if target_key and topic.startswith("outcome:"):
                parts = topic.split(":", 2)
                if len(parts) == 3:
                    is_target = parts[2].strip().lower() == target_key
            lesson["scope"] = "target" if is_target else "class"
            lessons.append(lesson)
            (target_lessons if is_target else class_lessons).append(lesson)
    return {"target": target, "technologies": list(technologies),
            "scope": "class",
            "scope_note": ("the prior is class-level: a verified lesson is "
                           "experience with the CLASS, not with one host. "
                           "Lessons that are specifically about this target "
                           "are marked scope='target' and listed separately."),
            "classes_with_verified_lessons": classes,
            "lessons": lessons,
            "target_lessons": target_lessons,
            "class_lessons": class_lessons,
            "note": ("verified lessons only — an unverified observation is "
                     "not returned as intelligence")}


def during_testing(con: sqlite3.Connection, signals: dict[str, Any]
                   ) -> dict[str, Any]:
    """Score signals against what has been learned before.

    MEASURED 2026-11-01: the prior lookup was
    `WHERE topic LIKE '%{signal_name}%' AND state='verified'`. But the
    lesson topics are NOT signal names: the learning bridge writes
    `outcome:{class_id}:{target}` and the write-up pipeline writes
    `{class_id}: {title}`. So the LIKE could never match a real lesson --
    `prior_lessons` was 0 for every signal, always. The hook was wired and
    running, and it reported "absent history" for history that existed.

    The prior is now looked up the way the corpus actually stores it:

      1. BY CLASS -- the lesson's `class_id`, when the signal names a known
         class. This is the strong match: a lesson verified for `sqli` is
         prior experience with SQL injection.
      2. BY SIGNAL TEXT -- the lesson's `body`, when it mentions the signal.
         This catches a lesson about a specific observed behaviour.

    A signal that matches neither is reported as having no prior, which is
    the truth.
    """
    ensure_schema(con)
    from learning_engine.scoring.engine import score as _score
    scored = []
    for name, value in (signals or {}).items():
        v = value if isinstance(value, (int, float)) else 1.0
        s = _score({name: float(v)})
        prior_n, prior_avg = _prior_for_signal(con, name)
        scored.append({"signal": name, "score": round(float(s), 4),
                       "prior_lessons": prior_n,
                       "prior_average": round(prior_avg, 4)})
    scored.sort(key=lambda r: -r["score"])
    return {"signals": scored,
            "note": ("historical outcomes are attached where a verified lesson "
                     "exists for the signal; absent history is reported as "
                     "absent, not as a score")}


def _prior_for_signal(con: sqlite3.Connection, name: str) -> tuple[int, float]:
    """How much verified history backs this signal? (count, average score)

    The lookup is by CLASS and by BODY, because that is how the corpus
    actually records what was learned. See `during_testing`'s docstring for
    the measurement that forced the change.

    A signal names a BEHAVIOUR ("sql_error_or_behaviour"), not a class
    ("sqli"). The behaviour-to-class mapping is the taxonomy's own
    (`orch.hypothesis.SIGNATURES`), so it is read from there rather than
    re-declared here -- a second copy of the taxonomy would be a second
    source of truth.
    """
    sig = (name or "").strip().lower()
    if not sig:
        return 0, 0.0
    classes = _classes_for_signal(sig)
    n = 0
    total = 0.0
    for cid in classes:
        row = con.execute(
            f"SELECT count(*) n, avg(score) avg FROM lesson"
            f" WHERE state='verified' AND origin IN"
            f" ({_eligible_origin_sql()}) AND lower(class_id)=?",
            (*_ELIGIBLE_ORIGINS, cid)).fetchone()
        cnt = int(row["n"] or 0)
        if cnt:
            n += cnt
            total += float(row["avg"] or 0.0) * cnt
    if n:
        return n, total / n
    # BY BODY -- the lesson's body mentions the signal.
    # ELIGIBLE ORIGIN ONLY -- see `_ELIGIBLE_ORIGINS`.
    row = con.execute(
        f"SELECT count(*) n, avg(score) avg FROM lesson"
        f" WHERE state='verified' AND origin IN"
        f" ({_eligible_origin_sql()}) AND lower(body) LIKE ?",
        (*_ELIGIBLE_ORIGINS, f"%{sig}%")).fetchone()
    return int(row["n"] or 0), float(row["avg"] or 0.0)


def _classes_for_signal(sig: str) -> list[str]:
    """The bug classes the taxonomy says this signal belongs to.

    Read from `orch.hypothesis.SIGNATURES`, which is the project's own
    behaviour-to-class mapping. If the taxonomy is unavailable, the signal
    is treated as a class name itself, which is the best a caller can do
    without it.
    """
    try:
        from orch.hypothesis import SIGNATURES
    except Exception:
        return [sig]
    out: list[str] = []
    for cid, spec in SIGNATURES.items():
        names = {str(s).lower() for s in spec.get("all", [])}
        names |= {str(s).lower() for s in spec.get("any", [])}
        if sig in names:
            out.append(cid.lower())
    if out:
        return out
    # The signal may already name the class.
    return [sig] if sig in {c.lower() for c in SIGNATURES} else []


def _origin_from_target(target: str | None) -> str:
    """Derive an origin from the target alone.

    MEASURED 2026-11-01: `after_finding` captured every lesson with no
    origin, so it defaulted to UNKNOWN -- and `verify_hook` refuses an
    UNKNOWN lesson. So no lesson captured through the hunt's own
    learning path could ever be verified, promoted, or returned as
    intelligence. The learning loop was disconnected at its first step.

    MEASURED 2026-11-02: the fix for that disconnectedness was WRONG in
    the other direction. This function returned PRODUCTION_HUNT for any
    routable-looking target -- so a lesson was called production
    experience purely because of the string in its host field. The
    target names where the observation happened; it says NOTHING about
    whether the observation was authorized, and a host name is not a
    receipt.

    So the rule is now FAIL-CLOSED: a target that cannot be a production
    target -- the loopback address, or a reserved test domain -- names a
    test observation, and everything else is UNKNOWN. UNKNOWN refuses
    verification, which is correct: a lesson whose authorization was
    never checked must not steer a hunt.

    A caller that HAS an authorization receipt passes `origin`
    explicitly, and `capture_hook` verifies that receipt before the
    lesson can claim PRODUCTION_HUNT.

    This is deliberately DUPLICATED from `orch/provenance.py`, because
    the learning engine and the orchestrator are two owners of one
    database and an owner must not import the other.
    `eval/test_p2_provenance.py` asserts the two agree.
    """
    t = (target or "").strip().lower()
    if not t:
        return "UNKNOWN"
    if t in ("127.0.0.1", "localhost", "::1", "0.0.0.0"):
        return "EVAL_TEST"
    if t.startswith("127."):
        return "EVAL_TEST"
    if any(t.endswith(sfx) for sfx in
           (".test", ".example", ".invalid", ".localhost", ".local")):
        return "EVAL_TEST"
    # A ROUTABLE TARGET IS NOT A RECEIPT.
    return "UNKNOWN"


def after_finding(con: sqlite3.Connection, *, target: str,
                  vulnerability_class: str, signals: dict[str, Any] | None = None,
                  validation_state: str = "candidate",
                  source_provenance: dict[str, Any] | None = None,
                  origin: str | None = None,
                  hunt_id: str | None = None,
                  authorization_ref: str | None = None
                  ) -> dict[str, Any]:
    """Persist a finding outcome as a captured lesson.

    `origin` says where the observation came from. MEASURED 2026-11-01:
    it did not exist, so every captured lesson defaulted to UNKNOWN, and
    `verify_hook` refuses an UNKNOWN lesson -- so no lesson captured
    through this path could ever be verified or promoted.

    The default is derived from the target: the loopback address and
    the reserved test domains cannot have produced a production
    observation. The rule lives in `orch/provenance.py`.

    MEASURED 2026-11-02: the default is now FAIL-CLOSED -- a routable
    target is UNKNOWN, because a host name is not a receipt. A caller
    with a receipt passes `origin` AND `hunt_id` AND
    `authorization_ref`, and `capture_hook` verifies the receipt before
    the lesson may claim PRODUCTION_HUNT.
    """
    body = (f"finding on {target}: class={vulnerability_class}, "
            f"state={validation_state}, signals="
            f"{sorted((signals or {}).keys())}")
    if origin is None:
        origin = _origin_from_target(target)
    return capture_hook(con, topic=f"finding:{vulnerability_class}:{target}",
                        body=body, class_id=vulnerability_class,
                        origin=origin,
                        hunt_id=hunt_id,
                        authorization_ref=authorization_ref,
                        provenance={"source_provenance": source_provenance or {},
                                    "validation_state": validation_state,
                                    "target": target,
                                    "hunt_id": hunt_id,
                                    "authorization_ref": authorization_ref})


def before_summary(con: sqlite3.Connection, findings: Iterable[dict[str, Any]]
                   ) -> dict[str, Any]:
    """Rank findings by their learned exploitability."""
    ensure_schema(con)
    ranked = []
    for f in list(findings or []):
        cid = f.get("class_id") or f.get("vulnerability_class") or ""
        # ELIGIBLE ORIGIN ONLY -- see `_ELIGIBLE_ORIGINS`.
        row = con.execute(
            f"SELECT count(*) n, avg(score) avg FROM lesson WHERE class_id=?"
            f" AND state='verified' AND origin IN ({_eligible_origin_sql()})",
            (cid, *_ELIGIBLE_ORIGINS)).fetchone()
        prior = float(row["avg"] or 0.0) if int(row["n"] or 0) else 0.0
        ranked.append({**f, "learned_exploitability": round(prior, 4),
                       "prior_lessons": int(row["n"] or 0)})
    ranked.sort(key=lambda r: (-r["learned_exploitability"],
                                str(r.get("finding_key") or r.get("title") or "")))
    return {"ranked": ranked,
            "note": ("ranking uses verified lessons only; a class with no "
                     "history is ranked last rather than given a default "
                     "score")}


# ---------------------------------------------------------------------------
# legacy migration
# ---------------------------------------------------------------------------

def migrate_legacy(con: sqlite3.Connection) -> dict[str, Any]:
    """Copy the legacy `learning.db` records into the canonical database.

    ONE-TIME and transactional. The legacy file is never written again; it is
    left in place because nothing is deleted. Re-running is a no-op.

    MEASURED 2026-10-31 (db-layer audit): this read ONLY the `lessons`
    table. The legacy database also holds a `findings` table (7 rows), and
    those rows were silently dropped -- the function reported "migrated: N"
    with no mention of them, which is exactly the kind of quiet data loss a
    migration is supposed to prevent. The docstring said "lessons" and the
    code did what the docstring said; the problem is that the docstring was
    narrower than the database.

    It also `continue`d past any lesson with an empty topic or body, with
    no count of what it skipped. A skipped row is indistinguishable from a
    migrated one in the report.

    Now: BOTH tables are migrated, and every row read is accounted for --
    migrated, skipped-with-reason, or already present.
    """
    ensure_schema(con)
    if not LEGACY_DB.is_file():
        return {"migrated": 0, "legacy_present": False}
    try:
        legacy = sqlite3.connect(f"file:{LEGACY_DB}?mode=ro", uri=True)
        legacy.row_factory = sqlite3.Row
        tables = {r[0] for r in legacy.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        lessons = legacy.execute(
            "SELECT topic, body, score FROM lessons").fetchall() \
            if "lessons" in tables else []
        findings = legacy.execute(
            "SELECT id, title, class_id, severity, status, created_at"
            " FROM findings").fetchall() if "findings" in tables else []
        legacy.close()
    except sqlite3.Error as e:
        return {"migrated": 0, "legacy_present": True, "error": str(e)}

    now = _now()
    migrated = 0
    skipped: list[dict[str, Any]] = []

    # `lesson` is a KNOWLEDGE table, so writing it needs the knowledge
    # OWNER's authority -- and the connection this migration runs on may be
    # an ORCHESTRATION connection. The owner context is taken once, around
    # the whole lesson loop, so the authority is explicit and the grant is
    # released even if a row raises.
    from wks import ownership as _ownership
    with _ownership.owner_write(con, _ownership.WKS):
        for r in lessons:
            topic = (r["topic"] or "").strip()
            body = (r["body"] or "").strip()
            if not topic or not body:
                # NOT silently dropped: a skipped row is reported with its
                # reason, so the count always adds up.
                skipped.append({"table": "lessons", "reason":
                                "empty topic or body", "topic": topic})
                continue
            key = _key(topic, body)
            cur = con.execute(
                "INSERT INTO lesson(lesson_key, topic, body, score, state,"
                " provenance, evidence, created_at, updated_at)"
                " VALUES (?,?,?,?,'captured',?,NULL,?,?)"
                " ON CONFLICT(lesson_key) DO NOTHING",
                (key, topic, body, float(r["score"] or 0.0),
                 json.dumps({"migrated_from": str(LEGACY_DB)}, default=str),
                 now, now))
            migrated += cur.rowcount or 0

    # The legacy `findings` table held operational records: a title, a bug
    # class, a severity and a status. The canonical `finding` table is the
    # home for those.
    #
    # `finding` is an ORCHESTRATION table (see `wks/ownership.py`), so the
    # learning engine cannot write it directly -- the runtime ownership
    # authorizer would refuse, and rightly so. The write goes through
    # `orch.store.add_finding`, the owner's API, with the owner's authority
    # explicitly granted for the duration of the call.
    findings_migrated = 0
    try:
        from orch import store as orch_store
        from wks import ownership as _ownership
    except ImportError:
        orch_store = None
    for r in findings:
        title = (r["title"] or "").strip()
        if not title:
            skipped.append({"table": "findings", "reason": "empty title",
                            "title": title})
            continue
        key = "legacy." + _key(title, str(r["class_id"] or ""),
                               str(r["severity"] or ""))
        if orch_store is None:
            skipped.append({"table": "findings",
                            "reason": "orch layer unavailable", "title": title})
            continue
        #
        # MEASURED 2026-10-31: the legacy `findings` rows are migrated to
        # the `quarantine` table, NOT to the live `finding` table.
        #
        # The first version of this migration inserted them as live
        # findings. That was wrong, and the test suite said so:
        # `eval/test_wks_integrity_repair.py` asserts "no evidence row
        # comes from a disqualified or failed exam" by requiring
        # `evidence == finding`, and the count went 15/15 -> 15/22.
        #
        # The reason is structural, not cosmetic: the canonical `finding`
        # table is the HUNT's record of a finding, and every live finding
        # must be backed by an `evidence` row. The legacy table had no
        # evidence column at all -- only a title, a class, a severity and a
        # status. Inserting them as live findings created seven findings
        # with no proof behind them, which is exactly the state the
        # evidence invariant exists to prevent.
        #
        # So the rows are RETAINED (nothing is deleted) in `quarantine`,
        # with a verdict saying why they are not live findings. The
        # `quarantine` table is the knowledge owner's, so the write goes
        # through the owner's authority.
        payload = {k: r[k] for k in r.keys()}
        qkey = f"legacy_finding.{key}"
        try:
            with _ownership.owner_write(con, _ownership.WKS):
                con.execute(
                    "INSERT INTO quarantine(quarantine_key, table_name,"
                    " row_key, verdict, payload, quarantined_at)"
                    " VALUES (?,?,?,?,?,?)"
                    " ON CONFLICT(quarantine_key) DO NOTHING",
                    (qkey, "legacy.findings", str(r["id"]),
                     LEGACY_FINDING_VERDICT,
                     json.dumps(payload, default=str), now))
                con.commit()
            findings_migrated += 1
        except sqlite3.Error as e:
            skipped.append({"table": "findings", "reason": str(e),
                            "title": title})

    con.commit()
    return {"migrated": migrated,
            "findings_quarantined": findings_migrated,
            "legacy_present": True,
            "legacy_rows_read": len(lessons) + len(findings),
            "legacy_lessons_read": len(lessons),
            "legacy_findings_read": len(findings),
            "skipped": skipped,
            "skipped_count": len(skipped),
            "note": ("every legacy row is accounted for: migrated, skipped "
                     "with a reason, or already present")}


# ---------------------------------------------------------------------------
# convenience
# ---------------------------------------------------------------------------

class LearningEngine:
    """The object the skill file documents: `from learning_engine import
    LearningEngine`.

    It holds no state of its own beyond the database handle, so it is safe
    to construct per call.
    """

    def __init__(self, con: sqlite3.Connection | None = None):
        self._con = con
        self._owns = con is None

    @property
    def con(self) -> sqlite3.Connection:
        if self._con is None:
            self._con = open_canonical()
        return self._con

    def close(self) -> None:
        if self._owns and self._con is not None:
            self._con.close()
            self._con = None

    # The five hooks.
    def capture(self, **kw) -> dict[str, Any]:
        return capture_hook(self.con, **kw)

    def analyze(self, **kw) -> dict[str, Any]:
        return analyze_hook(self.con, **kw)

    def research(self, **kw) -> dict[str, Any]:
        return research_hook(self.con, **kw)

    def verify(self, **kw) -> dict[str, Any]:
        return verify_hook(self.con, **kw)

    def update(self, **kw) -> dict[str, Any]:
        return update_hook(self.con, **kw)

    # The named integration points from the skill file.
    def before_recon(self, target: str, technologies=()) -> dict[str, Any]:
        return before_recon(self.con, target, technologies)

    def during_testing(self, signals: dict[str, Any]) -> dict[str, Any]:
        return during_testing(self.con, signals)

    def after_finding(self, **kw) -> dict[str, Any]:
        return after_finding(self.con, **kw)

    def after_triage(self, **kw) -> dict[str, Any]:
        return after_triage(self.con, **kw)

    def before_summary(self, findings) -> dict[str, Any]:
        return before_summary(self.con, findings)


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="learning_engine")
    ap.add_argument("--db", default="")
    ap.add_argument("--migrate-legacy", action="store_true")
    ap.add_argument("--audit", action="store_true")
    a = ap.parse_args(argv)
    con = open_canonical()
    if a.migrate_legacy:
        print(json.dumps(migrate_legacy(con), indent=2))
    if a.audit:
        out = {
            "lessons": con.execute(
                "SELECT count(*) n FROM lesson").fetchone()["n"],
            "by_state": {r["state"]: r["n"] for r in con.execute(
                "SELECT state, count(*) n FROM lesson GROUP BY state")},
            "gaps": con.execute(
                "SELECT count(*) n FROM learning_gap").fetchone()["n"],
            "research": con.execute(
                "SELECT count(*) n FROM learning_research").fetchone()["n"],
            "feedback": con.execute(
                "SELECT count(*) n FROM lesson_feedback").fetchone()["n"],
            "legacy_present": LEGACY_DB.is_file(),
        }
        print(json.dumps(out, indent=2))
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
