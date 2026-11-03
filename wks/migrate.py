"""Idempotent schema migration for the remediation.

Adds to `source`:  access_state, access_checked_at, access_detail, last_ok_at
                    -> so a source's reachability is a stored FACT.
Adds to `item`:     dedup_of INTEGER, canonical_id INTEGER
                    -> so an exact duplicate is recorded, not silently merged.
Adds to `evidence`: class_id, item_id, exam_id
                    -> so a graded assessment can attach to the corpus.

Every step is safe to re-run and reports what it changed. Backfills
`access_state='UNVERIFIED'` rather than guessing: the audit measured
http_status NULL on 473/473 rows, so the honest default for a row that was
never fetched is UNVERIFIED, not ACTIVE.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import config, transport as http  # noqa: E402


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def _add(con: sqlite3.Connection, table: str, col: str, decl: str) -> bool:
    if col in _columns(con, table):
        return False
    con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
    return True


def _index(con: sqlite3.Connection, name: str, target: str) -> bool:
    """Create an index only if absent. Returns True when it CREATED one, so
    `migrate()` can report honestly instead of re-listing work it did not do."""
    have = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    if name in have:
        return False
    con.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {target}")
    return True


def migrate(con: sqlite3.Connection) -> dict:
    """Migrate the store under the migration lock. Idempotent.

    MEASURED 2026-10-31 (db-layer audit): the migration ran with NO lock.
    Two processes migrating at once could interleave their `ALTER TABLE ADD
    COLUMN` steps, and both can observe the column as absent and both try
    to add it -- which is not safely repeatable.

    The lock is a row in a dedicated table taken with a conditional INSERT:
    SQLite serializes the write, so exactly one process wins and the others
    wait. See `wks/migration_lock.py`.
    """
    from wks import migration_lock
    with migration_lock.migration_lock(con, name="wks-migrate"):
        return _migrate_locked(con)


def _migrate_locked(con: sqlite3.Connection) -> dict:
    """The migration body. Callers must hold the migration lock.

    Return what changed. Idempotent, and the report is HONEST: a re-run on a
    migrated store reports `changed: []`. An idempotent migration that lists
    its work every time is a monitor that always reads "changed", which is the
    failure this system keeps measuring elsewhere.
    """
    changed: list[str] = []

    # ---- source: access state is a stored fact, not a code constant --------
    if _add(con, "source", "access_state", "TEXT NOT NULL DEFAULT 'UNVERIFIED'"):
        changed.append("source.access_state")
    if _add(con, "source", "access_checked_at", "TEXT"):
        changed.append("source.access_checked_at")
    if _add(con, "source", "access_detail", "TEXT"):
        changed.append("source.access_detail")
    if _add(con, "source", "last_ok_at", "TEXT"):
        changed.append("source.last_ok_at")
    # content_hash / http_status / retrieved_at already exist; they were simply
    # never written. The backfill below fills what it can and the fetcher fills
    # the rest on the next verification pass.

    # A CHECK constraint cannot be added by ALTER TABLE on an existing table, so
    # the vocabulary is enforced by `http.problems()` and by an audit-side
    # check instead. Recorded here so the omission is a decision, not an
    # oversight.
    if _index(con, "ix_source_access", "source(access_state)"):
        changed.append("ix_source_access")

    # ---- item: duplicate bookkeeping -------------------------------------
    if _add(con, "item", "dedup_of", "INTEGER REFERENCES item(id) ON DELETE SET NULL"):
        changed.append("item.dedup_of")
    if _add(con, "item", "canonical_id", "INTEGER REFERENCES item(id) ON DELETE SET NULL"):
        changed.append("item.canonical_id")
    if _index(con, "ix_item_canonical", "item(canonical_id)"):
        changed.append("ix_item_canonical")

    # ---- evidence: connect graded assessment to the corpus ---------------
    if _add(con, "evidence", "class_id", "TEXT REFERENCES bug_class(id) ON DELETE SET NULL"):
        changed.append("evidence.class_id")
    if _add(con, "evidence", "item_id", "INTEGER REFERENCES item(id) ON DELETE SET NULL"):
        changed.append("evidence.item_id")
    if _add(con, "evidence", "exam_id", "TEXT"):
        changed.append("evidence.exam_id")
    if _index(con, "ix_evidence_exam", "evidence(exam_id)"):
        changed.append("ix_evidence_exam")
    if _index(con, "ix_evidence_class", "evidence(class_id)"):
        changed.append("ix_evidence_class")

    # ---- backfill: never claim a fetch that did not happen ---------------
    n = con.execute(
        "UPDATE source SET access_state='UNVERIFIED' "
        "WHERE access_state IS NULL OR access_state NOT IN (%s)"
        % ",".join("?" * len(http.ACCESS_STATES)),
        tuple(http.ACCESS_STATES)).rowcount
    if n:
        changed.append(f"backfill source.access_state ({n} rows)")

    # Annotate rows that predate the migration, ONCE. `access_detail IS NULL`
    # is the guard that makes this idempotent; without it this line re-fires on
    # every open and reports 473 rows "changed" forever.
    n2 = con.execute(
        "UPDATE source SET access_detail='never fetched: pre-migration row, "
        "http_status was NULL' WHERE access_state='UNVERIFIED' "
        "AND access_checked_at IS NULL AND http_status IS NULL "
        "AND access_detail IS NULL").rowcount
    if n2:
        changed.append(f"annotate never-fetched sources ({n2} rows)")

    tables = {
     "dedup_fingerprint": "CREATE TABLE IF NOT EXISTS dedup_fingerprint (id INTEGER PRIMARY KEY, item_id INTEGER REFERENCES item(id) ON DELETE CASCADE, class_id TEXT REFERENCES bug_class(id) ON DELETE SET NULL, fingerprint TEXT NOT NULL, normalized TEXT NOT NULL, polarity INTEGER NOT NULL DEFAULT 0, scope TEXT, version TEXT, preconditions TEXT, created_at TEXT NOT NULL)",
     "canonical_group": "CREATE TABLE IF NOT EXISTS canonical_group (id INTEGER PRIMARY KEY, group_key TEXT NOT NULL UNIQUE, canonical_item_id INTEGER REFERENCES item(id) ON DELETE SET NULL, status TEXT NOT NULL DEFAULT 'PENDING_REVIEW', created_at TEXT NOT NULL, updated_at TEXT NOT NULL)",
     "item_group": "CREATE TABLE IF NOT EXISTS item_group (item_id INTEGER NOT NULL REFERENCES item(id) ON DELETE CASCADE, group_id INTEGER NOT NULL REFERENCES canonical_group(id) ON DELETE CASCADE, role TEXT NOT NULL DEFAULT 'member', PRIMARY KEY(item_id,group_id))",
     "merge_proposal": "CREATE TABLE IF NOT EXISTS merge_proposal (id INTEGER PRIMARY KEY, proposal_key TEXT NOT NULL UNIQUE, group_id INTEGER REFERENCES canonical_group(id) ON DELETE SET NULL, item_ids TEXT NOT NULL, relationship TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING_REVIEW', mode TEXT NOT NULL DEFAULT 'PROPOSE', rationale TEXT, reviewer TEXT, created_at TEXT NOT NULL, reviewed_at TEXT, applied_at TEXT)",
    }
    def _exists(t): return con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(t,)).fetchone() is not None
    for t,ddl in tables.items():
        if not _exists(t):
            con.execute(ddl); changed.append(t)
    con.commit()
    return {"changed": changed, "store": str(config.DB_PATH)}


if __name__ == "__main__":
    con = sqlite3.connect(str(config.db_path()))
    print(migrate(con))
    con.close()