"""Projection manifest: tracks generated Markdown projections of the corpus.

Additive. One row per (class_id, artifact_type) logical artifact. The primary
key on (class_id, artifact_type) is the uniqueness constraint: no duplicate
rows for the same logical artifact.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import ownership


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


TABLE = "projection_manifest"


def ensure_table(con: sqlite3.Connection) -> None:
    """Create the projection_manifest table if absent (idempotent)."""
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {TABLE} (
          class_id          TEXT NOT NULL REFERENCES bug_class(id) ON DELETE CASCADE,
          artifact_type     TEXT NOT NULL,
          relative_path     TEXT NOT NULL,
          source_digest     TEXT,
          content_sha256    TEXT,
          generator_version TEXT,
          generated_at      TEXT NOT NULL,
          PRIMARY KEY (class_id, artifact_type)
        )""")
    con.execute(
        f"CREATE INDEX IF NOT EXISTS ix_projection_manifest_type "
        f"ON {TABLE}(artifact_type)")
    con.commit()


@ownership.as_owner(ownership.WKS)
def upsert(
    con: sqlite3.Connection,
    class_id: str,
    artifact_type: str,
    relative_path: str,
    *,
    source_digest: str | None = None,
    content_sha256: str | None = None,
    generator_version: str | None = None,
    generated_at: str | None = None,
) -> None:
    """Insert or update the manifest row for a logical artifact."""
    ensure_table(con)
    ts = generated_at or _now()
    con.execute(
        f"""INSERT INTO {TABLE}
               (class_id, artifact_type, relative_path, source_digest,
                content_sha256, generator_version, generated_at)
           VALUES (?,?,?,?,?,?,?)
           ON CONFLICT(class_id, artifact_type) DO UPDATE SET
               relative_path=excluded.relative_path,
               source_digest=excluded.source_digest,
               content_sha256=excluded.content_sha256,
               generator_version=excluded.generator_version,
               generated_at=excluded.generated_at""",
        (class_id, artifact_type, relative_path, source_digest,
         content_sha256, generator_version, ts),
    )
    con.commit()


def get(con: sqlite3.Connection, class_id: str,
        artifact_type: str) -> sqlite3.Row | None:
    """Return the manifest row for one logical artifact, or None."""
    try:
        return con.execute(
            f"SELECT * FROM {TABLE} WHERE class_id=? AND artifact_type=?",
            (class_id, artifact_type)).fetchone()
    except sqlite3.OperationalError:
        ensure_table(con)
        return con.execute(
            f"SELECT * FROM {TABLE} WHERE class_id=? AND artifact_type=?",
            (class_id, artifact_type)).fetchone()


def list_for_class(con: sqlite3.Connection, class_id: str) -> list[sqlite3.Row]:
    """Return all manifest rows for a class."""
    try:
        return con.execute(
            f"SELECT * FROM {TABLE} WHERE class_id=? ORDER BY artifact_type",
            (class_id,)).fetchall()
    except sqlite3.OperationalError:
        ensure_table(con)
        return con.execute(
            f"SELECT * FROM {TABLE} WHERE class_id=? ORDER BY artifact_type",
            (class_id,)).fetchall()


def all_rows(con: sqlite3.Connection) -> list[sqlite3.Row]:
    ensure_table(con)
    return con.execute(
        f"SELECT * FROM {TABLE} ORDER BY class_id, artifact_type").fetchall()
