"""Snapshot-safe corpus audits.

MEASURED (audit 2026-10-02): the corpus grew 472 -> 501 items *while an audit
was reading it*. Two enabled cron loops were ingesting on 20- and 180-minute
schedules, so any count published from the live file was stale or inconsistent
depending on when it was read -- and one pass reported `items_total: 471` while
a later pass in the same audit reported 501. Two numbers, both "correct",
neither citable.

Two mechanisms, because both are needed:

  * `snapshot()` -- a consistent READ of the live db inside one transaction.
    `BEGIN DEFERRED` alone is not enough: a deferred transaction only starts
    reading at the first SELECT, so two passes separated by a writer each see a
    different world. `snapshot()` takes the read lock at open time, so every
    pass against one snapshot sees the same rows.

  * `frozen_copy()` -- a byte copy taken through sqlite's online backup API
    (never `cp`: the db is in WAL mode and a file copy can tear). An audit that
    must survive a concurrent writer, or must be reproducible later, reads the
    copy instead of the live file.

Audit callers should use `snapshot()`. `frozen_copy()` is for publishing a
metric that must stay true after the fact.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Any

from wks import config

_SNAPSHOTS: dict[str, sqlite3.Connection] = {}


def _tables(con: sqlite3.Connection) -> int:
    return con.execute(
        "SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]


def _fingerprint(con: sqlite3.Connection) -> dict[str, Any]:
    """Cheap change-detector. Two passes can compare these to prove they read
    the same world, or to prove the corpus moved under them."""
    def n(sql: str) -> int:
        try:
            return con.execute(sql).fetchone()[0]
        except sqlite3.Error:
            return -1
    return {
        "item": n("SELECT count(*) FROM item"),
        "quality": n("SELECT count(*) FROM quality"),
        "source": n("SELECT count(*) FROM source"),
        "item_source": n("SELECT count(*) FROM item_source"),
        "bug_class": n("SELECT count(*) FROM bug_class"),
        "fp_case": n("SELECT count(*) FROM fp_case"),
        "chain": n("SELECT count(*) FROM chain"),
        "conflict": n("SELECT count(*) FROM conflict"),
        "evidence": n("SELECT count(*) FROM evidence"),
    }


def snapshot(path: str | None = None, *, label: str = "default") -> sqlite3.Connection:
    """A read-only connection holding a CONSISTENT view of the store.

    `PRAGMA query_only` makes an accidental write fail loudly instead of
    corrupting a corpus the audit promised not to touch. The read transaction is
    opened immediately, before any SELECT, so every later pass sees the same
    rows even if a writer commits in between.
    """
    key = f"{path or config.DB_PATH}|{label}"
    if key in _SNAPSHOTS:
        return _SNAPSHOTS[key]
    p = path or str(config.db_path())
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("BEGIN")          # take the read snapshot NOW, not on first SELECT
    con.execute("SELECT count(*) FROM sqlite_master LIMIT 1")
    _SNAPSHOTS[key] = con
    return con


def release(label: str | None = None) -> None:
    """Close snapshots. An audit that opens many must not leak read locks --
    a leaked read lock blocks the very writers it was meant to observe."""
    for key, con in list(_SNAPSHOTS.items()):
        if label is None or key.endswith(f"|{label}"):
            try:
                con.rollback()
                con.close()
            except sqlite3.Error:
                pass
            _SNAPSHOTS.pop(key, None)


def frozen_copy(path: str | None = None, dest_dir: str | None = None) -> dict[str, Any]:
    """Copy the store through sqlite's online backup API.

    Never `shutil.copy`: the db runs in WAL mode, so the .db file without its
    -wal is not the database, and copying while a writer is active can capture a
    torn state. The backup API produces a consistent, self-contained file.

    Returns the destination, a sha256 prefix, and the row fingerprints, so an
    audit can publish a number and the evidence that supported it together.
    """
    p = path or str(config.db_path())
    d = dest_dir or tempfile.mkdtemp(prefix="wks-audit-")
    os.makedirs(d, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(d, f"wks-audit-{stamp}.db")

    src = sqlite3.connect(p)
    before = _fingerprint(src)
    tables = _tables(src)
    out = sqlite3.connect(dest)
    with out:
        src.backup(out)
    out.close()
    src.close()

    chk = sqlite3.connect(f"file:{dest}?mode=ro", uri=True)
    integrity = chk.execute("PRAGMA integrity_check").fetchone()[0]
    after = _fingerprint(chk)
    copied_tables = _tables(chk)
    chk.close()

    return {
        "path": dest,
        "bytes": os.path.getsize(dest),
        "sha256": hashlib.sha256(open(dest, "rb").read()).hexdigest()[:32],
        "integrity_check": integrity,
        "tables_source": tables,
        "tables_copy": copied_tables,
        "fingerprint": before,
        "fingerprint_copy": after,
        # If these differ, the copy is not a faithful snapshot and any number
        # read from it is unciteable. Checked, not assumed.
        "fingerprint_matches": before == after,
    }


def read_frozen(info: dict[str, Any]) -> sqlite3.Connection:
    """Open a frozen copy read-only for a multi-pass audit."""
    con = sqlite3.connect(f"file:{info['path']}?mode=ro", uri=True,
                         check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA query_only=ON")
    con.execute("BEGIN")
    return con


def moved_under_audit(first: dict[str, Any], second: dict[str, Any]) -> dict[str, Any]:
    """Compare two fingerprints. Returns the deltas, or an empty dict.

    An audit that takes a final fingerprint and finds a delta did not read one
    world -- it read two, and every number spanning the change is suspect.
    """
    delta = {k: (first.get(k), second.get(k))
             for k in set(first) | set(second)
             if first.get(k) != second.get(k)}
    return delta


def problems() -> list[str]:
    bad = []
    if not os.path.exists(str(config.db_path())):
        bad.append(f"no store at {config.db_path()}")
    return bad


def describe() -> dict[str, Any]:
    p = str(config.db_path())
    out: dict[str, Any] = {"store": p, "exists": os.path.exists(p)}
    if not out["exists"]:
        return out
    con = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
    out["journal_mode"] = con.execute("PRAGMA journal_mode").fetchone()[0]
    out["tables"] = _tables(con)
    out["fingerprint"] = _fingerprint(con)
    con.close()
    return out


if __name__ == "__main__":  # pragma: no cover - operator convenience
    import json
    print(json.dumps({"problems": problems(), **describe()}, indent=1, default=str))