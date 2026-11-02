"""MIGRATION SERIALIZATION.

MEASURED 2026-10-31 (db-layer audit): there was NO file lock, no advisory
lock, no migration-lock table and no `BEGIN IMMEDIATE` anywhere in the
project. Every schema application and every migration was unprotected:

    * `wks.store.init` ran `con.executescript(SCHEMA)` with no lock.
    * `orch.store.open_db` ran BOTH schema scripts with no lock.
    * `wks.migrate.migrate` ran its ALTER TABLE / UPDATE steps with no
      lock.

Two consequences, both real:

  1. Two processes opening the database at the same time both ran the
     schema scripts. `executescript` is not atomic with respect to
     concurrent DDL, and SQLite's "table already exists" errors from a
     racing `CREATE TABLE IF NOT EXISTS` are the visible symptom.

  2. Two migrations running at once could interleave their ALTER TABLE
     steps. `ALTER TABLE ADD COLUMN` is not safely repeatable under a
     race: both processes can see the column as absent and both try to
     add it.

THE LOCK
--------
A row in a dedicated `migration_lock` table, taken with a conditional
INSERT and released in a `finally`. The row is the lock because SQLite
serializes writes: only one connection can win the INSERT.

`busy_timeout` does the waiting. A process that finds the lock held does
not fail fast -- it waits, because the holder is a peer doing legitimate
work, not an error. The timeout is bounded and the failure is explicit.

This is the same shape as `orch.store.claim()` on a task: a conditional
UPDATE is the whole concurrency control, because SQLite serializes the
write and the loser sees zero rows changed. Here the loser retries.

HOW IT INTERACTS WITH THE AUTHORIZER
-------------------------------------
`migration_lock` is a KNOWLEDGE table -- it belongs to the schema owner,
not to either operational layer, because it guards the shared schema
itself. The migration paths run before any owner restriction is
installed, so the lock is always reachable by the code that needs it.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from typing import Any, Iterator

LOCK_TABLE = "migration_lock"

# How long to wait for a peer to finish migrating. The migration itself is
# sub-second on a healthy database; a minute is generous and bounded.
DEFAULT_TIMEOUT_SECONDS = 60.0

# How long to wait between attempts.
POLL_INTERVAL_SECONDS = 0.25


def _ensure_table(con: sqlite3.Connection) -> None:
    """Create the lock table if absent.

    DDL is idempotent and the table is tiny. It is created outside the
    lock itself, which is fine: `CREATE TABLE IF NOT EXISTS` is safe
    under concurrency, and the lock protects the CONTENT of the table,
    not the existence of the table.
    """
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {LOCK_TABLE} (
          name       TEXT PRIMARY KEY,
          holder     TEXT NOT NULL,
          acquired_at TEXT NOT NULL,
          pid        INTEGER
        )""")


class MigrationLockTimeout(RuntimeError):
    """The migration lock could not be acquired within the timeout."""


def _pid_alive(pid: int | None) -> bool:
    """Is this pid still running?

    `pid` is None for a lock row written by an older version that did not
    record it, and for a holder in another namespace. Both are treated as
    ALIVE, because reclaiming a lock whose holder we cannot see would let
    two migrations run at once -- which is the failure the lock exists to
    prevent. An unknown holder is waited out, not stolen.
    """
    if not pid:
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # The process exists but belongs to another user.
        return True
    except OSError:
        return True
    return True


def _reclaim_if_stale(con: sqlite3.Connection, name: str) -> str | None:
    """Delete an ABANDONED lock row, and say whose it was.

    A holder that has been KILLED never runs its `finally` block, so its
    lock row survives it. MEASURED 2026-10-31: a suite interrupted by the
    harness left `wks-schema` held by a pid that no longer existed, and
    every subsequent writer -- including the taxonomy generator and the
    dispatch-reachability suite -- failed with "could not acquire the
    migration lock" or "database is locked" for as long as the row
    remained. The lock's whole purpose is to SERIALIZE, and a lock that
    outlives its holder serializes nothing: it just blocks the project
    permanently.

    So: if the recorded pid is not running, the holder is gone and the row
    is abandoned. Reclaim it, and record what was reclaimed so the
    reclamation is visible rather than silent.

    The reclaim is a conditional DELETE on the exact row we inspected, so
    two waiters cannot both delete it: SQLite serializes the write and
    the loser sees zero rows changed.
    """
    row = con.execute(
        f"SELECT holder, acquired_at, pid FROM {LOCK_TABLE} WHERE name=?",
        (name,)).fetchone()
    if row is None:
        return None
    if _pid_alive(row["pid"]):
        return None
    cur = con.execute(
        f"DELETE FROM {LOCK_TABLE} WHERE name=? AND holder=? AND pid IS ?",
        (name, row["holder"], row["pid"]))
    if cur.rowcount:
        con.commit()
        return f"{row['holder']} (pid {row['pid']}, since {row['acquired_at']})"
    return None


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def migration_lock(con: sqlite3.Connection, *,
                   name: str = "schema",
                   timeout: float = DEFAULT_TIMEOUT_SECONDS) -> Iterator[None]:
    """Hold the migration lock for the duration of the block.

    Raises MigrationLockTimeout if the lock cannot be acquired within
    `timeout`. The lock is ALWAYS released, including when the body
    raises -- a migration that crashed must not leave the database
    permanently un-migratable.
    """
    _ensure_table(con)
    holder = f"pid:{os.getpid()}"
    deadline = time.monotonic() + timeout
    acquired = False
    while True:
        try:
            cur = con.execute(
                f"INSERT OR IGNORE INTO {LOCK_TABLE}(name, holder, acquired_at, pid)"
                f" VALUES (?,?,?,?)",
                (name, holder, _now(), os.getpid()))
            if cur.rowcount == 1:
                acquired = True
                break
        except sqlite3.OperationalError:
            # A concurrent writer held the database lock; the busy timeout
            # has already waited for it. Retry until the deadline.
            pass
        # The holder may have been killed without running its `finally`.
        # An abandoned lock must not block the project forever.
        try:
            reclaimed = _reclaim_if_stale(con, name)
        except sqlite3.OperationalError:
            reclaimed = None
        if reclaimed:
            print(f"reclaimed abandoned migration lock {name!r} from "
                  f"{reclaimed}", file=sys.stderr)
            continue
        if time.monotonic() >= deadline:
            row = con.execute(
                f"SELECT holder, acquired_at FROM {LOCK_TABLE} WHERE name=?",
                (name,)).fetchone()
            held = f" (held by {row['holder']} since {row['acquired_at']})" if row else ""
            raise MigrationLockTimeout(
                f"could not acquire the {name!r} migration lock within "
                f"{timeout:g}s{held}")
        time.sleep(POLL_INTERVAL_SECONDS)
    try:
        yield
    finally:
        if acquired:
            try:
                con.execute(f"DELETE FROM {LOCK_TABLE} WHERE name=? AND holder=?",
                            (name, holder))
                con.commit()
            except sqlite3.Error:
                # A failed release must not mask the body's own exception.
                # The lock row carries its holder and acquisition time, so a
                # stale row is diagnosable.
                pass


def lock_status(con: sqlite3.Connection) -> dict[str, Any]:
    """Report whether the migration lock is currently held.

    A row whose holder is gone is reported as `stale`, not `held`: the
    difference matters because a stale row blocks every writer until it is
    reclaimed, and an operator reading "held" has no way to tell a live
    peer from a dead one.
    """
    try:
        _ensure_table(con)
        rows = con.execute(
            f"SELECT name, holder, acquired_at, pid FROM {LOCK_TABLE}").fetchall()
    except sqlite3.Error as e:
        return {"held": None, "error": str(e)}
    locks = []
    stale = []
    for r in rows:
        entry = {"name": r["name"], "holder": r["holder"],
                 "acquired_at": r["acquired_at"], "pid": r["pid"]}
        if _pid_alive(r["pid"]):
            locks.append(entry)
        else:
            stale.append(entry)
    return {
        "held": bool(locks),
        "locks": locks,
        "stale": stale,
    }
