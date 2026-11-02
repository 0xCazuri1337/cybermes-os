"""The migration lock must SERIALIZE, and it must not outlive its holder.

THE DEFECT (measured, 2026-10-31)
  `wks/migration_lock.py` takes the lock as a row in a `migration_lock`
  table and releases it in a `finally`. A holder that is KILLED never
  runs its `finally`, so its row survives it -- and the lock then blocks
  every writer in the project forever.

  MEASURED: an eval suite interrupted by the harness left `wks-schema`
  held by pid 6249. That process no longer existed, and the lock row
  stayed. Every subsequent writer failed:

      MigrationLockTimeout: could not acquire the 'wks-schema' migration
      lock within 60s (held by pid:6249 since 2026-10-31T12:38:02+00:00)
      sqlite3.OperationalError: database is locked

  which took out the taxonomy generator AND the dispatch-reachability
  suite in the same run. A lock that outlives its holder serializes
  nothing; it just stops the project.

WHAT THIS SUITE PINS
  1. A LIVE holder blocks a second acquirer (the lock still serializes).
  2. A DEAD holder is reclaimed, and the reclamation is reported.
  3. The reclaimed lock is actually usable afterwards.
  4. A holder with an UNKNOWN pid (None, or another namespace) is NOT
     reclaimed -- an invisible holder must be waited out, not stolen.
  5. `lock_status` distinguishes live from stale.

Run: python eval/test_migration_lock.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import os
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import migration_lock as ml  # noqa: E402

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def fresh_db() -> sqlite3.Connection:
    con = sqlite3.connect(":memory:")
    con.row_factory = sqlite3.Row
    ml._ensure_table(con)
    return con


def pid_alive() -> int:
    """A pid that is guaranteed not to be running."""
    # Fork a child, wait for it to exit, and use its pid: it is dead and
    # its number cannot be reused while we hold the reference.
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    return pid


def main() -> int:
    print("=== migration lock: serialize, and never outlive the holder ===")

    # --- 1. A LIVE holder blocks a second acquirer -----------------------
    con = fresh_db()
    with ml.migration_lock(con, name="t1", timeout=5):
        blocked = False
        try:
            with ml.migration_lock(con, name="t1", timeout=1):
                pass
        except ml.MigrationLockTimeout:
            blocked = True
    check("a LIVE holder blocks a second acquirer", blocked,
          "the second acquirer got the lock while the first held it")
    con.close()

    # --- 2. A DEAD holder is reclaimed, and it is reported ---------------
    con = fresh_db()
    dead = pid_alive()
    con.execute(
        "INSERT INTO migration_lock(name,holder,acquired_at,pid) VALUES (?,?,?,?)",
        ("t2", f"pid:{dead}", "2026-01-01T00:00:00+00:00", dead))
    con.commit()
    acquired = False
    new_pid = None
    with ml.migration_lock(con, name="t2", timeout=10):
        acquired = True
        # The holder row is read INSIDE the block: the lock is released in
        # the `finally`, so after the block the row is correctly absent and
        # reading it then would prove nothing.
        row = con.execute(
            "SELECT holder, pid FROM migration_lock WHERE name='t2'").fetchone()
        new_pid = row["pid"] if row else None
    check("a DEAD holder is reclaimed", acquired,
          "the abandoned lock still blocked the acquirer")
    check("the reclaimed lock names the NEW holder",
          new_pid == os.getpid(),
          f"holder pid={new_pid}, expected {os.getpid()}")
    check("the lock is RELEASED on exit",
          con.execute(
              "SELECT COUNT(*) c FROM migration_lock WHERE name='t2'"
          ).fetchone()["c"] == 0)
    con.close()

    # --- 3. The reclaimed lock is usable afterwards ----------------------
    con = fresh_db()
    con.execute(
        "INSERT INTO migration_lock(name,holder,acquired_at,pid) VALUES (?,?,?,?)",
        ("t3", f"pid:{dead}", "2026-01-01T00:00:00+00:00", dead))
    con.commit()
    for _ in range(3):
        with ml.migration_lock(con, name="t3", timeout=10):
            pass
    check("the reclaimed lock is usable repeatedly", True)
    con.close()

    # --- 4. An UNKNOWN holder is NOT reclaimed --------------------------
    con = fresh_db()
    con.execute(
        "INSERT INTO migration_lock(name,holder,acquired_at,pid) VALUES (?,?,?,?)",
        ("t4", "pid:unknown", "2026-01-01T00:00:00+00:00", None))
    con.commit()
    blocked = False
    try:
        with ml.migration_lock(con, name="t4", timeout=1):
            pass
    except ml.MigrationLockTimeout:
        blocked = True
    check("an UNKNOWN holder is NOT reclaimed", blocked,
          "a lock whose holder cannot be seen was stolen")
    row = con.execute(
        "SELECT holder FROM migration_lock WHERE name='t4'").fetchone()
    check("the unknown holder's row survives the attempt",
          row is not None and row["holder"] == "pid:unknown")
    con.close()

    # --- 5. lock_status distinguishes live from stale --------------------
    con = fresh_db()
    con.execute(
        "INSERT INTO migration_lock(name,holder,acquired_at,pid) VALUES (?,?,?,?)",
        ("stale", f"pid:{dead}", "2026-01-01T00:00:00+00:00", dead))
    con.execute(
        "INSERT INTO migration_lock(name,holder,acquired_at,pid) VALUES (?,?,?,?)",
        ("live", f"pid:{os.getpid()}", "2026-01-01T00:00:00+00:00",
         os.getpid()))
    con.commit()
    st = ml.lock_status(con)
    check("lock_status reports the stale lock as stale",
          [e["name"] for e in st.get("stale", [])] == ["stale"],
          str(st))
    check("lock_status reports the live lock as held",
          [e["name"] for e in st.get("locks", [])] == ["live"], str(st))
    con.close()

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL MIGRATION LOCK CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
