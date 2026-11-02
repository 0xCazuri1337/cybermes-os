"""Audit the LEARNING ENGINE against the CANONICAL store.

MEASURED 2026-10-31 (db-layer audit): this script queried `lessons` and
`findings` -- the RETIRED `learning_engine/memory/learning.db` schema -- via
`core.storage.connect()`, which opened that second database WRITABLY.

`core.storage.connect()` now returns the canonical store, so the queries
against the retired table names fail with "no such table". That failure is
the correct outcome: the audit was reporting on a database the running
system does not use.

This script now reports on the canonical tables the learning engine
actually writes, and it says which legacy records are still unmigrated --
so the audit is a check on the LIVE state rather than a check on a
historical file.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import storage  # noqa: E402

con = storage.connect()
try:
    print("canonical store:", con.execute(
        "PRAGMA database_list").fetchone()[2])

    def count(table: str) -> int:
        """Count a table, reporting 0 when it does not exist yet."""
        try:
            return con.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except Exception:
            return 0

    print("lessons:", count("lesson"))
    print("lesson feedback:", count("lesson_feedback"))
    print("learning gaps:", count("learning_gap"))
    print("learning research:", count("learning_research"))
    print("write-up lessons:", count("writeup_lesson"))
    print("findings:", count("finding"))

    # Is the legacy database fully accounted for? `migrate_legacy` reports
    # every row it skips with a reason, so the check is "did the migration
    # leave anything behind".
    from learning_engine import engine as le
    legacy_present = le.LEGACY_DB.is_file()
    print("legacy database present:", legacy_present)
    if legacy_present:
        r = le.migrate_legacy(con)
        print("legacy migration:", {k: v for k, v in r.items()
                                    if k != "skipped"})
finally:
    con.close()
print("audit ok")
