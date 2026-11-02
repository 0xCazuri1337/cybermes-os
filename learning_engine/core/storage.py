"""THE LEGACY STORAGE ENTRY POINT — now a REDIRECT to the canonical store.

MEASURED 2026-10-31 (db-layer audit): this module opened
`learning_engine/memory/learning.db` -- a SECOND SQLite file -- WRITABLY.
That file is the retired learning store; the canonical store is
`db/wks.db` (`wks.config.db_path()`), and `learning_engine.engine
.open_canonical()` already opened it.

Two databases means two WALs, two failure modes, and a cross-file
consistency problem for a system whose purpose is surviving a crash
mid-run. The mission asked this question explicitly -- "is learning.db a
genuine secondary source of truth, a legacy database, a derived retrieval
store, a disposable cache, or an unused artifact?" -- and the answer is
now unambiguous:

    learning.db is a LEGACY database. Its 10 lessons and 7 findings were
    migrated into the canonical store by `learning_engine.engine
    .migrate_legacy`, which now accounts for EVERY row it reads. The file
    itself is retained, because nothing is deleted.

So this module no longer opens it at all. `connect()` returns a handle on
the CANONICAL store, with the learning schema applied -- the same handle
`learning_engine.engine.open_canonical()` returns. The legacy file is
read-only history, and nothing in the running system writes to it.

The module name and the `connect()` signature are preserved: five callers
(`analytics/patterns.py`, `ingestion/finding.py`, `ingestion/triage.py`,
`retrieval/search.py`, `scripts/audit_learning_engine.py`) import them, and
they should not have to change to get the canonical store.

WHAT A CALLER MUST KNOW
------------------------
The legacy schema (`lessons`, `findings` with their own column names) is
NOT the canonical schema (`lesson`, `finding`, plus the learning engine's
own tables). A caller that queries `SELECT * FROM lessons` against this
handle will now fail with "no such table: lessons" -- which is the correct
outcome, because that table is retired and a live query against it would
have been reading the SECOND source of truth this module used to provide.
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import DB_PATH  # noqa: F401,E402  (kept for back-compat)

LEGACY_DB_PATH = DB_PATH


def connect():
    """Return a handle on the CANONICAL store, with the learning schema.

    Replaces the old behaviour of opening `learning_engine/memory/
    learning.db` writable. See the module docstring for why.
    """
    # Imported lazily, and by ABSOLUTE PATH rather than by package name.
    #
    # MEASURED 2026-10-31: this module inserts `learning_engine/` onto
    # sys.path at import time so that `from core.config import ...` works
    # for callers that add `learning_engine/` rather than the project root.
    # That makes the package name `learning_engine` unimportable from here
    # when the project root is not on sys.path -- and the callers that need
    # this module are exactly those callers.
    #
    # The canonical store is reached through `wks.store` (which needs the
    # project root on sys.path) plus this package's own schema, so both
    # roots are added explicitly.
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    project_root = os.path.dirname(here)
    for p in (project_root, here):
        if p not in sys.path:
            sys.path.insert(0, p)
    from learning_engine import engine
    return engine.open_canonical()


def legacy_path() -> str:
    """The path of the retired database. Read-only history, never opened."""
    return DB_PATH
