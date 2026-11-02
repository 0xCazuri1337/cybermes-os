"""Open the Cyber db READ-ONLY, or give a sandboxed COPY.

MEASURED INCIDENT (2026-10-02, recon mastery cycle): a subagent briefed
"read-only against the db" ran

    sqlite3.connect('db/wks.db')            # relative path!
    DELETE FROM item_source WHERE item_id IN (SELECT id FROM item
                                               WHERE class_id='idor')

against the LIVE corpus, intending to point at a sandbox. A relative path
silently resolves against the process CWD, and `connect()` on a writable path
creates or MUTATES the file — sqlite3 does not refuse. Five `ldap_enum` rows
were flipped to `superseded`. No rows were lost and the change was reverted by
diffing against the pre-existing snapshot, but a child probed the maturity
gate on live data it was told not to touch.

A brief saying "read-only" is not a control. This module is.

    from wks.readonly import ro, sandbox
    con = ro()                       # live db, mode=ro, verified
    con, path = sandbox()            # private COPY, free to mutate

    python -m wks.readonly ro        # prove the live db refuses a write
    python -m wks.readonly sandbox   # create a throwaway copy, print its path

Why `mode=ro` and not a SELECT-only discipline: sqlite3 in `ro` mode raises
`sqlite3.OperationalError: attempt to write a readonly database` on the first
write, so the failure is loud and immediate instead of silent and permanent.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile

# A writable copy is still a copy: never let sandbox() point at WKS_ROOT.
FORBIDDEN_SUBSTR = ("\\.hermes\\\\cyber", "/.hermes/cyber")


def db_path() -> str:
    root = os.environ.get("WKS_ROOT")
    if not root:
        raise SystemExit("WKS_ROOT is not set; refusing to guess the corpus path")
    path = os.path.join(root, "db", "wks.db")
    if not os.path.exists(path):
        raise SystemExit(f"no db at {path} -- is WKS_ROOT correct?")
    return path


def ro(path: str | None = None) -> sqlite3.Connection:
    """Live db opened `mode=ro`. Any write raises instead of landing."""
    path = path or db_path()
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    return con


def sandbox(path: str | None = None) -> tuple[sqlite3.Connection, str]:
    """A private, writable COPY. Returns (connection, path).

    MEASURED: the destination used to be a FIXED path
    (`<temp>/wks_sandbox/wks.db`), so two runs overlapping -- a test suite and
    a probe, or a retry -- deleted and rewrote each other's copy mid-flight.
    `eval/test_wks_relevance.py` failed intermittently on
    "OFF_CLASS_TOPIC persists into quality.gate_reasons" for exactly this
    reason, and an intermittent failure in a gate test is worse than no test:
    it teaches the operator to re-run until green.

    The path is now unique per call, so concurrent sandboxes cannot collide.
    """
    src = path or db_path()
    dst_dir = tempfile.mkdtemp(prefix="wks_sandbox_")
    dst = os.path.join(dst_dir, "wks.db")
    for ext in ("-wal", "-shm"):
        side = src + ext
        if os.path.exists(side):
            shutil.copy2(side, dst + ext)
    shutil.copy2(src, dst)
    con = sqlite3.connect(dst)
    con.row_factory = sqlite3.Row
    # MEASURED 2026-10-31: this connection did NOT enable foreign keys.
    # SQLite defaults `foreign_keys` to OFF per connection, so the schema's
    # `ON DELETE CASCADE` clauses were INERT in every sandbox. Deleting an
    # item left its `quality` row behind, which is exactly how the five
    # orphaned quality rows (item_id 1959-1963) got into the canonical
    # corpus: a sandbox experiment deleted items and the rows outlived
    # them. `eval/test_wks_integrity_repair.py` has been failing on
    # "quality rows match item rows -- 2091 vs 2086" because of it.
    #
    # A sandbox that silently does not enforce the schema's referential
    # integrity is worse than one that refuses to open: the experiment
    # produces results that cannot be true of the real database.
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("CREATE TABLE IF NOT EXISTS _sandbox_marker "
                "(note TEXT, created TEXT)")
    con.execute("DELETE FROM _sandbox_marker")
    con.execute("INSERT INTO _sandbox_marker VALUES (?,?)",
                ("THIS IS A SANDBOX COPY, NOT THE CORPUS. "
                 "Mutate freely; never copy rows back.",
                 "2026-10-02"))
    con.commit()
    return con, dst


def selftest() -> tuple[bool, list[str]]:
    """Prove the live db REFUSES a write, and that a sandbox accepts one."""
    fails: list[str] = []
    live = ro()
    try:
        live.execute("CREATE TABLE _readonly_probe (x INTEGER)")
        fails.append("FAIL: live db accepted a CREATE TABLE in mode=ro")
    except sqlite3.OperationalError as e:
        if "readonly" not in str(e).lower() and "read-only" not in str(e).lower():
            fails.append(f"FAIL: wrong error for a live write: {e}")
        else:
            print(f"  live db refused a write, as required: {e}")
    finally:
        live.close()

    con, path = sandbox()
    try:
        con.execute("CREATE TABLE _sandbox_probe (x INTEGER)")
        con.execute("INSERT INTO _sandbox_probe VALUES (1)")
        n = con.execute("SELECT count(*) FROM _sandbox_probe").fetchone()[0]
        if n != 1:
            fails.append("FAIL: sandbox write did not persist")
        else:
            print("  sandbox copy accepted a write, as required")
        marker = con.execute("SELECT note FROM _sandbox_marker").fetchone()[0]
        if "SANDBOX" not in marker.upper():
            fails.append("FAIL: sandbox is not marked as a sandbox")
        else:
            print("  sandbox carries its marker")
    finally:
        con.close()

    # The original must be untouched by the probe.
    live2 = ro()
    try:
        live2.execute("SELECT count(*) FROM sqlite_master "
                      "WHERE name='_readonly_probe'").fetchone()[0]
        found = live2.execute(
            "SELECT count(*) FROM sqlite_master WHERE name='_readonly_probe'"
        ).fetchone()[0]
        if found:
            fails.append("FAIL: the probe table exists in the LIVE corpus")
        else:
            print("  live corpus has no probe table: unmodified")
    finally:
        live2.close()

    print(f"wks.readonly selftest: {'PASS' if not fails else 'FAIL'}")
    for f in fails:
        print("  " + f)
    return (not fails), fails


def main(argv: list[str]) -> int:
    if "--selftest" in argv or not argv:
        ok, _ = selftest()
        return 0 if ok else 1
    if argv[0] == "sandbox":
        con, path = sandbox()
        print(path)
        con.close()
        return 0
    print("  ro         open the live db read-only (writes raise)")
    print("  sandbox    create a writable COPY, print its path")
    print("  --selftest prove the live db refuses a write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))