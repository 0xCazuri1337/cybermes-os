"""Make R31 checkable: a measurement is invalid if the corpus moved under it.

A verifier that fails because the world changed is indistinguishable from a
broken verifier -- the same trap as a dead filter. So the guard belongs in the
tool, not in a habit.

    python tools/recon_stable_measure.py            # run a measurement safely
    python tools/recon_stable_measure.py --check    # report corpus identity

Usage inside any audit:

    from tools.recon_stable_measure import stable
    with stable() as fp:
        ...  # measure; if another writer lands, this raises on exit
"""
from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import contextmanager

WKS = os.environ.get("WKS_ROOT")
DB = os.path.join(WKS, "db", "wks.db")


def fingerprint() -> dict:
    """Everything that changes when another writer touches the corpus."""
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        g = lambda q: con.execute(q).fetchone()[0]
        return {
            "items_active": g("SELECT count(*) FROM item WHERE status='active'"),
            "items_total": g("SELECT count(*) FROM item"),
            "items_superseded": g(
                "SELECT count(*) FROM item WHERE status='superseded'"),
            "sources": g("SELECT count(*) FROM source"),
            "item_source": g("SELECT count(*) FROM item_source"),
            "max_updated": g("SELECT coalesce(max(updated_at),'') FROM item"),
            # MEASURED: counts alone missed a write that changed only
            # updated_at (a no-op UPDATE that committed fine and left every
            # count identical). The negative control caught it. A writer that
            # edits without adding rows is exactly the case this guard exists
            # for, so mtime is part of the identity.
            "db_mtime_ns": str(os.stat(DB).st_mtime_ns),
        }
    finally:
        con.close()


class CorpusMoved(RuntimeError):
    pass


@contextmanager
def strict():
    """Fail loudly if the corpus changed during the block."""
    before = fingerprint()
    yield before
    after = fingerprint()
    if before != after:
        diff = {k: (before[k], after[k]) for k in before if before[k] != after[k]}
        raise CorpusMoved(
            "the corpus changed while this measurement was being taken, so the "
            f"result describes no single instant. drift: {diff}. Re-run against "
            "a stable tree, or label the result with its snapshot time. "
            "(CONTROL/rules-concurrent-writers.md, R31)")


def main(argv: list[str]) -> int:
    fp = fingerprint()
    if "--check" in argv:
        for k, v in fp.items():
            print(f"{k:18} {v}")
        mtime = os.path.getmtime(DB)
        import datetime
        print(f"{'db mtime':18} "
              f"{datetime.datetime.fromtimestamp(mtime).isoformat()}")
        return 0
    print("corpus identity:", fp)
    print()
    print("wrap any measurement in `with strict():` to be told if another")
    print("writer lands while it runs (R31).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))