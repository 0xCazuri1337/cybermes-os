"""Did the T30 vocabulary edit damage any OTHER class?  Per-class diff.

A corpus-level total is not enough: +5 items in api_trust can hide -3 in oauth
and +8 somewhere else.  This opens the pre-change BACKUP read-only and diffs
every class's state counts against the live db, so the blast radius of a
shared-gate edit is measured rather than assumed.

Run:  python tools/w12_regression_diff.py <backup.db>
Exit non-zero if any class other than the expected one moved.
"""
import os
import sqlite3
import sys

WKS = os.environ.get("WKS_ROOT", "C:/Users/Administrator/.hermes/cyber")
sys.path.insert(0, WKS)

from wks import store  # noqa: E402

EXPECTED_MOVES = {"api_trust"}


def per_class(path: str) -> dict[str, dict[str, int]]:
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    out: dict[str, dict[str, int]] = {}
    for r in con.execute(
        """SELECT i.class_id cid, q.validation_state vs, COUNT(*) n
           FROM item i JOIN quality q ON q.item_id=i.id
           GROUP BY i.class_id, q.validation_state"""
    ):
        out.setdefault(r["cid"], {})[r["vs"]] = r["n"]
    con.close()
    return out


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    backup = sys.argv[1]
    live = str(store.config.db_path()) if hasattr(store, "config") else None
    from wks import config
    live = str(config.db_path())

    before, after = per_class(backup), per_class(live)
    classes = sorted(set(before) | set(after))
    moved = []
    for cid in classes:
        b, a = before.get(cid, {}), after.get(cid, {})
        delta = {k: a.get(k, 0) - b.get(k, 0) for k in set(b) | set(a)}
        delta = {k: v for k, v in delta.items() if v}
        if delta:
            moved.append((cid, delta))

    print(f"before: {backup}")
    print(f"after : {live}")
    print(f"classes compared: {len(classes)}   classes MOVED: {len(moved)}\n")
    for cid, delta in moved:
        mark = "expected" if cid in EXPECTED_MOVES else "*** UNEXPECTED ***"
        print(f"  {cid:32s} {str(delta):46s} {mark}")

    unexpected = [c for c, _ in moved if c not in EXPECTED_MOVES]
    tb = sum(d.get("high_confidence", 0) for _, d in moved)
    ta = sum(d.get("high_confidence", 0) for _, d in moved)
    print(f"\ntotal high_confidence movement: {tb}")
    print(f"unexpected classes moved: {len(unexpected)}")
    if unexpected:
        print("ROLLBACK CANDIDATE:", unexpected)
    return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())