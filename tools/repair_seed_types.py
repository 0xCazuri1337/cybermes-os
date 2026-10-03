"""Repair the source_type/authority regression from the dual-domain re-seed.

Measured damage (see `wks/store.py::upsert_source` for the full writeup):

    11 pre-existing sources had `source_type` overwritten by the coarse
    declaration in `taxonomy._SEED`, and 2 of those LOST authority tier
    (1 -> 2), which would lower `source_credibility` on the next gate run.

Repair restores the exact pre-seed values from the snapshot taken before any
seeding, then re-runs the seed to PROVE the fix: the monotonic-authority rule
in `upsert_source` must leave the restored rows untouched. Without that second
step this would be a repair that silently re-breaks on the next taxonomy run.

Snapshots are matched by URL, never by rowid, and a URL that is not in the
snapshot is never touched: a source created since the snapshot has no correct
prior value, and inventing one is worse than leaving it alone.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

SNAPSHOT = Path(r"C:\Users\Administrator\AppData\Local\hermes\cache\scratch"
                r"\wks-preseed.db")
DB = Path("db/wks.db")


def main() -> int:
    if not SNAPSHOT.exists():
        print(f"FAIL: no pre-seed snapshot at {SNAPSHOT}. Refusing to guess "
              f"prior values.", file=sys.stderr)
        return 2

    snap = sqlite3.connect(str(SNAPSHOT))
    con = sqlite3.connect(str(DB))
    con.row_factory = sqlite3.Row

    prior = {r[0]: (r[1], r[2]) for r in snap.execute(
        "SELECT url, source_type, authority FROM source")}

    repaired = []
    for r in con.execute("SELECT id, url, source_type, authority FROM source"):
        if r["url"] not in prior:
            continue
        ptype, pauth = prior[r["url"]]
        if r["source_type"] != ptype or r["authority"] != pauth:
            con.execute(
                "UPDATE source SET source_type=?, authority=? WHERE id=?",
                (ptype, pauth, r["id"]))
            repaired.append((r["url"], ptype, pauth,
                             r["source_type"], r["authority"]))

    con.commit()
    print(f"restored {len(repaired)} source row(s) to their pre-seed values:")
    for url, ptype, pauth, old_t, old_a in repaired:
        print(f"  {old_t}({old_a}) -> {ptype}({pauth})  {url[:70]}")

    # PROVE the fix: re-seed and assert nothing regresses a second time.
    from wks import store
    con2 = store.open_db()
    before = {r["url"]: (r["source_type"], r["authority"])
              for r in con2.execute("SELECT url, source_type, authority FROM source")}
    from wks import seed as seeder
    seeder.seed(con2, domain="all")
    con2.commit()
    after = {r["url"]: (r["source_type"], r["authority"])
             for r in con2.execute("SELECT url, source_type, authority FROM source")}
    con2.close()

    demoted = [(u, before[u], after[u]) for u in before
               if after.get(u) and int(after[u][1]) > int(before[u][1])]
    print(f"\nre-seed verification: {len(demoted)} authority demotion(s) "
          f"(must be 0)")
    for d in demoted:
        print(f"  DEMOTED {d[0]}  {d[1]} -> {d[2]}")

    snap.close()
    con.close()
    return 1 if demoted else 0


if __name__ == "__main__":
    raise SystemExit(main())
