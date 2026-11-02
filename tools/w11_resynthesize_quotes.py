"""T27 — re-source the 20 fabricated-quote items with REAL quotes.

Remedy, not deletion. The 20 `*.fp_rule.auto.derived` items are not junk: each
one wraps a real corpus claim in a useful "reject until distinguished from X"
rule. Only their CITATION was fabricated (`"class <id> evidence: <url>"`).

So this:
  1. snapshots the db (WAL-safe, via SQLite's online backup API),
  2. re-attaches each item to real quotes harvested from the items that
     genuinely cite the same source,
  3. re-runs the quote gate over them,
  4. supersedes anything that still cannot be sourced, so it stops being
     served as knowledge instead of being silently kept as truth.

Deleting outright would destroy usable content; keeping as-is would keep
serving a fabrication. Superseding keeps the row for provenance and removes it
from the active corpus, which is what `quality.py` filters on.

Run:  python tools/w11_resynthesize_quotes.py          (dry run)
      python tools/w11_resynthesize_quotes.py --apply
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402

SYNTHETIC_PREFIX = "class "
SYNTHETIC_MID = " evidence: "


def is_synthetic(q: str | None) -> bool:
    return bool(q) and q.startswith(SYNTHETIC_PREFIX) and SYNTHETIC_MID in q


def snapshot() -> Path:
    """WAL-safe copy. shutil.copy2 on a WAL db yields a corpus missing
    committed rows, which then reports 'unknown class' for classes that
    demonstrably exist."""
    src = store.connect(config.DB_PATH)
    dst = ROOT / "db" / f"wks-pre-resynth-{__import__('datetime').datetime.now():%Y%m%d-%H%M%S}.db"
    dst.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(dst)) as out:
        src.backup(out)
    src.close()
    return dst


def real_quote_for(con, source_id: int) -> tuple[str, str] | None:
    """A verbatim quote some OTHER item already verified on this source."""
    r = con.execute(
        """SELECT q.quote, i.item_key FROM item_source q
             JOIN item i ON i.id = q.item_id
            WHERE q.source_id = ? AND i.status = 'active'
              AND q.quote IS NOT NULL AND TRIM(q.quote) != ''
              AND q.quote NOT LIKE 'class % evidence: %'
            ORDER BY i.id LIMIT 1""", (source_id,)).fetchone()
    return (r["quote"], r["item_key"]) if r else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    con = store.connect(config.DB_PATH)
    rows = con.execute(
        """SELECT DISTINCT i.id, i.item_key, i.class_id
             FROM item i JOIN item_source q ON q.item_id = i.id
            WHERE i.status = 'active' AND q.quote LIKE 'class % evidence: %'"""
    ).fetchall()
    print(f"items holding a synthesised quote: {len(rows)}")

    repaired, unsourceable = [], []
    for it in rows:
        cites = con.execute(
            """SELECT q.source_id, s.url, q.quote FROM item_source q
                 JOIN source s ON s.id = q.source_id WHERE q.item_id = ?""",
            (it["id"],)).fetchall()
        new = []
        for c in cites:
            if not is_synthetic(c["quote"]):
                continue
            got = real_quote_for(con, c["source_id"])
            if got:
                new.append((c["source_id"], got[0], got[1]))
            else:
                new.append((c["source_id"], None, c["url"]))
        ok = [n for n in new if n[1]]
        if len(ok) >= 1:
            repaired.append((it, ok, new))
        else:
            unsourceable.append((it, new))

    print(f"  repairable with a real quote : {len(repaired)}")
    print(f"  no real quote exists anywhere: {len(unsourceable)}")
    for it, _ in unsourceable:
        print(f"    UNSOURCEABLE {it['item_key']}")

    if not a.apply:
        print("\ndry run: pass --apply to write")
        con.close()
        return 0

    snap = snapshot()
    print(f"\nsnapshot: {snap}")

    n_fix = 0
    for it, ok, _ in repaired:
        for source_id, quote, _src_item in ok:
            con.execute(
                """UPDATE item_source SET quote = ?
                    WHERE item_id = ? AND source_id = ?""",
                (quote, it["id"], source_id))
            n_fix += 1
    print(f"rewrote {n_fix} citation row(s) with verbatim quotes")

    for it, _ in unsourceable:
        con.execute("UPDATE item SET status='superseded' WHERE id=?", (it["id"],))
        print(f"  superseded {it['item_key']} (no sourceable quote existed)")

    con.commit()
    con.close()
    print("\nAPPLIED. Now re-verify: python -m wks.verify_quotes --class <id>")
    return 0


if __name__ == "__main__":
    sys.exit(main())
