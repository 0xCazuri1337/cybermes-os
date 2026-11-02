"""Wave-10 merge audit: child CLAIM vs db MOVEMENT.

Children claimed 14+16+14+15+15 = 74 items. items_total moved 396 -> 426, i.e.
+30. open_conflicts moved 11 -> 43. Either items collided on item_key, or the
real ingest ran for only some files, or the gate rejected them.

Prints, per file: items claimed, item_keys present, which of those already
existed in the db BEFORE this wave (so a colliding key is invisible), and the
conflict rows now open against each item_key.
"""
import glob
import json
import os
import sqlite3
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "db", "wks.db")

con = sqlite3.connect(DB)
con.row_factory = sqlite3.Row
cur = con.cursor()

db_keys = {r[0] for r in cur.execute("SELECT item_key FROM item")}
print("db item rows: %d  distinct item_key: %d" % (cur.execute(
    "SELECT count(*) FROM item").fetchone()[0], len(db_keys)))

print("\nconflict table shape:")
cols = [r[1] for r in cur.execute("PRAGMA table_info(conflict)")]
print("  cols:", cols)
print("  open by status:")
for r in cur.execute("SELECT status, count(*) FROM conflict GROUP BY status"):
    print("   ", tuple(r))

total_claimed = 0
for f in sorted(glob.glob(os.path.join(ROOT, "research", "incoming", "w10-*.json"))):
    raw = open(f, encoding="utf-8").read()
    raw = "\n".join(l for l in raw.splitlines() if not l.strip().startswith("// COMPLETE"))
    data = json.loads(raw)
    items = data["items"] if isinstance(data, dict) else data
    keys = [it["item_key"] for it in items]
    dupes = [k for k, n in Counter(keys).items() if n > 1]
    in_db = [k for k in keys if k in db_keys]
    print("\n%s  items=%d  distinct=%d  intra-file dupes=%d  now_in_db=%d" %
          (os.path.basename(f), len(keys), len(set(keys)), len(dupes), len(in_db)))
    if dupes:
        print("   DUPES:", dupes)

    for it in items:
        k = it["item_key"]
        row = cur.execute(
            "SELECT i.id, q.validation_state FROM item i "
            "LEFT JOIN quality q ON q.item_id = i.id WHERE i.item_key = ?", (k,)).fetchone()
        if row is None:
            print("   MISSING FROM DB:", k)
        elif row["validation_state"] not in ("high_confidence", "supported"):
            print("   NOT PROMOTED (%s): %s" % (row["validation_state"], k))
    total_claimed += len(items)

print("\ntotal claimed across files:", total_claimed)

# where did the open conflicts come from?
print("\nopen conflicts (first 20):")
for r in cur.execute("SELECT status, class_id, topic, substr(coalesce(item_a,''),1,60) "
                     "FROM conflict WHERE status='open' ORDER BY id LIMIT 25"):
    print("  ", tuple(r))