"""Who wrote 43 open conflict rows for classes wave 10 never touched?

Classes in the open rows: ssrf, xss, race, deser, idor, graphql -- none of which
appear in any w10-*.json. And the claims REPEAT with byte-identical lengths
(xss claim_a_len=144 at 10:17, 10:20, 10:23, 10:26 UTC), so one item was
re-ingested at least four times, inserting a fresh conflict row each time.

So: (a) which incoming FILE carries these claims, (b) does ingest dedupe the
conflict row, and (c) can a conflict row be traced back to an item at all
(item_a is NULL in all 43, which is why tools/resolve_disputes.py cannot settle
them -- it looks the claim up in the item table).
"""
import glob
import json
import os
import sqlite3
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
con = sqlite3.connect(os.path.join(ROOT, "db", "wks.db"))
con.row_factory = sqlite3.Row
cur = con.cursor()

opens = cur.execute("SELECT id, class_id, claim_a, claim_b, created_at FROM conflict "
                    "WHERE status='open' ORDER BY id").fetchall()
distinct = {}
for r in opens:
    distinct.setdefault((r["class_id"], r["claim_a"]), []).append(r["id"])
print("open rows: %d   distinct (class, claim_a): %d" % (len(opens), len(distinct)))
print("=> %d redundant rows inserted for an already-recorded dispute\n" %
      (len(opens) - len(distinct)))

print("=== where does each distinct claim live? ===")
files = sorted(glob.glob(os.path.join(ROOT, "research", "incoming", "*.json")))
claims_in_files = {}
for f in files:
    raw = open(f, encoding="utf-8").read()
    raw = "\n".join(l for l in raw.splitlines()
                    if not l.strip().startswith("// COMPLETE"))
    try:
        data = json.loads(raw)
    except Exception as e:
        print("  UNREADABLE %s: %s" % (os.path.basename(f), e))
        continue
    items = data.get("items") if isinstance(data, dict) else data
    if not isinstance(items, list):
        print("  NO ITEM ARRAY (%s): keys=%s" %
              (os.path.basename(f), sorted(data) if isinstance(data, dict) else type(data)))
        continue
    for it in items:
        claims_in_files.setdefault(it["claim"], []).append(
            (os.path.basename(f), it["item_key"]))

unlocated = 0
for (cid, claim_a), ids in sorted(distinct.items(), key=lambda kv: kv[1][0]):
    hits = claims_in_files.get(claim_a, [])
    if hits:
        print("  %-8s rows=%-3d %s" % (cid, len(ids),
              ", ".join("%s :: %s" % (h[0], h[1]) for h in hits[:2])))
    else:
        unlocated += 1
        print("  %-8s rows=%-3d NOT IN ANY INCOMING FILE -> %s" %
              (cid, len(ids), claim_a[:100]))
print("\nunlocated distinct claims: %d of %d" % (unlocated, len(distinct)))

print("\n=== is the conflicting item in the db? ===")
in_db = 0
for (cid, claim_a) in distinct:
    n = cur.execute("SELECT count(*) FROM item WHERE claim = ?", (claim_a,)).fetchone()[0]
    if n:
        in_db += 1
print("distinct claims matching a db item.claim: %d of %d" % (in_db, len(distinct)))
for (cid, claim_a) in list(distinct)[:5]:
    row = cur.execute("SELECT i.item_key, q.validation_state FROM item i "
                      "LEFT JOIN quality q ON q.item_id=i.id WHERE i.claim=?",
                      (claim_a,)).fetchone()
    print("   %-8s -> %s" % (cid, tuple(row) if row else None))

print("\n=== sample dispute text (deser, newest) ===")
for r in opens:
    if r["class_id"] == "deser":
        print("  id=%d %s" % (r["id"], r["created_at"]))
        print("  A: %s" % r["claim_a"])
        print("  B: %s" % r["claim_b"][:220])
        break