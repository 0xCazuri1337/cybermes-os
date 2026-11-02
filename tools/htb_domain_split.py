"""Split the HTB-derived items into the WEB and NETWORK domains, from the db.

The user asked for the material sorted into web and network domains. That
routing already exists (`wks.domains`), so this does not invent a new taxonomy:
it reads the authoritative split and reports, per domain, which HTB write-up
items now live there, with their evidence.

Read from the db, not from the builder's log -- a generator's own output is a
self-report, and the rule is that a child's claim must be checked against the
store's movement.
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, ".")
from wks.domains import domain_of  # authoritative domain routing

DB = os.path.join(os.environ.get("WKS_ROOT", "."), "db", "wks.db")
db = sqlite3.connect(DB)
db.row_factory = sqlite3.Row

rows = list(db.execute("""
    SELECT DISTINCT i.item_key, i.status, i.kind, i.claim
      FROM item i
      JOIN item_source isr ON isr.item_id = i.id
      JOIN source s ON s.id = isr.source_id
     WHERE s.host LIKE '%githubusercontent%' AND i.status != 'superseded'
     ORDER BY i.item_key"""))

# Route each class through the db-backed mapping. `domain_of` raises for an
# unknown/unmapped class rather than defaulting, which is the behaviour we
# want: an unrouted class must be reported, never guessed into a folder.
def route(cls):
    try:
        return domain_of(db, cls)
    except KeyError as e:
        return f"UNROUTED:{e}"


web, net, unplaced = [], [], []
for r in rows:
    d = route(r["item_key"].split(".")[0])
    (web if d == "web" else net if d in ("network", "ad") else unplaced).append(r)

print("=" * 78)
print("HTB-DERIVED TECHNIQUES BY DOMAIN  (read from the db, routed by wks.domains)")
print("=" * 78)
for label, group in (("WEB", web), ("NETWORK / AD", net)):
    print(f"\n### {label}  ({len(group)} items)\n")
    for r in sorted(group, key=lambda x: x["item_key"]):
        cls = r["item_key"].split(".")[0]
        print(f"  [{r['kind']:<10}] {cls:<22} {r['item_key'].split('.', 2)[2][:52]}")
        print(f"       {r['claim'][:112]}")

if unplaced:
    print(f"\n### UNROUTED ({len(unplaced)}) -- not in the split:")
    for r in unplaced:
        print("   ", r["item_key"])

out = {
    "web": [r["item_key"] for r in web],
    "network": [r["item_key"] for r in net],
    "unplaced": [r["item_key"] for r in unplaced],
}
with open("research/htb_domain_split.json", "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
print(f"\nTOTAL htb items={len(rows)}  web={len(web)}  network={len(net)}  "
      f"unplaced={len(unplaced)}")
assert len(web) + len(net) + len(unplaced) == len(rows), "buckets do not reconcile"
print("reconciliation OK -> research/htb_domain_split.json")