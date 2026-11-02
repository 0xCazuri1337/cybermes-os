import json
import sys
import collections

sys.path.insert(0, ".")
from wks import store

con = store.connect()
c = collections.Counter()
rows = con.execute(
    "SELECT i.item_key, i.class_id, q.gate_reasons FROM item i"
    " JOIN quality q ON q.item_id=i.id"
    " WHERE i.item_key LIKE 'hth!_%' ESCAPE '!'").fetchall()
print("hth_ items in the db:", len(rows))
for r in rows:
    try:
        rs = json.loads(r["gate_reasons"] or "[]")
    except Exception:
        rs = [r["gate_reasons"]]
    for x in rs:
        c[str(x)] += 1
print()
print("gate reasons:")
for k, v in c.most_common(10):
    print("  %-46s %d" % (k[:46], v))
print()
print("sample items and their hosts:")
for r in con.execute(
        "SELECT i.item_key, s.host, s.publisher FROM item i"
        " JOIN item_source x ON x.item_id=i.id JOIN source s ON s.id=x.source_id"
        " WHERE i.item_key LIKE 'hth!_%' ESCAPE '!' LIMIT 6"):
    print("  %-48s %-26s %s" % (r["item_key"][:48], r["host"], r["publisher"]))
print()
import sys as _s
from wks import config
orgs = set()
for r in con.execute(
        "SELECT DISTINCT s.host FROM item i JOIN item_source x ON x.item_id=i.id"
        " JOIN source s ON s.id=x.source_id WHERE i.item_key LIKE 'hth!_%' ESCAPE '!'"):
    orgs.add(config.publisher_org(r["host"]))
print("distinct publisher ORGs across hth_ items:", sorted(orgs))
print("MIN_PUBLISHER_HOSTS =", config.MIN_PUBLISHER_HOSTS)