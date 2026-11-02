"""Backfill chain_step.class_id for the 10 wave-9 chains.

MEASURED: all 10 chains recovered from wave 9 had `class_id` AND `item_id` NULL
on every step, so `build_chain_home` had nothing to group them by (all 10 piled
into cross-class-chains.md) and `build_taxonomy.chain_file` could not render any
source or evidence for them. The child's steps named no existing item, so no
item_id could be derived honestly.

What is legitimate here: the class a step belongs to. The step lives on an item
(`item.chain.<name>`) whose class IS known, and a step that is part of a chain
about that class belongs to that class. That is a derivation from the corpus,
not an invention.

What is NOT legitimate: fabricating an item_id. A step with no matching item
stays unbound, and is reported as such rather than pointed at an unrelated item.
"""
import os
import sqlite3
import sys

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
os.environ.setdefault("WKS_ROOT", ROOT)
from wks import store  # noqa: E402

con = store.open_db(create=False)

# the host item of each chain: the item whose body carried the chain block
rows = con.execute(
    """SELECT c.id AS chain_id, c.chain_key, i.class_id
       FROM chain c
       JOIN item i ON i.item_key = replace(c.chain_key, '-', '.')
       WHERE 1=0""").fetchall()  # placeholder, replaced below

# chain_key -> host item, matched by the item that declared the chain.
# The recovered chains came from items named <class>.chain.<slug>; the chain_key
# was slugified from the chain name, so match on the slug instead.
host = {}
for it in con.execute("SELECT id, item_key, class_id, body FROM item").fetchall():
    b = it["body"] or ""
    if '"chain_key"' not in b and "'chain_key'" not in b:
        continue
    import re
    m = re.search(r'"chain_key"\s*:\s*"([^"]+)"', b)
    if m:
        host[m.group(1)] = (it["id"], it["item_key"], it["class_id"])

print("chains with a host item found in item bodies: %d" % len(host))

filled = 0
for c in con.execute("SELECT id, chain_key FROM chain").fetchall():
    h = host.get(c["chain_key"])
    if not h:
        print("  NO HOST ITEM for", c["chain_key"])
        continue
    n = con.execute(
        "UPDATE chain_step SET class_id=? WHERE chain_id=? AND class_id IS NULL",
        (h[2], c["id"])).rowcount
    if n:
        print("  %-58s class_id <- %s (%d steps)"
              % (c["chain_key"], h[2], n))
        filled += n

con.commit()
print("\nsteps backfilled: %d" % filled)

remaining = con.execute(
    """SELECT COUNT(*) FROM chain_step s JOIN chain c ON c.id=s.chain_id
       WHERE s.class_id IS NULL""").fetchone()[0]
unbound = con.execute(
    "SELECT COUNT(*) FROM chain_step WHERE item_id IS NULL").fetchone()[0]
print("steps still without class_id: %d" % remaining)
print("steps without item_id (no real evidence item to render): %d" % unbound)
con.close()