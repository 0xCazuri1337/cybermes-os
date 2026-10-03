"""Backfill chain_step.class_id / item_id for wave-9 chains from the INCOMING
file, which is the canonical record of what the child actually authored.

`ingest` persists only the item's `body` field, so the `chain` block never
reaches the db; the chains were recovered from `research/incoming/w9-4-chains.json`.
The host item of each chain is the item in that file carrying the block, and its
`class_id` is what every step belongs to.

Two different things are being filled, and the distinction matters:
  * class_id — derivable from the corpus (the host item's class). Filled.
  * item_id  — only filled where the step names a REAL item_key that exists.
    A step naming nothing stays unbound: pointing it at an unrelated item would
    make the chain cite evidence it does not have.
"""
import io
import json
import os
import re
import sys

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
os.environ.setdefault("WKS_ROOT", ROOT)
from wks import store  # noqa: E402

SRC = os.path.join(ROOT, "research", "incoming", "w9-4-chains.json")
raw = open(SRC, encoding="utf-8").read()
raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
items = json.loads(raw)["items"]

con = store.open_db(create=False)
by_key = {r["item_key"]: (int(r["id"]), r["class_id"]) for r in con.execute(
    "SELECT id, item_key, class_id FROM item").fetchall()}

filled_c = filled_i = 0
for it in items:
    spec = it.get("chain")
    if not isinstance(spec, dict):
        continue
    ck = spec.get("chain_key")
    row = con.execute("SELECT id FROM chain WHERE chain_key=?", (ck,)).fetchone()
    if row is None:
        print("  chain row missing for", ck)
        continue
    cid = row["id"]
    host_class = it.get("class_id")
    for s in spec.get("steps") or []:
        ref = s.get("item_key")
        item_id = class_id = None
        if ref and ref in by_key:
            item_id, class_id = by_key[ref]
        elif host_class:
            class_id = host_class
        n1 = con.execute(
            "UPDATE chain_step SET item_id=? WHERE chain_id=? AND ord=? AND item_id IS NULL",
            (item_id, cid, s.get("ord"))).rowcount
        n2 = con.execute(
            "UPDATE chain_step SET class_id=? WHERE chain_id=? AND ord=? AND class_id IS NULL",
            (class_id, cid, s.get("ord"))).rowcount
        filled_i += n1
        filled_c += n2

con.commit()
print("item_id backfilled: %d   class_id backfilled: %d" % (filled_i, filled_c))
print("steps still unbound item_id:",
      con.execute("SELECT COUNT(*) FROM chain_step WHERE item_id IS NULL").fetchone()[0])
print("steps still unbound class_id:",
      con.execute("SELECT COUNT(*) FROM chain_step WHERE class_id IS NULL").fetchone()[0])
con.close()