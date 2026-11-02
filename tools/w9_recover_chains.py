"""Assemble the 4 chains wave 9 produced but ingest silently dropped.

The items are already merged and promoted; only the chain STRUCTURE was lost.
Re-run the chain assembly for those items from their stored bodies, so the
research is recovered rather than re-researched.

Reads the `chain` block from the incoming file (the canonical record of what the
child authored), re-verifies each host item is still promoted, and writes the
chain + steps through the same validated `authoring.add_chain`.
"""
import json
import os
import re
import sys

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
os.environ.setdefault("WKS_ROOT", ROOT)
from wks import authoring, store  # noqa: E402

SRC = os.path.join(ROOT, "research", "incoming", "w9-4-chains.json")
raw = open(SRC, encoding="utf-8").read()
raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
items = json.loads(raw)["items"]

con = store.open_db(create=False)
promoted = {r[0] for r in con.execute(
    """SELECT i.item_key FROM item i JOIN quality q ON q.item_id=i.id
       WHERE q.validation_state IN ('high_confidence','supported')""").fetchall()}

ok, refused = [], []
for it in items:
    spec = it.get("chain")
    if not isinstance(spec, dict):
        continue
    key = it["item_key"]
    if key not in promoted:
        refused.append((key, "host item is not promoted"))
        continue
    steps = []
    for s in (spec.get("steps") or []):
        s = dict(s)
        ref = s.pop("item_key", None)
        if ref:
            row = con.execute("SELECT id, class_id FROM item WHERE item_key=?",
                              (ref,)).fetchone()
            if row is not None:
                s["item_id"] = int(row["id"])
                s["class_id"] = s.get("class_id") or row["class_id"]
        steps.append(s)
    spec = dict(spec, steps=steps)
    spec.setdefault("chain_key",
                    spec.get("name", "").lower().replace(" ", "-"))
    good, msg = authoring.add_chain(con, spec)
    (ok if good else refused).append(msg if good else (key, msg))
    print(("  ok   " if good else "  FAIL ") + str(msg))

con.commit()
print("\nchain rows now:",
      con.execute("SELECT COUNT(*) FROM chain").fetchone()[0],
      " steps:",
      con.execute("SELECT COUNT(*) FROM chain_step").fetchone()[0])
print("assembled=%d refused=%d" % (len(ok), len(refused)))
for r in refused:
    print("   refused:", r)
con.close()