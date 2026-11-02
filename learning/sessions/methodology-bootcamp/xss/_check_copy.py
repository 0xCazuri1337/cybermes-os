import re, sys, sqlite3, os
CLASS = sys.argv[1]
ART = r"learning/sessions/methodology-bootcamp/xss"
db = sqlite3.connect('C:/Users/Administrator/.hermes/cyber\\db\\wks.db')
rows = db.execute(
    "SELECT i.item_key, q.validation_state FROM item i "
    "JOIN quality q ON q.item_id = i.id WHERE i.class_id = ?", (CLASS,)
).fetchall()
keys = {k: v for k, v in rows}
cited, bad, unpromoted = set(), [], []
for f in os.listdir(ART):
    if not f.endswith(".md"):
        continue
    for m in re.findall(r"\[" + CLASS + r"\.[a-z_]+\.[a-z0-9_\-]+\]", open(os.path.join(ART, f), encoding="utf-8").read()):
        k = m[1:-1]
        cited.add(k)
        if k not in keys:
            bad.append((f, k))
        elif keys[k] not in ("high_confidence", "supported"):
            unpromoted.append((f, k, keys[k]))
print(f"class={CLASS} items={len(keys)} cited={len(cited)} unknown={len(bad)} unpromoted={len(unpromoted)}")
for x in bad[:20]: print("  UNKNOWN  ", x)
for x in unpromoted[:20]: print("  UNPROMOTED", x)
sys.exit(1 if (bad or unpromoted or not cited) else 0)