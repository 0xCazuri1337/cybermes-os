"""Assert ONLY the items this wave contributed are rendered into the domain pages.

`htb_verify_projection.py` flagged 121 "missing" items, but they are almost all
kinds the renderer does not place in CLASS.md by design (`chain_link`, `test`,
`evidence`) -- my section map was incomplete, not the knowledge absent. So that
check answers the wrong question.

This one asks the question that was actually asked: of the items that CITE an
HTB write-up, how many are readable on a page? Each is located by the class dir
that actually holds CLASS.md, and its claim is matched in whichever sections
the renderer uses for its kind.
"""
import os
import sqlite3
import sys

sys.path.insert(0, ".")

db = sqlite3.connect("db/wks.db")
db.row_factory = sqlite3.Row

# kinds build_taxonomy renders into a CLASS.md section, and where
KIND_SECTION = {
    "prerequisite": ["Preconditions"],
    "signal": ["Detection"],
    "technique": ["Exploitation"],
    "bypass": ["Variations"],
    "variant": ["Variations"],
    "validation": ["Validation"],
    "impact": ["Impact"],
    "fp_rule": ["Common False Positives"],
    # rendered elsewhere (chains / assessment) or not in CLASS.md at all
    "chain_link": [],
    "test": [],
    "evidence": [],
}


def norm(s):
    return " ".join((s or "").lower().split())


def section(txt, name):
    marker = f"\n## {name}"
    i = txt.find(marker)
    if i < 0:
        return ""
    j = txt.find("\n## ", i + len(marker))
    return txt[i:j] if j > 0 else txt[i:]


def page_for(cid):
    for root, _, files in os.walk("skills"):
        if "CLASS.md" in files:
            if os.path.basename(os.path.dirname(root)) == cid:
                return os.path.join(root, "CLASS.md")
    return None


rows = list(db.execute("""
    SELECT DISTINCT i.item_key, i.kind, i.claim, i.status
      FROM item i
      JOIN item_source isr ON isr.item_id = i.id
      JOIN source s ON s.id = isr.source_id
     WHERE s.host LIKE '%githubusercontent%' AND i.status='active'
     ORDER BY i.item_key"""))

by_class, not_renderable, rendered, missing = {}, [], [], []
for r in rows:
    by_class.setdefault(r["item_key"].split(".")[0], []).append(r)

for cid, items in sorted(by_class.items()):
    page = page_for(cid)
    if not page:
        missing.extend((cid, i["kind"], i["item_key"]) for i in items)
        continue
    txt = norm(open(page, encoding="utf-8", errors="replace").read())
    for i in items:
        secs = KIND_SECTION.get(i["kind"])
        if secs is None:
            not_renderable.append((cid, i["kind"]))
            continue
        if not secs:
            not_renderable.append((cid, i["kind"]))
            continue
        body = norm(" ".join(section(open(page, encoding="utf-8", errors="replace").read(), s)
                             for s in secs))
        frag = norm(i["claim"])[:60]
        (rendered if frag and frag in body else missing).append(
            (cid, i["kind"], i["item_key"].split(".")[-1][:52]))

print(f"HTB-derived active items : {len(rows)}")
print(f"  classes                : {len(by_class)}")
print(f"  RENDERED on a page     : {len(rendered)}")
print(f"  not in a CLASS.md kind : {len(not_renderable)}  "
      f"(chain_link/test/evidence render elsewhere by design)")
print(f"  MISSING                : {len(missing)}")

if missing:
    print("\nMISSING from the domain pages:")
    for c, k, i in missing:
        print(f"   {c:<22} [{k:<12}] {i}")

web = [c for c in by_class if c in {
    "file_upload", "idor", "info_disclosure", "misconfig", "path_traversal",
    "smuggling", "sqli", "ssrf", "ssti", "xss", "xxe"}]
print(f"\nweb classes with HTB items: {len(web)}")
print(f"network classes           : {len(by_class) - len(web)}")
raise SystemExit(1 if missing else 0)