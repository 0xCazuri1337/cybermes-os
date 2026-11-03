"""Assert the RENDERED domain pages against the db, item by item.

`build_taxonomy.py` prints nothing and exits 0, which is exactly the "green run
that changed nothing" shape. MEASURED before regenerating: 11/11 web classes
had a CLASS.md but none contained the new items (xss Exploitation was missing
its technique row), and all 9 network classes had no CLASS.md at all -- while
`wks.domains --check` reported "0 problems across 62 classes", because that
verifies the TREE (which class sits in which domain), never the CONTENT.

So the check here is a set difference in the direction that matters:
  items in the db  -  items actually rendered into a page
Anything left in that difference is knowledge that exists but is INVISIBLE to a
reader, which is the failure this whole corpus is supposed to prevent.
"""
import os
import sqlite3
import sys

sys.path.insert(0, ".")
from wks.domains import domain_of

db = sqlite3.connect("db/wks.db")
db.row_factory = sqlite3.Row

# the classes this wave contributed, and how to recognise each item on a page
CLASSES = ["ad_kerberos", "dns_enum", "exposed_services", "file_upload", "idor",
           "info_disclosure", "ldap_enum", "misconfig", "pass_the_hash",
           "path_traversal", "rdp", "service_enumeration", "smb", "smuggling",
           "sqli", "ssrf", "ssti", "tunneling_pivoting", "xss", "xxe"]

# kind -> the CLASS.md section that renders it
KIND_SECTION = {
    "prerequisite": "Preconditions", "signal": "Detection",
    "technique": "Exploitation", "bypass": "Variations",
    "validation": "Validation", "impact": "Impact", "test": "Tests",
    "fp_rule": "Common False Positives",
}


def page_for(cid):
    """Locate CLASS.md for a class wherever the tree files it.

    MEASURED BUG: the first version compared `os.path.basename(root)` to the
    class id, but the walk step that CONTAINS CLASS.md is
    `skills/<dom>/<class>/knowledge` -- whose basename is "knowledge", never
    the class. It reported 0/20 pages for a tree holding 62 of them. The class
    directory is the PARENT of the directory holding the file.
    """
    for root, _, files in os.walk("skills"):
        if "CLASS.md" not in files:
            continue
        # skills/<domain>/<class>/CLASS.md  ->  parent of root is <class>
        holder = os.path.basename(root)              # "knowledge"
        cls_dir = os.path.dirname(root)               # ".../<class>"
        if holder in ("knowledge", "topics", "assessment", "skills", "chains"):
            if os.path.basename(cls_dir) == cid:
                return os.path.join(root, "CLASS.md")
        elif os.path.basename(root) == cid:
            return os.path.join(root, "CLASS.md")
    return None


def section(txt, name):
    """Return the body of one '## <name>' section."""
    marker = f"\n## {name}"
    i = txt.find(marker)
    if i < 0:
        return ""
    j = txt.find("\n## ", i + len(marker))
    return txt[i:j] if j > 0 else txt[i:]


def norm(s):
    return " ".join((s or "").lower().split())


missing, no_page, ok = [], [], 0

for cid in CLASSES:
    page = page_for(cid)
    try:
        dom = domain_of(db, cid)
    except KeyError:
        dom = "?"
    if not page:
        no_page.append((cid, dom))
        continue
    txt = open(page, encoding="utf-8", errors="replace").read()
    rows = list(db.execute(
        "SELECT item_key, kind, claim FROM item WHERE status='active' AND item_key LIKE ?",
        (cid + ".%",)))
    for r in rows:
        body = section(txt, KIND_SECTION.get(r["kind"], ""))
        # a distinctive 60-char slice of the claim, whitespace-normalised
        frag = norm(r["claim"])[:60]
        if frag and frag in norm(body):
            ok += 1
        else:
            missing.append((cid, r["kind"], r["item_key"].split(".")[-1][:44]))

print(f"pages found        : {len(CLASSES) - len(no_page)}/{len(CLASSES)}")
print(f"items rendered OK  : {ok}")
print(f"items MISSING      : {len(missing)}")
print(f"classes w/o page   : {len(no_page)}")

if no_page:
    print("\nno CLASS.md for:")
    for c, d in no_page:
        print(f"   {c:<24} domain={d}")
if missing:
    print("\nitems in the db but NOT on any page (invisible knowledge):")
    for c, k, i in missing[:40]:
        print(f"   {c:<22} [{k:<12}] {i}")
    if len(missing) > 40:
        print(f"   ... and {len(missing) - 40} more")

raise SystemExit(1 if (missing or no_page) else 0)