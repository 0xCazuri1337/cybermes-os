"""w11: build the per-class priority table rows. Read-only."""
import json
import os
import re
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(os.environ.get("WKS_ROOT", r"C:/Users/Administrator/.hermes/cyber"))
sys.path.insert(0, str(ROOT))
from wks.config import publisher_org  # noqa: E402

con = sqlite3.connect(f"file:{(ROOT/'db'/'wks.db').as_posix()}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
src = {r["id"]: r for r in con.execute("select * from source")}

web = sorted(p for p in os.listdir(ROOT / "domains" / "web")
             if (ROOT / "domains" / "web" / p).is_dir()
             and p not in {"areas", "chains", "methodology", "topics"})

items = defaultdict(list)
for r in con.execute("select id,item_key,class_id,body,status from item"):
    items[r["class_id"]].append(r)
isrc = defaultdict(list)
for r in con.execute("select item_id,source_id,locator,quote from item_source"):
    isrc[r["item_id"]].append(r)
fpcase = Counter()
for r in con.execute("select class_id,count(*) c from fp_case group by class_id"):
    fpcase[r["class_id"]] = r["c"]
fprule = Counter()
for r in con.execute("select class_id,count(*) c from item where kind='fp_rule' group by class_id"):
    fprule[r["class_id"]] = r["c"]

# classes where verify_quotes measured FABRICATED (measured this session)
FAB = {"xxe": 1, "misconfig": 1, "smuggling": 1, "cmd": 1, "ldap": 1,
       "api_trust": 2, "crlf": 1, "nosql": 1}
VERIFIED = {"race": 15, "graphql": 13, "xxe": 22, "misconfig": 12, "smuggling": 16,
            "cmd": 12, "ldap": 12, "api_trust": 12, "crlf": 13, "nosql": 15, "authz": 18}

rows = []
for cid in web:
    its = items[cid]
    links = [s for i in its for s in isrc[i["id"]]]
    ids = {s["source_id"] for s in links}
    orgs = {publisher_org(src[i]["host"]) for i in ids if i in src}
    per_item = []
    for i in its:
        o = {publisher_org(src[s["source_id"]]["host"])
             for s in isrc[i["id"]] if s["source_id"] in src}
        per_item.append(len(o))
    at2 = sum(1 for n in per_item if n == 2)
    loc = sum(1 for s in links if s["locator"])
    auto = [i for i in its if ".auto." in i["item_key"]]
    nav = [i for i in auto if re.search(r"\n\s*\n\s*\n", i["body"] or "")]
    qlens = sorted(len(s["quote"] or "") for s in links)
    rows.append({
        "class_id": cid,
        "items": len(its),
        "orgs": len(orgs),
        "at2": at2,
        "frag": round(100 * at2 / len(its)),
        "loccov": round(100 * loc / len(links)) if links else 0,
        "nav": len(nav),
        "auto": len(auto),
        "fpcase": fpcase[cid],
        "fprule": fprule[cid],
        "fab": FAB.get(cid, 0),
        "verif": VERIFIED.get(cid),
        "medq": qlens[len(qlens) // 2] if qlens else 0,
        "orglist": sorted(orgs),
    })

json.dump(rows, open(ROOT / "validation" / "w11_table_rows.json", "w"), indent=1)
print(f"{'class':22s} {'it':>3} {'org':>3} {'at2':>3} {'frag%':>5} {'loc%':>5} "
      f"{'nav':>4} {'auto':>4} {'fpc':>3} {'fpr':>3} {'fab':>3} {'medQ':>4}")
for r in sorted(rows, key=lambda x: (x["orgs"], -x["frag"], x["class_id"])):
    print(f"{r['class_id']:22s} {r['items']:3d} {r['orgs']:3d} {r['at2']:3d} {r['frag']:5d} "
          f"{r['loccov']:5d} {r['nav']:4d} {r['auto']:4d} {r['fpcase']:3d} {r['fprule']:3d} "
          f"{r['fab']:3d} {r['medq']:4d}")
