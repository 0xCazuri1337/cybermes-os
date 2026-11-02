import glob
import sys

sys.path.insert(0, ".")
from wks import store

con = store.connect()
for dom, surfs in (("web", ("web", "client", "api", "business", "identity", "infra")),
                   ("network", ("net", "ad"))):
    txt = "".join(open(p, encoding="utf-8").read()
                  for p in glob.glob("domains/%s/**/*.md" % dom, recursive=True))
    sql = ("SELECT i.claim FROM item i WHERE i.body LIKE ?"
           " AND i.class_id IN (SELECT id FROM bug_class"
           " WHERE surface IN (" + ",".join("?" * len(surfs)) + "))")
    claims = [c for (c,) in con.execute(sql, ("%Write-up provenance:%",) + surfs)]
    miss = [c for c in claims if c[:70] not in txt]
    print("%-8s HTB-provenance claims=%2d   missing after the deletion=%d"
          % (dom, len(claims), len(miss)))
    for m in miss[:3]:
        print("    MISSING:", m[:80])