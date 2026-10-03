"""Classify the second dead citation found by the full sweep:
https://projectdiscovery.io/blog/ruby-saml-gitlab-auth-bypass-cve-2024-45409

Is it a MOVED page (resolvable successor holding the quote) or genuinely dead
knowledge? Print the quotes attributed to it and what the items claim, so the
verdict is made on evidence rather than on the URL's shape.
"""
import os
import sqlite3
import sys

ROOT = r"C:/Users/Administrator/.hermes/cyber"
DB = os.path.join(ROOT, "db", "wks.db")
con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
cur = con.cursor()

cur.execute("""select id, url, host, http_status, notes from source
               where url like '%ruby-saml-gitlab%'""")
rows = cur.fetchall()
print("source rows:", rows)
if not rows:
    raise SystemExit("no such source row")
sid = rows[0][0]

cur.execute("""select i.item_key, i.class_id, i.claim, isr.quote
               from item_source isr join item i on i.id=isr.item_id
               where isr.source_id=?""", (sid,))
items = cur.fetchall()
print("\nitems citing it:", len(items))
for key, cls, claim, q in items:
    print("=" * 70)
    print(key, "|", cls)
    print("claim:", (claim or "")[:200])
    print("quote:", (q or "")[:200])

print("\n--- sibling sources of each item ---")
for key, cls, claim, q in items:
    cur.execute("""select s.host, s.url from item_source isr
                   join source s on s.id=isr.source_id
                   join item i on i.id=isr.item_id
                   where i.item_key=? and s.id<>?""", (key, sid))
    print(" ", key, cur.fetchall())

print("\n--- resolver verdict per quote ---")
sys.path.insert(0, ROOT)
from wks import resolver  # noqa: E402
url = rows[0][1]
for key, cls, claim, q in items:
    r = resolver.resolve(url, q)
    print(" ", key, "->", r["resolved"])
    for t in r["tried"][:5]:
        print("       tried", t["status"], t["url"][-80:])