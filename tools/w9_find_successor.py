"""Find the live successor of the dead WSTG SQLi page, and test whether the
404 -> resolver path is reachable from the DB-side verification that promoted
the 3 sqli items (the WIRING test, not just the component test).
"""
import io
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}


def get(url):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)


CANDIDATES = [
    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/",
    "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html",
    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html",
]

print("--- candidate paths ---")
live = []
for u in CANDIDATES:
    st, body = get(u)
    print(" ", st, u)
    if st == 200:
        live.append(u)

print("\n--- links discovered on live index pages ---")
found = set()
for u in live:
    if not u.endswith("/"):
        continue
    st, body = get(u)
    for h in re.findall(r'href="([^"]+)"', body):
        if "sql" in h.lower() or "inject" in h.lower():
            found.add(h)
print(sorted(found)[:25])

# what quotes do the 3 sqli items attribute to the dead page?
con = sqlite3.connect("file:" + os.path.join(ROOT, "db", "wks.db") + "?mode=ro", uri=True)
cur = con.cursor()
cur.execute("select id from source where url like '%05-Testing_for_SQL_Injection%'")
rows = cur.fetchall()
print("\n--- quotes attributed to the dead page ---")
for (sid,) in rows:
    cur.execute("""select i.item_key, isr.quote from item_source isr
                   join item i on i.id=isr.item_id where isr.source_id=?""", (sid,))
    for key, q in cur.fetchall():
        print(" ", key, "->", (q or "")[:120])

# WIRING: does resolver.resolve() actually find a successor for this URL+quote?
print("\n--- resolver wiring test ---")
from wks import resolver  # noqa: E402
print("resolver.resolve signature ok:", callable(getattr(resolver, "resolve", None)))
for (sid,) in rows:
    cur.execute("""select i.item_key, isr.quote, s.url from item_source isr
                   join item i on i.id=isr.item_id join source s on s.id=isr.source_id
                   where isr.source_id=?""", (sid,))
    for key, q, url in cur.fetchall():
        try:
            moved = resolver.resolve(url, q)
            print("  ", key, "->", moved)
        except Exception as e:
            print("  ", key, "resolver raised", type(e).__name__, e)