"""Is the 404 WSTG citation real, and does ANY code check db rows for dead URLs?

The resolver reported resolved=0 unresolved=0 for every wave file, yet a live
fetch of one cited URL 404s. Two possibilities: the URL is fine and my fetch is
wrong, or the resolver never looked at it.

This script:
  1. GETs the cited URL and the current WSTG index to find the successor path.
  2. Lists every db item citing that URL, and that item's other sources.
  3. Checks whether any code path calls the resolver over the DB (the wiring test).
"""
import io
import os
import re
import sqlite3
import sys
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "db", "wks.db")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
BAD = "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html"


def head(url):
    req = urllib.request.Request(url, headers=UA, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception as e:
        return None, str(e)


def main():
    st, _ = head(BAD)
    print("cited URL status:", st, BAD)
    idx = ("https://owasp.org/www-project-web-security-testing-guide/stable/"
           "4-Web_Application_Security_Testing/07-Input_Validation_Testing/")
    st2, body = head(idx)
    print("parent dir status:", st2)
    if body:
        hrefs = re.findall(r'href="([^"]*SQL[^"]*)"', body, re.I)
        print("successor candidates on index:", sorted(set(hrefs))[:10])

    con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
    cur = con.cursor()
    cur.execute("select id from source where url=?", (BAD,))
    r = cur.fetchone()
    print("\nsource row:", r)
    if not r:
        return
    sid = r[0]
    cur.execute("""select i.id, i.item_key, i.class_id from item i
                   join item_source isr on isr.item_id=i.id
                   where isr.source_id=?""", (sid,))
    items = cur.fetchall()
    print("items citing it:", len(items))
    for iid, key, cls in items:
        print("  -", key, cls)
        cur.execute("""select s.host, s.url, isr.quote from item_source isr
                       join source s on s.id=isr.source_id
                       where isr.item_id=? and s.id<>?""", (iid, sid))
        for host, url, q in cur.fetchall():
            print("      other src:", host, url)
        cur.execute("select validation_state, gate_reasons from quality where item_id=?",
                    (iid,))
        print("      quality:", cur.fetchall())


main()