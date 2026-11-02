"""Spot-check wave-9 quotes against the live pages, independently of the gate.

Uses the gate's own matcher (wks.verify_quotes.find_quote) but fetches with an
INDEPENDENT pipeline, so a systematic fetch bug in wks.pipeline cannot make a
fabrication look verbatim. Samples items per file with a fixed seed.

Also reports, per item, whether its publishers are NEW to the corpus judged by
REGISTRABLE DOMAIN -- the rule children were given, which the gate does not
enforce (it only requires 2 distinct orgs, new or not).
"""
import html
import json
import os
import random
import re
import sqlite3
import sys
import urllib.error
import urllib.request

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
from wks import config  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


def independent_fetch(url, timeout=35):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        s = r.read().decode("utf-8", "ignore")
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", s)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    for a, b in (("\u00a0", " "), ("\u200b", ""), ("\u2019", "'"), ("`", ""),
                 ("\u201c", '"'), ("\u201d", '"'), ("\u2018", "'")):
        s = s.replace(a, b)
    return WS.sub(" ", s)


con = sqlite3.connect("file:" + os.path.join(ROOT, "db", "wks.db") + "?mode=ro", uri=True)
cur = con.cursor()
cited_orgs = {config.publisher_org(r[0]) for r in
              cur.execute("SELECT DISTINCT host FROM source").fetchall()}

random.seed(90210)
total_ok = total_miss = total_err = 0
for path in sys.argv[1:]:
    raw = open(path, encoding="utf-8").read()
    raw = re.sub(r"\n?//\s*COMPLETE[^\n]*\s*$", "", raw).strip()
    items = (json.loads(raw))["items"]
    k = min(3, len(items))
    picked = random.sample(items, k)
    print("=" * 78)
    print(os.path.basename(path), " sampling", k, "of", len(items))
    cache = {}
    for it in picked:
        orgs = {config.publisher_org((s.get("host") or "").lower()
                                     .removeprefix("www."))
                for s in it.get("sources", [])}
        new = orgs - cited_orgs
        print("  %-62s orgs=%d new_orgs=%d %s"
              % (it["item_key"][:62], len(orgs), len(new),
                 ("NEW:" + ",".join(sorted(new))) if new else "ALL-REUSED"))
        for s in it.get("sources", []):
            u, q = s.get("url"), s.get("quote") or ""
            if u not in cache:
                try:
                    cache[u] = independent_fetch(u)
                except Exception as e:
                    cache[u] = None
                    print("     FETCH_FAIL %-38s %s %s"
                          % (u.split("/")[2], type(e).__name__, str(e)[:50]))
                    total_err += 1
            page = cache[u]
            if page is None:
                continue
            if find_quote(page, q):
                total_ok += 1
                print("     OK   %-38s %dch" % (u.split("/")[2], len(q)))
            else:
                total_miss += 1
                print("     MISS %-38s %dch  %s" % (u.split("/")[2], len(q), q[:70]))

print("\nINDEPENDENT SPOT-CHECK: verbatim=%d MISSING=%d unfetchable=%d"
      % (total_ok, total_miss, total_err))
print("cited publisher orgs in corpus BEFORE this wave:", len(cited_orgs))