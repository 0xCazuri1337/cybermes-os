"""Independent audit of PROMOTED items (parent-side, no child trust).

1. Re-fetch every cited URL of a sample and confirm each recorded quote is on the page,
   using the GATE'S OWN matcher (wks.verify_quotes.find_quote) after
   tools/w9_validate_checker.py proved it both ways.
2. Re-derive the publisher rule on what actually got promoted: builder hosts and
   same-organisation host pairs must not satisfy the >=2 publisher rule.

Usage: python tools/w9_parent_audit.py [sample_size]
"""
import html
import json
import os
import random
import re
import sqlite3
import sys
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB = os.path.join(ROOT, "db", "wks.db")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
TAG = re.compile(r"<[^>]+>")
WS = re.compile(r"\s+")


def fetch(url, timeout=35):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
    s = raw.decode("utf-8", "ignore")
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", s)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    s = s.replace("\u00a0", " ").replace("\u200b", "").replace("\u2019", "'")
    return WS.sub(" ", s)


def norm(q):
    q = q.replace("\u00a0", " ").replace("\u200b", "").replace("\u2019", "'")
    return WS.sub(" ", q).strip()


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 12
    con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
    cur = con.cursor()

    # ---- 2. publisher-rule re-derivation over ALL promoted items -------------
    sys.path.insert(0, ROOT)
    from wks.config import publisher_org, is_builder_host
    from wks.verify_quotes import find_quote
    cur.execute("""select i.id, i.item_key, i.class_id, s.host
                   from item i join item_source isr on isr.item_id=i.id
                   join source s on s.id=isr.source_id
                   join quality q on q.item_id=i.id
                   where q.validation_state='high_confidence'""")
    rows = cur.fetchall()
    per = {}
    for iid, key, cls, host in rows:
        per.setdefault(iid, {"key": key, "class": cls, "hosts": set()})["hosts"].add(host)
    offenders = []
    for iid, d in per.items():
        real = [h for h in d["hosts"] if not is_builder_host(h)]
        orgs = {publisher_org(h) for h in real}
        if len(orgs) < 2:
            offenders.append((iid, d["key"], sorted(real), sorted(orgs)))
    print("promoted items audited for publisher rule:", len(per))
    print("promoted items failing >=2 distinct publisher ORGS:", len(offenders))
    for o in offenders[:10]:
        print("   OFFENDER", o)

    # ---- 1. live quote re-derivation on a sample ---------------------------
    cur.execute("""select i.id, i.item_key, i.class_id, s.url, s.host, isr.quote
                   from item i join item_source isr on isr.item_id=i.id
                   join source s on s.id=isr.source_id
                   join quality q on q.item_id=i.id
                   where q.validation_state='high_confidence'""")
    allrows = cur.fetchall()
    ids = sorted({r[0] for r in allrows})
    sample_items = random.sample(ids, min(n, len(ids)))
    want = set(sample_items)
    srows = [r for r in allrows if r[0] in want]
    cache = {}
    ok = miss = err = 0
    misses = []
    for iid, key, cls, url, host, quote in srows:
        if url not in cache:
            try:
                cache[url] = fetch(url)
            except Exception as e:
                cache[url] = None
                err += 1
                print("  FETCH_FAIL", url, type(e).__name__, str(e)[:80])
        page = cache[url]
        if page is None:
            continue
        if find_quote(page, quote):
            ok += 1
        else:
            miss += 1
            misses.append((key, cls, host, url, quote[:90]))
    print("\nQUOTE RE-DERIVATION over %d items / %d citations (seed 20261002)"
          % (len(sample_items), len(srows)))
    print("  verbatim present:", ok, " MISSING:", miss, " unfetchable urls:", err)
    for m in misses[:12]:
        print("   MISS", m)

    json.dump({"promoted": len(per), "publisher_offenders": offenders,
               "quotes_ok": ok, "quotes_missing": miss,
               "unfetchable": err, "misses": misses},
              open(os.path.join(ROOT, "research", "w9_parent_audit.json"), "w"),
              indent=1, default=str)


main()