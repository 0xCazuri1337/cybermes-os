"""Classify ONE citation miss precisely: the exact (item_key, host) pair the audit
flagged. Prints the stored quote, the live page region around a distinctive
mid-fragment, and a char-level diff of the two. An extraction artefact shows a
near-identical region; a fabrication shows nothing resembling it.

Usage: python tools/w9_classify_miss2.py <item_key> <host>
"""
import difflib
import html
import os
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


def fetch(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=35) as r:
        raw = r.read()
    s = raw.decode("utf-8", "ignore")
    s = re.sub(r"(?is)<(script|style|nav|footer)[^>]*>.*?</\1>", " ", s)
    s = TAG.sub(" ", s)
    s = html.unescape(html.unescape(s))
    for a, b in (("\u00a0", " "), ("\u200b", ""), ("\u2019", "'"), ("`", ""),
                 ("*", ""), ("|", " "), ("\u201c", '"'), ("\u201d", '"'),
                 ("\u2014", "-"), ("\u2013", "-")):
        s = s.replace(a, b)
    return WS.sub(" ", s)


def strip_md(q):
    for a, b in (("`", ""), ("*", ""), ("|", " "), ("\u00a0", " "), ("\u200b", ""),
                 ("\u2019", "'"), ("\u2014", "-"), ("\u2013", "-")):
        q = q.replace(a, b)
    return WS.sub(" ", q).strip()


def classify(key, host):
    con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
    cur = con.cursor()
    cur.execute("""select s.url, isr.quote, i.claim from item i
                   join item_source isr on isr.item_id=i.id
                   join source s on s.id=isr.source_id
                   where i.item_key=? and s.host=?""", (key, host))
    rows = cur.fetchall()
    print("=" * 78)
    print("ITEM:", key, " HOST:", host, " citations on this host:", len(rows))
    if not rows:
        print("  no citation on that host - audit row was stale")
        return
    for url, quote, claim in rows:
        page = fetch(url)
        q = strip_md(quote)
        print("-" * 78)
        print("URL:", url)
        print("CLAIM:", (claim or "")[:180])
        print("STORED QUOTE:\n ", quote)
        if q in page:
            print("VERDICT: extraction artefact (verbatim after normalisation)")
            continue
        words = q.split()
        mid_i = len(words) // 2
        frag = " ".join(words[mid_i:mid_i + 6])
        idx = page.find(frag)
        if idx == -1:
            # try progressively shorter fragments
            for ln in (5, 4, 3):
                frag = " ".join(words[mid_i:mid_i + ln])
                idx = page.find(frag)
                if idx != -1:
                    break
        if idx == -1:
            print("VERDICT: NO RESEMBLING SPAN - mid fragment %r absent" % frag)
            print("  page length:", len(page))
            continue
        region = page[max(0, idx - 200): idx + 260]
        print("MID FRAGMENT %r FOUND. LIVE REGION:\n  %s" % (frag, region.strip()))
        sm = difflib.SequenceMatcher(None, q, region)
        blocks = [b for b in sm.get_matching_blocks() if b.size >= 4]
        print("  longest common blocks:", sorted((b.size for b in blocks), reverse=True)[:6],
              " ratio=%.3f" % sm.quick_ratio())


if len(sys.argv) < 3:
    print(__doc__)
    raise SystemExit(2)
classify(sys.argv[1], sys.argv[2])