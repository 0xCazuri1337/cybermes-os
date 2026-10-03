"""Classify a MISS: print the stored quote, then search the live page for its
first N-word window and show the closest real span. An extraction artefact has a
near-identical span; a fabrication has nothing resembling it."""
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
                 ("*", ""), ("|", " "), ("\u201c", '"'), ("\u201d", '"')):
        s = s.replace(a, b)
    return WS.sub(" ", s)


def strip_md(q):
    for a, b in (("`", ""), ("*", ""), ("|", " "), ("\u00a0", " "), ("\u200b", "")):
        q = q.replace(a, b)
    return WS.sub(" ", q).strip()


def classify(url, quote):
    page = fetch(url)
    print("=" * 78)
    print("URL:", url)
    print("STORED QUOTE (%d chars):\n  %s" % (len(quote), quote))
    if strip_md(quote) in page:
        print("VERDICT: extraction artefact - verbatim after markdown/whitespace normalisation")
        return
    # sliding window over the first 8 words of the quote
    words = strip_md(quote).split()
    if len(words) < 4:
        print("VERDICT: INCONCLUSIVE - quote too short to classify")
        return
    head = " ".join(words[:8])
    best = (0.0, "")
    idx = page.find(words[0])
    while idx != -1:
        span = page[max(0, idx - 120): idx + 400]
        r = difflib.SequenceMatcher(None, head, span).quick_ratio()
        if r > best[0]:
            best = (r, span)
        idx = page.find(words[0], idx + 1)
    print("BEST REAL SPAN (sim %.2f):\n  %s" % (best[0], best[1].strip()))
    # also try a distinctive mid-fragment
    mid = " ".join(words[len(words) // 2: len(words) // 2 + 6])
    print("MID FRAGMENT %r found: %s" % (mid, mid in page))


con = sqlite3.connect("file:" + DB + "?mode=ro", uri=True)
cur = con.cursor()
keys = sys.argv[1:]
if not keys:
    print("usage: w9_classify_miss.py <item_key> [<item_key> ...]")
    raise SystemExit(2)
for key in keys:
    cur.execute("""select s.url, isr.quote from item i
                   join item_source isr on isr.item_id=i.id
                   join source s on s.id=isr.source_id where i.item_key=?""", (key,))
    r = cur.fetchone()
    if not r:
        print("=" * 78)
        print("no such item", key)
        continue
    classify(r[0], r[1])