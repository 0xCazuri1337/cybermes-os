"""Round-7: extract REAL leaf URLs from new-host index pages.

`pipeline.fetch` returns de-tagged text only (keys: text/url/status/... -- no
`html`), so hrefs cannot be recovered from it. This raw-fetches the index HTML,
extracts same-host hrefs, then GET-verifies each through pipeline.fetch so the
brief ships live URLs only. Guessing paths from a topic name is the documented
way to waste a child's whole fetch budget (every dirkjan.nl guess 404'd).
"""
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
INDEXES = ["https://dirkjan.nl/", "https://cyberattack.nl/", "https://sigmahq.io/"]

for idx in INDEXES:
    host = idx.split("/")[2]
    try:
        req = urllib.request.Request(idx, headers=UA)
        html = urllib.request.urlopen(req, timeout=30).read().decode("utf-8", "ignore")
    except Exception as e:
        print("INDEX ERR", idx, type(e).__name__, str(e)[:60])
        continue
    hrefs = sorted(set(re.findall(r'href="(https?://%s/[^"#?]*)"' % re.escape(host), html)))
    hrefs = [h for h in hrefs
             if not re.search(r"/(wp-content|wp-includes|css|js|feed|tag|category|page)/\d", h)
             and h.count("/") <= 5]
    print("\n=== %s : %d candidate hrefs ===" % (idx, len(hrefs)))
    live = 0
    for h in hrefs[:60]:
        try:
            r = pipeline.fetch(h)
            n = len(r.get("text") or "")
        except Exception:
            n = 0
        if n >= 2000:
            live += 1
            print("  LIVE %6d  %s" % (n, h))
    print("  -> %d live of %d scanned" % (live, min(len(hrefs), 60)))