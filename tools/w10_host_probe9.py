"""Round-9: get real deep pages from the surviving NEW hosts.

WordPress sites render their post list client-side, so the index HTML carries no
post links (dirkjan.nl: 16 relative hrefs, all chrome; cyberattack.nl: 4, all
legal). The WordPress REST API exposes the same posts as plain JSON at
/wp-json/wp/v2/posts -- one fetch gives every real URL, which is the difference
between shipping a brief a child can use and one that burns its budget on 404s.

Also samples the 78KB cyberattack.nl body, because 78KB from an index is either
a very long page or a concatenated feed and worth knowing which.
"""
import json
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
MIN_CHARS = 3000

SITES = ["https://dirkjan.nl", "https://cyberattack.nl", "https://labs.ripe.net"]

for site in SITES:
    host = site.split("/")[2]
    print("\n=== %s ===" % site)
    urls = []
    for path in ("/wp-json/wp/v2/posts?per_page=40&_fields=link,title",
                 "/wp-json/wp/v2/pages?per_page=20&_fields=link,title"):
        try:
            raw = urllib.request.urlopen(
                urllib.request.Request(site + path, headers=UA), timeout=40).read()
            rows = json.loads(raw.decode("utf-8", "ignore"))
            urls.extend(r["link"] for r in rows if r.get("link"))
        except Exception as e:
            print("  api %-46s ERR %s %s" % (path.split("?")[0], type(e).__name__,
                                              str(e)[:50]))
    print("  %d candidate urls from wp-json" % len(urls))
    live = []
    for u in urls[:40]:
        try:
            n = len(pipeline.fetch(u).get("text") or "")
        except Exception:
            n = 0
        if n >= MIN_CHARS:
            live.append((n, u))
    for n, u in sorted(live, reverse=True)[:25]:
        print("  LIVE %6d  %s" % (n, u))
    print("  -> %d live of %d" % (len(live), min(len(urls), 40)))