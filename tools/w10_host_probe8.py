"""Round-8: find dirkjan.nl post URLs.

The index HTML only exposed chrome links (auteur/boeken/cartoon), because the
post list is rendered client-side. The de-tagged TEXT is 16KB, so the post
titles live there -- pull relative hrefs out of the raw HTML with a looser
pattern (no scheme, and also quoted with single quotes / unquoted).
"""
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}

for idx in ["https://dirkjan.nl/", "https://cyberattack.nl/"]:
    host = idx.split("/")[2]
    html = urllib.request.urlopen(
        urllib.request.Request(idx, headers=UA), timeout=30).read().decode("utf-8", "ignore")
    rel = set(re.findall(r'href=["\']?(/[^"\'>?#]+)', html))
    rel = sorted({r for r in rel if r.count("/") <= 2 and
                  not re.search(r"^/(wp-|feed|tag|category|author|page|xmlrpc)", r) and
                  not r.startswith("/cartoon")})
    print("\n=== %s relative hrefs: %d ===" % (idx, len(rel)))
    live = []
    for r in rel:
        u = "https://%s%s" % (host, r)
        try:
            n = len(pipeline.fetch(u).get("text") or "")
        except Exception:
            n = 0
        base = len(pipeline.fetch(idx).get("text") or "")
        if n >= 2000 and abs(n - base) > 300:   # a real distinct page, not the shell
            live.append((n, u))
    for n, u in sorted(live, reverse=True)[:40]:
        print("  LIVE %6d  %s" % (n, u))
    print("  -> %d distinct live pages" % len(live))