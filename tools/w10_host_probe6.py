"""Round-6: what keys does pipeline.fetch actually return, and what are the real
dirkjan.nl / cyberattack.nl hrefs? (round 5 found fetch() has no 'html' key)"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline  # noqa: E402

r = pipeline.fetch("https://dirkjan.nl/")
print("fetch keys:", sorted(r.keys()))
for k, v in sorted(r.items()):
    if isinstance(v, str):
        print("  %-12s len=%d" % (k, len(v)))

blob = " ".join(str(v) for v in r.values() if isinstance(v, str))
hrefs = sorted(set(re.findall(r'https?://dirkjan\.nl/[a-z0-9\-_]+/?', blob)))
hrefs = [h for h in hrefs if "wp-includes" not in h and "wp-content" not in h]
print("\ndirkjan.nl hrefs (%d):" % len(hrefs))
for h in hrefs:
    print("  ", h)

r2 = pipeline.fetch("https://cyberattack.nl/")
blob2 = " ".join(str(v) for v in r2.values() if isinstance(v, str))
h2 = sorted(set(re.findall(r'https?://cyberattack\.nl/[a-z0-9\-_]+/?', blob2)))
print("\ncyberattack.nl hrefs (%d):" % len(h2))
for h in h2[:40]:
    print("  ", h)