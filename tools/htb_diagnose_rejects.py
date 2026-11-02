"""Diagnose the 3 remaining QUOTE_NOT_FOUND_ON_CITED_PAGE rejections.

Re-fetch each rejected item's own cited URLs and test its own quote, so the
verdict comes from the live page rather than from the build's local copy. The
two can differ: the build sliced a cached file, the gate reads the network, and
the cache is the thing most likely to be stale.
"""
import json
import re
import ssl
import sys
import urllib.request

sys.path.insert(0, ".")
from wks.verify_quotes import find_quote

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120"}

TARGETS = ["exposed_services", "service_enumeration", "smb", "xss"]


def fetch(u, tries=2):
    for _ in range(tries):
        try:
            r = urllib.request.urlopen(urllib.request.Request(u, headers=UA),
                                       timeout=30, context=ctx)
            return r.status, r.read().decode("utf-8", "replace")
        except Exception as e:
            last = e
    return None, str(last) if "last" in dir() else ""


for cls in TARGETS:
    p = f"research/incoming/htb_{cls}.json"
    try:
        raw = re.sub(r"\n\s*//\s*COMPLETE.*$", "", open(p, encoding="utf-8").read())
        d = json.loads(raw)
    except Exception as e:
        print(f"{cls}: cannot read {p}: {e}")
        continue
    for it in d["items"]:
        print(f"\n=== {it['item_key'][:60]} ===")
        for s in it["sources"]:
            status, body = fetch(s["url"])
            if status is None:
                print(f"  FETCH FAIL {s['publisher']:<18} {s['url'][:76]}")
                continue
            hit = find_quote(body, s["quote"])
            print(f"  {s['publisher']:<18} {status} {len(body):>7}b  "
                  f"quote_found={hit}")
            if not hit:
                print(f"     url   ={s['url'][:100]}")
                print(f"     quote ={s['quote'][:100]!r}")
                # is a distinctive fragment present at all?
                frag = re.sub(r"\s+", " ", s["quote"])[:40]
                print(f"     first 40 chars present verbatim? {frag in body}")
                norm = re.sub(r"\s+", " ", body)
                print(f"     first 40 chars present whitespace-normalised? {frag in norm}")