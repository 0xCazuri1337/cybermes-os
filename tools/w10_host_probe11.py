"""Round-11: final leaf extraction for wave-10's usable NEW hosts.

Rounds 3-10 established that reachability is the wrong filter. A 200 with 78KB
and ZERO technical markers (cyberattack.nl, dirkjan.nl, gtfobins, lolbas) is a
client-rendered shell; book.hacktricks.wiki returns a byte-identical 9358-char
body for three unrelated paths, i.e. a catch-all. None of those are citable.

Confirmed hosts holding real prose on the gap classes: securelist.com,
fortiguard.com, welivesecurity.com, sigmahq.io, academy.hackthebox.com.
This extracts real article URLs from each index and verifies them, so the brief
ships LEAF pages with prose -- not index shells.
"""
import re
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
MARKERS = ["group policy", "gpresult", "gpo", "rdp", "remote desktop", "restricted admin",
           "dcsync", "kerberoast", "delegation", "zone transfer", "smuggling",
           "transfer-encoding", "cache deception", "segmentation", "supply chain",
           "lateral movement", "pass-the-hash", "psexec"]
MIN_CHARS = 4000

INDEXES = [
    "https://securelist.com/",
    "https://www.fortiguard.com/",
    "https://www.welivesecurity.com/",
    "https://academy.hackthebox.com/",
    "https://labs.ripe.net/",
]


def groups(t):
    return [m for m in MARKERS if m in t.lower()]


for idx in INDEXES:
    host = idx.split("/")[2]
    try:
        html = urllib.request.urlopen(
            urllib.request.Request(idx, headers=UA), timeout=30).read().decode("utf-8", "ignore")
    except Exception as e:
        print("INDEX ERR", idx, type(e).__name__, str(e)[:50])
        continue
    hrefs = sorted(set(re.findall(r'href="(https?://%s/[^"#?]*)"' % re.escape(host), html)))
    hrefs = [h for h in hrefs if h != idx.rstrip("/") and
             not re.search(r"/(tag|category|author|feed|about|contact|privacy|legal)", h)]
    print("\n=== %s org=%s : %d hrefs ===" % (idx, config.publisher_org(host), len(hrefs)))
    found = 0
    for u in hrefs[:35]:
        try:
            t = pipeline.fetch(u).get("text") or ""
        except Exception:
            continue
        g = groups(t)
        if len(t) >= MIN_CHARS and g:
            found += 1
            print("  LIVE %6d  %-2d  %s" % (len(t), len(g), u))
            print("            %s" % ", ".join(g[:9]))
    print("  -> %d citable leaf pages" % found)