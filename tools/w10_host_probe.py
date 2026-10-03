"""Probe candidate NEW publisher hosts for reachability + real prose.

Prints: url, status, length, publisher_org. A host is only worth putting in a
child brief if it returns >=2000 chars of de-tagged prose (a JS shell that
returns 200 proves nothing).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

URLS = [
    "https://lazcacer.github.io/Azure-Red-Team/",
    "https://noraj.github.io/",
    "https://gtfobins.github.io/",
    "https://lolbas-project.github.io/",
    "https://dsinternals.com/",
    "https://secgeek.io/",
    "https://dirkjan.nl/",
    "https://pentest.wtf/",
    "https://0x727.sh/",
    "https://rootkit.nl/",
    "https://lolnethunter.github.io/",
    "https://github.io/",
    "https://sigmahq.io/",
]

for u in URLS:
    host = u.split("/")[2]
    try:
        r = pipeline.fetch(u)
        t = r.get("text") or ""
        st = r.get("http_status") or r.get("status")
        print("%-46s %s %6d  org=%s" % (u, st, len(t),
                                        config.publisher_org(host)))
    except Exception as e:
        print("%-46s ERR %s %s" % (u, type(e).__name__, str(e)[:80]))