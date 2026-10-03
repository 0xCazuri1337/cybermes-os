import os, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline

CACHE = Path(os.environ.get("TMPDIR") or os.path.expanduser("~")) / "w10cache2"
CACHE.mkdir(parents=True, exist_ok=True)

URLS = [
 "https://academy.hackthebox.com/course/preview/active-directory-ldap",
 "https://academy.hackthebox.com/course/preview/active-directory-powerview",
 "https://academy.hackthebox.com/course/preview/active-directory-trust-attacks",
 "https://academy.hackthebox.com/course/preview/active-directory-bloodhound",
 "https://academy.hackthebox.com/course/preview/adcs-attacks",
 "https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks",
 "https://securelist.com/tr/payload-ransomware-via-group-policy/121335/",
 "https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/",
 "https://securelist.com/tr/network-anomaly-detection-in-kata/120892/",
 "https://www.welivesecurity.com/en/eset-research/eset-apt-activity-report-q4-2025-q1-2026",
]

import hashlib
idx = CACHE / "index.txt"
lines = []
for u in URLS:
    p = CACHE / (hashlib.md5(u.encode()).hexdigest()[:12] + ".txt")
    if not p.exists():
        r = pipeline.fetch(u, limit=1_500_000)
        if not r.get("ok"):
            print("ERR", u, r.get("status"), r.get("error")); lines.append(u + "\tERR"); continue
        t = r["text"]
        p.write_text(t, encoding="utf-8")
        print("FETCHED", len(t), u)
    t = p.read_text(encoding="utf-8")
    print("CACHED", len(t), u)
    lines.append(u + "\t" + str(p))
idx.write_text("\n".join(lines), encoding="utf-8")
print("CACHE", CACHE)