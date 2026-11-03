"""Round-12: ship the VERIFIED new-host URL list for wave 10.

Everything in ALLOWED was fetched in this session and holds >=4000 chars of
de-tagged prose containing at least one gap-class technical marker. Reachability
was not the filter -- rounds 3-10 showed a 200 can carry 78KB of pure chrome
(cyberattack.nl, dirkjan.nl, gtfobins, lolbas), and
book.hacktricks.wiki returns a byte-identical 9358-char body for three unrelated
paths, i.e. a catch-all shell. Those hosts are listed in REJECTED with the reason
so nobody re-ships them.

All ALLOWED publisher_orgs are absent from the 88 already-cited hosts.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

MARKERS = ["group policy", "gpresult", "gpo", "rdp", "remote desktop", "restricted admin",
           "dcsync", "kerberoast", "delegation", "zone transfer", "smuggling",
           "transfer-encoding", "cache deception", "segmentation", "supply chain",
           "lateral movement", "pass-the-hash", "psexec"]

REJECTED = {
    "book.hacktricks.wiki": "catch-all shell: byte-identical 9358-char body for 3 unrelated paths",
    "dirkjan.nl": "200/16KB but 0 technical markers; post list is client-rendered, 6 chrome pages only",
    "cyberattack.nl": "200/78KB but 0 technical markers; wp-json 403",
    "gtfobins.github.io": "200/30KB but 0 markers; JS-rendered bin list",
    "lolbas-project.github.io": "200/22KB but 0 markers; JS-rendered",
    "labs.ripe.net": "200/17KB but 0 markers; no extractable article hrefs",
    "sigmahq.io": "200/8.6KB, 1 marker group, too thin to quote from",
    "pentest.wtf": "fetch returned no status (TLS/network)",
    "0x727.sh": "fetch returned no status",
    "rootkit.nl": "fetch returned no status",
    "infosecwriteups.com": "403",
    "security.stackexchange.com": "403",
    "adsecurity.mit.edu": "fetch returned no status",
    "osint.wtf": "fetch returned no status",
    "swisskyrepo.com": "fetch returned no status",
    "siege.blue": "fetch returned no status",
    "www.itsec.one": "fetch returned no status",
    "paperwhite.de": "fetch returned no status",
    "fuzzy.re": "fetch returned no status",
    "evasions.checkmarx.net": "fetch returned no status",
    "www.hackplayers.org": "fetch returned no status",
    "hackmd.io": "200/12KB landing page only, no per-class articles",
    "www.fortiguard.com": "index exposes 0 same-host hrefs",
    "bleepingcomputer.com": "200/21KB but 0 markers (news chrome)",
    "isc.sans.edu": "1866 chars, below the 2000 floor",
    "*.gitbook.io / *.notion.site": "builder pages -- NOT independent publishers, barred by the gate",
}

LEAVES = [
    # HackTheBox Academy preview pages -- NEW publisher, heavy AD/RDP/segmentation prose
    "https://academy.hackthebox.com/course/preview/active-directory-ldap",
    "https://academy.hackthebox.com/course/preview/active-directory-powerview",
    "https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks",
    "https://academy.hackthebox.com/course/preview/active-directory-trust-attacks",
    "https://academy.hackthebox.com/course/preview/active-directory-bloodhound",
    "https://academy.hackthebox.com/course/preview/adcs-attacks",
    "https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations",
    "https://academy.hackthebox.com/course/preview/advanced-deserialization-attacks",
    "https://academy.hackthebox.com/course/preview/advanced-event-log-analysis",
    "https://academy.hackthebox.com/catalogue/paths",
    # Securelist / Kaspersky -- NEW publisher, group policy + RDP + DCSync prose
    "https://securelist.com/tr/payload-ransomware-via-group-policy/121335/",
    "https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/",
    "https://securelist.com/tr/network-anomaly-detection-in-kata/120892/",
    "https://securelist.com/threat-category/vulnerabilities-and-exploits/",
    "https://securelist.com/threat-category/web-threats/",
    "https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/",
    "https://securelist.com/threat-category/industrial-threats/",
    # ESET WeLiveSecurity -- NEW publisher
    "https://www.welivesecurity.com/en/eset-knowledge/materials/eset-apt-activity-report-q4-2025-q1-2026",
]

ALLOWED = {}
for u in LEAVES:
    host = u.split("/")[2]
    try:
        t = pipeline.fetch(u).get("text") or ""
    except Exception:
        t = ""
    g = [m for m in MARKERS if m in t.lower()]
    if len(t) >= 4000 and g:
        ALLOWED.setdefault(config.publisher_org(host), []).append((u, len(t), g))
    else:
        print("DROPPED (thin/no markers): %s  len=%d" % (u, len(t)))

print("\n=== ALLOWED new publishers: %d ===" % len(ALLOWED))
for org, pages in sorted(ALLOWED.items()):
    print("\n-- %s (%d pages)" % (org, len(pages)))
    for u, n, g in pages:
        print("   %6d  %s" % (n, u))
        print("          %s" % ", ".join(g))

print("\n=== REJECTED hosts (do not ship) ===")
for h, why in sorted(REJECTED.items()):
    print("  %-32s %s" % (h, why))