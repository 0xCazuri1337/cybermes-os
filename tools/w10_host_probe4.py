"""Round-4 probe: LEAF pages on the surviving new hosts, chosen for the
wave-10 gap classes. Index pages are already shipped; this checks that the
specific deep pages a child would cite actually return real prose.

Gaps targeted: ad_group_policy, rdp (1 item / 0 fp each), cache_deception,
smuggling, dns_enum, segmentation_analysis, supply_chain, authn, misconfig.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

URLS = [
    # dirkjan.nl -- AD, and a web/infra researcher with real writeups
    "https://dirkjan.nl/kerberos/",
    "https://dirkjan.nl/ad/",
    "https://dirkjan.nl/attacker-controlled-pipe/",
    "https://dirkjan.nl/win/",
    "https://dirkjan.nl/rdp/",
    "https://dirkjan.nl/dns/",
    # hacktricks.wiki (book mirror, separate publisher org from hacktricks.owasp.org)
    "https://book.hacktricks.wiki/en/windows-hardening/active-directory-exploitation/",
    "https://book.hacktricks.wiki/en/generic-methodologies-and-resources/",
    "https://book.hacktricks.wiki/en/pentesting-methodologies/",
    # sigmahq.io
    "https://sigmahq.io/",
    "https://sigmahq.io/docs/",
    # cyberattack.nl -- red team notes
    "https://cyberattack.nl/",
    # labs.ripe.net -- network/infra recon
    "https://labs.ripe.net/",
    # gtfobins / lolbas -- LOLBins as evidence for AD/lateral classes
    "https://gtfobins.github.io/",
    "https://lolbas-project.github.io/",
    # hackthebox
    "https://academy.hackthebox.com/module/details/10",
]

for u in URLS:
    host = u.split("/")[2]
    try:
        r = pipeline.fetch(u)
        text = r.get("text") or ""
        st = r.get("http_status") or r.get("status")
        flag = "OK " if len(text) >= 2000 else "THIN"
        print("%-6s %-4s %6d  %s" % (flag, st, len(text), u))
    except Exception as e:
        print("ERR   %s %s" % (type(e).__name__, u))