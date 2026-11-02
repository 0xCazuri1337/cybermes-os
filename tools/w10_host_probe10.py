"""Round-10: does the surviving new-host corpus actually contain the PROSE the
wave-10 gap classes need?

A host with 78KB of body text is useless if the text is a nav bar. This samples
real technical markers out of the de-tagged text of every host that returned
>=2000 chars, so the brief ships hosts that hold content, not pages that hold
chrome. Also probes a final batch of candidate publisher hosts.

Gaps targeted: ad_group_policy, rdp, cache_deception, smuggling, dns_enum,
segmentation_analysis, supply_chain, authn.
"""
import sys
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from wks import pipeline, config  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}

MARKERS = {
    "group policy": ["Group Policy", "gpresult", "GPO"],
    "rdp": ["RDP", "Remote Desktop", "NLA", "Restricted Admin"],
    "kerberos/dcsync": ["DCSync", "Kerberoasting", "delegation"],
    "dns enum": ["zone transfer", "AXFR", "dnsrecon"],
    "smuggling": ["smuggling", "Transfer-Encoding", "CL.TE"],
    "cache deception": ["cache deception", "web cache"],
    "segmentation": ["segmentation", "firewall", "pivot"],
    "supply chain": ["supply chain", "CI/CD", "pipeline"],
    "lateral": ["lateral movement", "Pass-the-Hash", "PsExec"],
}

CANDIDATES = [
    "https://cyberattack.nl/",
    "https://gtfobins.github.io/",
    "https://lolbas-project.github.io/",
    "https://sigmahq.io/",
    "https://labs.ripe.net/",
    "https://academy.hackthebox.com/",
    "https://book.hacktricks.wiki/en/windows-hardening/active-directory-exploitation/",
    "https://dirkjan.nl/faq/",
]

FRESH = [
    "https://pentest.kg/",
    "https://hackers.lol/",
    "https://redacted.com/",
    "https://www.hackplayers.org/en/",
    "https://blog.pepsired.com/",
    "https://msrc.nvd/",
    "https://www.bleepingcomputer.com/",
    "https://security.stackexchange.com/questions/tagged/active-directory",
    "https://reverse.engineering/",
    "https://www.welivesecurity.com/",
    "https://securelist.com/",
    "https://unit42.paloaltonetworks.com/",
    "https://www.fortiguard.com/",
    "https://isc.sans.edu/",
    "https://www.inciple.com/mattifesto/",
]

CITED = {config.publisher_org(h) for h in ["owasp.org", "portswigger.net", "github.com",
                                           "microsoft.com", "hackthebox.com"]}


def body(u):
    try:
        return pipeline.fetch(u).get("text") or ""
    except Exception:
        return ""


print("=== content markers in surviving hosts ===")
for u in CANDIDATES:
    t = body(u)
    if not t:
        print("  DEAD %s" % u)
        continue
    hits = [g for g, ms in MARKERS.items() if any(m.lower() in t.lower() for m in ms)]
    print("  %6d  %-2d groups  %s" % (len(t), len(hits), u))
    print("        %s" % (", ".join(hits) or "NO technical markers"))

print("\n=== fresh candidates ===")
for u in FRESH:
    host = u.split("/")[2]
    org = config.publisher_org(host)
    t = body(u)
    if not t:
        try:
            urllib.request.urlopen(urllib.request.Request(u, headers=UA), timeout=15)
            code = 200
        except Exception as e:
            code = getattr(e, "code", type(e).__name__)
        print("  %-58s %s thin" % (u, code))
        continue
    hits = [g for g, ms in MARKERS.items() if any(m.lower() in t.lower() for m in ms)]
    print("  %-58s %6d  %2d groups org=%s" % (u, len(t), len(hits), org))
    print("        %s" % (", ".join(hits) or "NO technical markers"))