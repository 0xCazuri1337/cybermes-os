"""Probe a WIDE set of reputable publishers for hosts that are BOTH uncited in
the corpus AND verifiably live (GET 200). Emits the wave-9 host allowlist plus
the explicit exclusion list. No search engine: every URL is a known seed.
"""
import json
import os
import sys
import urllib.error
import urllib.request

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
from wks import store  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}

# (label, seed url) - deliberately spread across distinct organisations.
SEEDS = [
    # --- AD / identity / red team ---
    ("ired", "https://www.ired.team/lab/adenum"),
    ("ired2", "https://www.ired.team/"),
    ("adsecurity", "https://adsecurity.ms/"),
    ("madderley", "https://lab.adsecurity.ms/"),
    ("w pentest", "https://www.wizpentest.com/"),
    ("orange Tsai", "https://blog.orange.tw/"),
    # --- web research / vendor labs ---
    ("sonatype", "https://www.sonatype.com/blog"),
    ("veracode", "https://www.veracode.com/blog/"),
    ("checkmarx", "https://checkmarx.com/feed/"),
    ("snyk", "https://security.snyk.io/"),
    ("jupiter", "https://www.sonarsource.com/blog/"),
    ("detectify", "https://www.detectify.com/blog"),
    ("probely", "https://www.probely.com/blog"),
    ("burp lab", "https://portswigger.net/research"),
    ("zscaler", "https://www.zscaler.com/blogs/security-research"),
    ("mitel", "https://www.mitel.com/blog"),
    ("rapid7", "https://www.rapid7.com/blog/"),
    ("horiz3", "https://horizon3.ai/attack-knowledge/materials/"),
    ("watchtowr", "https://labs.watchtowr.com/"),
    ("claroty", "https://www.claroty.com/blog"),
    ("suzanne", "https://suzanne.shannonba.com/"),
    ("assetnote", "https://www.assetnote.io/resources/blog/"),
    ("binaryfellows", "https://binaryfellows.com/"),
    ("orange cyverse", "https://cyverse.com/blog"),
    ("cyentis", "https://cyentis.com/"),
    ("horizon3p", "https://www.horizon3.ai/"),
    ("redcanary", "https://redcanary.com/blog/"),
    ("elastic", "https://www.elastic.co/blog/"),
    ("wiz", "https://www.wiz.io/blog"),
    ("orca", "https://www.orcasecurity.io/blog"),
    ("docker", "https://www.docker.com/blog/"),
    ("datadoghq", "https://www.datadoghq.com/blog/"),
    ("trailofbits", "https://blog.trailofbits.com/"),
    ("verizon", "https://www.verizon.com/about/blog/"),
    ("paloalto", "https://www.paloaltonetworks.com/blog"),
    ("f5", "https://www.f5.com/blog"),
    ("fastly", "https://www.fastly.com/blog"),
    ("akamai", "https://www.akamai.com/blog"),
    ("netlify", "https://www.netlify.com/blog"),
    ("gitlab", "https://about.gitlab.com/blog/"),
    ("atlassian", "https://www.atlassian.com/blog"),
    ("doppler", "https://www.doppler.com/blog"),
    ("snyk2", "https://snyk.io/blog"),
    ("sysdig", "https://sysdig.com/blog/"),
    ("paloalto2", "https://unit42.paloaltonetworks.com/"),
    ("googlecloud", "https://cloud.google.com/blog/products/identity-security"),
    ("gcp", "https://security.googleblog.com/"),
    # --- protocol / standards (authoritative, distinct orgs) ---
    ("datatracker", "https://datatracker.ietf.org/doc/html/rfc6749"),
    ("rfc", "https://www.rfc-editor.org/rfc/rfc6749"),
    ("w3c", "https://www.w3.org/TR/webarch/"),
    ("ietf", "https://www.ietf.org/rfc/rfc8446.html"),
    ("whatwg", "https://html.spec.whatwg.org/multipage/"),
    ("unicode", "https://www.unicode.org/versions/Unicode16.0.0/"),
    ("cwe", "https://cwe.mitre.org/data/definitions/79.html"),
    ("capec", "https://capec.mitre.org/data/definitions/1000.html"),
    ("mitreattack", "https://attack.mitre.org/techniques/T1059/"),
    ("nist", "https://csrc.nist.gov/pubs/sp/800/63/final"),
    ("nvd", "https://nvd.nist.gov/vuln/detail/CVE-2024-45409"),
    ("cve", "https://www.cve.org/CVERecord?id=CVE-2024-45409"),
    ("osquery", "https://osquery.io/"),
    ("sysinternals", "https://learn.microsoft.com/en-us/sysinternals/"),
    ("elastic2", "https://www.elastic.co/guide/en/elasticsearch/reference/current/index.html"),
    # --- appsec orgs not yet cited ---
    ("modsecurity", "https://www.modsecurity.org/"),
    ("suricata", "https://suricata.io/"),
    ("wafw00f", "https://github.com/EnableSecurity/wafw00f"),
    ("nuclei", "https://docs.projectdiscovery.io/templates/introduction"),
    ("nikto", "https://github.com/sullo/nikto"),
    ("zaproxy", "https://www.zaproxy.org/docs/"),
    ("arachni", "https://github.com/railsware/arachni"),
    ("skipfish", "https://code.google.com/archive/p/skipfish/"),
    ("w3af", "https://github.com/AndreyBunkov/w3af"),
    ("whatweb", "https://github.com/urbanadventurer/WhatWeb"),
    ("gobuster", "https://github.com/OJ/gobuster"),
    ("ffuf", "https://github.com/ffuf/ffuf"),
    ("feroxbuster", "https://github.com/epi052/ feroxbuster"),
    ("kiterunner", "https://github.com/assetnote/kiterunner"),
    ("jaeles", "https://github.com/jaeles-project/jaeles"),
    ("katana", "https://github.com/projectdiscovery/katana"),
    ("httpx", "https://github.com/projectdiscovery/httpx"),
]


def status(url):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=18) as r:
            return int(r.status), len(r.read())
    except urllib.error.HTTPError as e:
        return int(e.code), 0
    except Exception as e:
        return None, type(e).__name__


con = store.open_db(create=False)
cited = {r[0] for r in con.execute("SELECT DISTINCT host FROM source").fetchall()}
con.close()

live_new, dead, reused = [], [], []
for label, url in SEEDS:
    url = url.replace(" ", "")
    host = url.split("/")[2].lower().removeprefix("www.")
    st, ln = status(url)
    row = (label, host, url, st, ln, host in cited)
    if st != 200:
        dead.append(row)
        continue
    (reused if host in cited else live_new).append(row)

print("=== LIVE + UNCITED (wave-9 allowlist) ===")
for label, host, url, st, ln, _ in live_new:
    print("  %-14s %-42s %s" % (label, host, url))

print("\n=== REUSE REJECTED (host already in corpus) ===")
for label, host, url, st, ln, _ in reused:
    print("  %-14s %-42s" % (label, host))

print("\n=== NOT USABLE (dead / unreachable) ===")
for label, host, url, st, ln, _ in dead:
    print("  %-14s %-42s status=%s (%s)" % (label, host, st, ln))

print("\nallowlist size: %d distinct hosts" % len({h for _, h, *_ in live_new}))

out = {"allowlist": [{"label": l, "host": h, "url": u} for l, h, u, *_ in live_new],
       "excluded_reuse": [{"label": l, "host": h} for l, h, *_ in reused],
       "unusable": [{"label": l, "host": h, "status": s} for l, h, _, s, *_ in dead]}
with open(os.path.join(ROOT, "research", "w9_hosts.json"), "w") as f:
    json.dump(out, f, indent=1)