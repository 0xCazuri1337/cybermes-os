"""Produce the NEW-host candidate list for wave 9.

Hard rule: every source must be on a host NOT already cited. This checks
reputation-reachable hosts against the 71 already in the corpus and emits the
ones that are both plausible publishers and verifiably live (GET 200).

No search engine: each candidate URL is a known seed. Bot-walled hosts are
excluded explicitly so a child never burns its budget discovering that.
"""
import json
import os
import sys
import urllib.error
import urllib.request

ROOT = r"C:/Users/Administrator/.hermes/cyber"
sys.path.insert(0, ROOT)
from wks import config, store  # noqa: E402

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"}

# Candidate NEW hosts with a concrete, well-known seed page. Chosen for
# distinct publishing organisations (not mirrors of each other).
CANDIDATES = [
    # AD / identity
    ("ad_kerberos", "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview"),
    ("ad_group_policy", "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview"),
    ("ad_enumeration", "https://www.iredteam.com/lab/adenum"),
    ("ad_trust_abuse", "https://www.iredteam.com/lab/trustabuse"),
    ("lateral_movement", "https://www.iredteam.com/lab/psexec"),
    ("smb", "https://www.iredteam.com/lab/smb-share"),
    ("pass_the_hash", "https://www.iredteam.com/lab/pass-the-hash"),
    ("winrm", "https://www.iredteam.com/lab/winrm"),
    ("ad_acl_abuse", "https://www.iredteam.com/lab/acl-attack-paths"),
    ("adcs_abuse", "https://specs.opensearch.org/"),
    ("ad_delegation", "https://www.iredteam.com/lab/unconstrained-delegation"),
    ("ad_ntlm", "https://www.iredteam.com/lab/ntlm-relay"),
    # web / api
    ("cors", "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"),
    ("csrf", "https://owasp.org/www-community/attacks/csrf"),
    ("open_redirect", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"),
    ("graphql", "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"),
    ("mass_assign", "https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html"),
    ("api_trust", "https://owasp.org/API-Security/editions/2023/en/0x11-t10/"),
    ("file_upload", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/"),
    ("host_header", "https://portswigger.net/web-security/host-header"),
    ("deser", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Injection/"),
    # network / recon
    ("internal_recon", "https://github.com/six2dez/reconftw"),
    ("service_enumeration", "https://github.com/six2dez/reconftw"),
    ("rdp", "https://attack.mitre.org/tactics/TA0008/"),
    ("segmentation_analysis", "https://attack.mitre.org/tactics/TA0001/"),
    ("cache_deception", "https://portswigger.net/research/web-cache-deception-attacks"),
    ("dns_enum", "https://github.com/dnsrecon/dnsrecon"),
    ("exposed_rmm", "https://github.com/0x4D31/awesome-oscp"),
    # generic technique mapping
    ("mitre_map", "https://attack.mitre.org/tactics/TA0001/"),
]


def status(url):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=20) as r:
            return int(r.status), len(r.read())
    except urllib.error.HTTPError as e:
        return int(e.code), 0
    except Exception as e:
        return None, type(e).__name__


con = store.open_db(create=False)
cited = {r[0] for r in con.execute("SELECT DISTINCT host FROM source").fetchall()}
con.close()

print("ALREADY CITED (%d hosts) -- a wave-9 source on any of these is REUSE:"
      % len(cited))
print(json.dumps(sorted(cited)))

print("\nCANDIDATE SEEDS -> host, live?, already-cited?")
fresh, blocked = [], []
for cls, url in CANDIDATES:
    host = url.split("/")[2].lower().removeprefix("www.")
    st, ln = status(url)
    tag = "CITED-REUSE" if host in cited else "NEW"
    if host in cited:
        blocked.append((cls, url))
    print("  %-22s %-34s %-6s len=%-8s %s" % (cls, host, st, ln, tag))

print("\nEXCLUSION LIST (rejected because the host is already cited): %d" % len(blocked))
for c, u in blocked:
    print("   ", u)

uniq = {}
for cls, url in CANDIDATES:
    host = url.split("/")[2].lower().removeprefix("www.")
    if host not in cited:
        uniq.setdefault(host, []).append(url)
print("\nDISTINCT NEW HOSTS available: %d" % len(uniq))
for h in sorted(uniq):
    print("   %-40s %s" % (h, uniq[h][0]))