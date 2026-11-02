"""Dump the top quotable spans for every NETWORK source in the pool.

Writes nspans.json so the item author can select quotes that actually support
the claim, instead of guessing. Each entry records the exact cached text, so
selection cannot introduce a character the gate will not see.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fetch_pool import POOL  # noqa: E402
from mine import mine  # noqa: E402

# Per-URL probes: what a network item would want to quote from that page.
PROBE_PATTERNS: dict[str, str] = {
    "https://attack.mitre.org/techniques/T1558/003/": r"RC4|offline Brute Force|TGS-REP",
    "https://attack.mitre.org/techniques/T1558/004/": r"preauthentication|AS-REP",
    "https://attack.mitre.org/techniques/T1558/001/": r"KRBTGT|forg",
    "https://attack.mitre.org/techniques/T1550/003/": r"Pass the Ticket|Kerberos ticket",
    "https://attack.mitre.org/techniques/T1550/002/": r"Pass the Hash|NTLM hash",
    "https://attack.mitre.org/techniques/T1557/001/": r"relay|NTLMv1",
    "https://attack.mitre.org/techniques/T1134/003/": r"delegat|ADD",
    "https://attack.mitre.org/techniques/T1222/001/": r"DACL|GUID|permission",
    "https://attack.mitre.org/techniques/T1484/": r"trust settings|forge access tokens",
    "https://attack.mitre.org/techniques/T1484/001/": r"SYSVOL|GPOs are containers",
    "https://attack.mitre.org/techniques/T1649/": r"AD CS|certificate",
    "https://attack.mitre.org/techniques/T1110/003/": r"spray|lockout",
    "https://attack.mitre.org/techniques/T1087/002/": r"LDAP|netlogon|Domain Account",
    "https://attack.mitre.org/techniques/T1087/": r"account|permission",
    "https://attack.mitre.org/techniques/T1003/": r"credential",
    "https://attack.mitre.org/techniques/T1003/006/": r"DCSync|ntds.dit|NTDS",
    "https://attack.mitre.org/techniques/T1021/002/": r"SMB|NetBIOS|Named Pipe",
    "https://attack.mitre.org/techniques/T1021/001/": r"RDP|Remote Desktop",
    "https://attack.mitre.org/techniques/T1021/006/": r"WinRM",
    "https://attack.mitre.org/techniques/T1021/": r"Remote Services|protocol",
    "https://attack.mitre.org/techniques/T1046/": r"banner|port|fingerprint",
    "https://attack.mitre.org/techniques/T1018/": r"Remote System Discovery",
    "https://attack.mitre.org/techniques/T1016/001/": r"DNS|Network Service Discovery",
    "https://attack.mitre.org/techniques/T1090/": r"proxy|Proxy",
    "https://attack.mitre.org/techniques/T1133/": r"External Remote Services",
    "https://attack.mitre.org/techniques/T1135/": r"Network Share Discovery",
    "https://attack.mitre.org/techniques/T1219/": r"Remote Monitoring|RMM|remote management",
    "https://attack.mitre.org/tactics/TA0008/": r"Lateral Movement",
    "https://attack.mitre.org/tactics/TA0006/": r"Credential Access",
    "https://attack.mitre.org/tactics/TA0001/": r"Initial Access",
    "https://attack.mitre.org/tactics/TA0005/": r"Lateral Movement",
    "https://attack.mitre.org/tactics/TA0043/": r"Reconnaissance",
    "https://www.rfc-editor.org/rfc/rfc4120.html": r"TGS-REQ|AS-REQ|delegat",
    "https://www.rfc-editor.org/rfc/rfc4511.html": r"SearchRequest.filter|search filter|filter",
    "https://www.rfc-editor.org/rfc/rfc5280.html": r"certification path|certificate",
    "https://www.rfc-editor.org/rfc/rfc1918.html": r"private|10\.0\.0\.0|172\.16|192\.168",
    "https://www.rfc-editor.org/rfc/rfc1035.html": r"zone transfer|AXFR|SOA",
    "https://www.rfc-editor.org/rfc/rfc4459.html": r"tunnel|Tunnel",
    "https://www.rfc-editor.org/rfc/rfc6335.html": r"service name|SERVICES",
    "https://www.rfc-editor.org/rfc/rfc1002.html": r"NetBIOS|SMB",
    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/": r"NTLM|authenticat",
    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/": r"trust|Trust|directory",
    "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/": r"certificate|enroll",
    "https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control": r"access control|DACL|SACL",
    "https://learn.microsoft.com/en-us/windows/win32/winrm/portal": r"WinRM|WS-Management|HTTP",
    "https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol": r"RDP|Remote Desktop|topologies",
    "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top": r"DNS|name resolution",
    "https://learn.microsoft.com/en-us/windows-server/networking/": r"network|Windows",
    "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html": r"brute|lockout|rate limit|multi-factor",
    "https://cwe.mitre.org/data/definitions/294.html": r"Capture-replay|replay",
    "https://cwe.mitre.org/data/definitions/863.html": r"Incorrect Authorization|authorization",
    "https://cwe.mitre.org/data/definitions/200.html": r"Exposure of Sensitive Information|sensitive",
    "https://cwe.mitre.org/data/definitions/269.html": r"Improper Privilege Management|privilege",
    "https://cwe.mitre.org/data/definitions/522.html": r"credentials|password",
    "https://cwe.mitre.org/data/definitions/90.html": r"LDAP|injection|Special Element",
    "https://cwe.mitre.org/data/definitions/284.html": r"Improper Access Control|access",
    "https://cwe.mitre.org/data/definitions/521.html": r"Weak Password|password",
    "https://cwe.mitre.org/data/definitions/1188.html": r"Insecure Default|default",
    "https://cwe.mitre.org/data/definitions/295.html": r"Improper Certificate Validation|certificate",
    "https://cwe.mitre.org/data/definitions/732.html": r"permissions|assignment",
    "https://cwe.mitre.org/data/definitions/16.html": r"Configuration|configuration",
    "https://cwe.mitre.org/data/definitions/287.html": r"Improper Authentication|authentication",
}

out: dict[str, list[str]] = {}
for url, host, stype in POOL:
    pat = PROBE_PATTERNS.get(url)
    if not pat:
        continue
    spans = mine(url, pat, limit=14)
    if spans:
        out[url] = spans
        print(f"### {url}  ({len(spans)} spans)")
        for s in spans:
            print("   -", s[:260].replace("\n", " "))
    else:
        print(f"### {url}  (no spans)")

Path("nspans.json").write_text(
    json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
print(f"\nurls with spans: {len(out)}")
