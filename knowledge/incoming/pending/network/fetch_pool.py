"""Fetch the NETWORK source pool into ncache. Prints liveness per URL.

Run:  python fetch_pool.py
Then:  python fetch_pool.py --refresh   (re-fetch everything, no cache)
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from ncache import get  # noqa: E402

# URL -> (host, source_type). Two DISTINCT hosts per class is the gate
# (config.MIN_PUBLISHER_HOSTS=2); the pairs below are chosen to be independent
# publishers (IETF / Microsoft / MITRE / OWASP), not two pages of one org.
POOL: list[tuple[str, str, str]] = [
    # --- Active Directory ---------------------------------------------------
    ("https://www.rfc-editor.org/rfc/rfc4120.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc4511.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc5280.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc1918.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc1035.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc4459.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc6335.html", "rfc-editor.org", "standard"),
    ("https://www.rfc-editor.org/rfc/rfc1002.html", "rfc-editor.org", "standard"),
    ("https://attack.mitre.org/techniques/T1558/003/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1558/004/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1558/001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1550/003/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1550/002/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1557/001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1134/003/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1222/001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1484/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1484/001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1649/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1110/003/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1087/002/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1087/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1003/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1003/006/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1021/002/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1021/001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1021/006/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1046/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1018/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1016/001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1090/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1133/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1135/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1219/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/techniques/T1021/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/tactics/TA0008/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/tactics/TA0006/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/tactics/TA0001/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/tactics/TA0005/", "attack.mitre.org", "taxonomy"),
    ("https://attack.mitre.org/tactics/TA0043/", "attack.mitre.org", "taxonomy"),
    # --- Microsoft protocol / product documentation -------------------------
    ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows/win32/winrm/portal", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/ntds-protection", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/password-policies", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows-server/networking/", "learn.microsoft.com", "docs"),
    ("https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-thresholds", "learn.microsoft.com", "docs"),
    # --- OWASP -------------------------------------------------------------
    ("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "cheatsheetseries.owasp.org", "cheatsheet"),
    ("https://cheatsheetseries.owasp.org/cheatsheets/Network_Security_Cheat_Sheet.html", "cheatsheetseries.owasp.org", "cheatsheet"),
]


def main() -> int:
    refresh = "--refresh" in sys.argv
    ok = dead = 0
    for url, host, stype in POOL:
        r = get(url, refresh=refresh)
        if r["ok"] and r["chars"] > 1500:
            ok += 1
            print(f"OK   {r['status']} chars={r['chars']:>7}  {host:<28} {url}"
                  + (f"  ->MIRROR {r['mirror']}" if r.get("mirror") else ""))
        else:
            dead += 1
            print(f"DEAD {str(r['status']):>5} chars={r['chars']:>7}  {host:<28} {url}"
                  f"  {r.get('error') or ''}")
    print(f"\npool={len(POOL)} ok={ok} dead={dead}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
