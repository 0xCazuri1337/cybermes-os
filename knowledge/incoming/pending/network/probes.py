"""Per-class span mining driver.

For each class: a set of (url, pattern) probes across DISTINCT hosts. Prints the
verbatim spans so an item author can pick quotes that actually say what the
claim asserts. Nothing here writes to the db.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mine import mine  # noqa: E402

# class_id -> list of (url, regex)
PROBES: dict[str, list[tuple[str, str]]] = {
    "ad_kerberos": [
        ("https://attack.mitre.org/techniques/T1558/003/", r"offline Brute Force|TGS-REP etype"),
        ("https://attack.mitre.org/techniques/T1558/004/", r"preauthentication|AS-REP"),
        ("https://attack.mitre.org/techniques/T1558/001/", r"KRBTGT account password hash"),
        ("https://www.rfc-editor.org/rfc/rfc4120.html", r"AS-REQ|TGS-REQ"),
    ],
    "ad_ntlm": [
        ("https://attack.mitre.org/techniques/T1557/001/", r"relay|NTLM authentication"),
        ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/", r"NTLM|NTLMSSP"),
    ],
    "ad_ldap": [
        ("https://www.rfc-editor.org/rfc/rfc4511.html", r"filter|searchRequest"),
        ("https://attack.mitre.org/techniques/T1087/002/", r"LDAP|Domain Account"),
    ],
    "pass_the_hash": [
        ("https://attack.mitre.org/techniques/T1550/002/", r"Pass the Hash|NTLM hash"),
        ("https://attack.mitre.org/techniques/T1550/003/", r"Pass the Ticket|Kerberos ticket"),
    ],
    "ad_enumeration": [
        ("https://attack.mitre.org/techniques/T1087/002/", r"LDAP query|netlogon|Domain Trust"),
        ("https://www.rfc-editor.org/rfc/rfc4511.html", r"SearchRequest|searchResEntry"),
    ],
    "ad_acl_abuse": [
        ("https://attack.mitre.org/techniques/T1222/001/", r"ACL|permission|GUID"),
        ("https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control", r"access control|DACL|SACL"),
    ],
    "ad_delegation": [
        ("https://attack.mitre.org/techniques/T1134/003/", r"delegat|service ticket"),
        ("https://www.rfc-editor.org/rfc/rfc4120.html", r"delegat"),
    ],
    "adcs_abuse": [
        ("https://attack.mitre.org/techniques/T1649/", r"certificate|Certificate"),
        ("https://www.rfc-editor.org/rfc/rfc5280.html", r"certification|certificate"),
    ],
    "ad_trust_abuse": [
        ("https://attack.mitre.org/techniques/T1484/", r"trust|Trust"),
        ("https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", r"trust|Trust"),
    ],
    "ad_group_policy": [
        ("https://attack.mitre.org/techniques/T1484/001/", r"SYSVOL|Group Policy|GPO"),
        ("https://learn.microsoft.com/en-us/windows/win32/winrm/portal", r"WinRM|Windows Remote Management"),
    ],
    "credential_access": [
        ("https://attack.mitre.org/techniques/T1003/006/", r"NTDS|ntds.dit|DCSync"),
        ("https://attack.mitre.org/tactics/TA0006/", r"Credential"),
    ],
    "password_attacks": [
        ("https://attack.mitre.org/techniques/T1110/003/", r"Password Spraying|spray|lockout"),
        ("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", r"rate limit|lock|brute"),
    ],
    "smb": [
        ("https://attack.mitre.org/techniques/T1021/002/", r"SMB|NetBIOS|Named Pipe"),
        ("https://www.rfc-editor.org/rfc/rfc1002.html", r"NetBIOS|SMB"),
    ],
    "winrm": [
        ("https://attack.mitre.org/techniques/T1021/006/", r"WinRM|Windows Remote Management"),
        ("https://learn.microsoft.com/en-us/windows/win32/winrm/portal", r"WinRM|Windows Remote Management|HTTP"),
    ],
    "rdp": [
        ("https://attack.mitre.org/techniques/T1021/001/", r"RDP|Remote Desktop"),
        ("https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol", r"RDP|Remote Desktop|Terminal Services"),
    ],
    "ldap_enum": [
        ("https://attack.mitre.org/techniques/T1087/002/", r"LDAP"),
        ("https://www.rfc-editor.org/rfc/rfc4511.html", r"search|Search"),
    ],
    "dns_enum": [
        ("https://attack.mitre.org/techniques/T1016/001/", r"DNS"),
        ("https://www.rfc-editor.org/rfc/rfc1035.html", r"zone transfer|AXFR|SOA"),
    ],
    "service_enumeration": [
        ("https://attack.mitre.org/techniques/T1046/", r"Network Service Scanning|banner|port"),
        ("https://www.rfc-editor.org/rfc/rfc6335.html", r"service name|registry"),
    ],
    "exposed_services": [
        ("https://attack.mitre.org/techniques/T1133/", r"External Remote Services|internet-facing"),
        ("https://learn.microsoft.com/en-us/windows-server/networking/", r"network|Windows"),
    ],
    "exposed_rmm": [
        ("https://attack.mitre.org/techniques/T1219/", r"Remote Monitoring|RMM|remote management"),
        ("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", r"multi-factor|second factor|MFA"),
    ],
    "internal_recon": [
        ("https://attack.mitre.org/techniques/T1018/", r"Remote System Discovery"),
        ("https://www.rfc-editor.org/rfc/rfc1918.html", r"private|10\.0\.0\.0|172\.16"),
    ],
    "lateral_movement": [
        ("https://attack.mitre.org/techniques/T1021/", r"Remote Services|protocol"),
        ("https://attack.mitre.org/tactics/TA0008/", r"Lateral Movement"),
    ],
    "tunneling_pivoting": [
        ("https://attack.mitre.org/techniques/T1090/", r"proxy|Proxy|tunnel"),
        ("https://www.rfc-editor.org/rfc/rfc4459.html", r"tunnel|Tunnel"),
    ],
    "segmentation_analysis": [
        ("https://attack.mitre.org/tactics/TA0005/", r"Lateral Movement|segmentation"),
        ("https://www.rfc-editor.org/rfc/rfc1918.html", r"private|Address Blocks"),
    ],
    "service_enumeration_detail": [
        ("https://attack.mitre.org/techniques/T1046/", r"port scan|Network Service Scanning"),
        ("https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", r"fail|lockout|rate"),
    ],
}


def main() -> int:
    only = sys.argv[1:] or list(PROBES)
    for cid in only:
        print(f"\n########## {cid}")
        for url, pat in PROBES[cid]:
            print(f"--- {url}   /{pat}/")
            for s in mine(url, pat, limit=4):
                print("   *", s[:400])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
