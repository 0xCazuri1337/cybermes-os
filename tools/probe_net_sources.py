"""Probe candidate NETWORK/AD normative sources with a real GET.

Why this script exists: R5 says a dead seed URL is worse than none, because it
looks configured. A NETWORK seed set that cannot corroborate is worse still --
every class whose seeds sit on one host can NEVER pass MIN_PUBLISHER_HOSTS, so
the research budget gets spent discovering that at promotion time.

So seeds are verified BEFORE they are written, by fetching them. HEAD is not
enough: portswigger.net 404s HEAD on live pages (R5), and some hosts 403 a
bare urllib agent. This uses GET with a browser-ish UA and follows redirects.

This script only READS the public web. It contacts no target, no lab, and no
private host. It writes runtime/state/network-seed-probe.json.
"""
from __future__ import annotations

import json
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from wks import config

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")

CTX = ssl.create_default_context()

# Candidate normative sources for the NETWORK domain, grouped by the publisher
# host they represent. The point of grouping is the MIN_PUBLISHER_HOSTS gate:
# a class needs its seeds spread across >= 2 of these hosts.
CANDIDATES: list[tuple[str, str, str]] = [
    # (class_id, url, source_type)
    # --- Microsoft Learn: protocol + AD product documentation -------------
    ("ad_kerberos", "https://learn.microsoft.com/en-us/windows/win32/secauthz/windows-authentication-authorization", "docs"),
    ("ad_kerberos", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erfce/", "docs"),
    ("ad_kerberos", "https://learn.microsoft.com/en-us/windows/win32/seccreds/kerberos-protocol", "docs"),
    ("ad_ntlm", "https://learn.microsoft.com/en-us/windows/win32/seccreds/ntlm", "docs"),
    ("ad_ldap", "https://learn.microsoft.com/en-us/windows/win32/secauthz/ldap", "docs"),
    ("ad_acl_abuse", "https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control", "docs"),
    ("ad_delegation", "https://learn.microsoft.com/en-us/windows/win32/secauthz/delegation", "docs"),
    ("adcs_abuse", "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/overview", "docs"),
    ("ad_trust_abuse", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
    ("ad_group_policy", "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings", "docs"),
    ("smb", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/", "docs"),
    ("winrm", "https://learn.microsoft.com/en-us/windows/win32/winrm/portal", "docs"),
    ("ldap_enum", "https://learn.microsoft.com/en-us/windows/win32/secauthz/ldap-search-strings", "docs"),
    ("dns_enum", "https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top", "docs"),
    ("rdp", "https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol", "docs"),
    ("internal_recon", "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands", "docs"),
    ("credential_access", "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management", "docs"),
    ("pass_the_hash", "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restrict-logon-locally", "docs"),
    ("adcs", "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-quick-start", "docs"),
    ("priv_escalation_win", "https://learn.microsoft.com/en-us/windows/security/threat-protection", "docs"),
    ("exposed_services", "https://learn.microsoft.com/en-us/windows-server/networking/", "docs"),

    # --- MITRE ATT&CK: adversary technique taxonomy -----------------------
    ("ad_kerberos", "https://attack.mitre.org/techniques/T1558/", "taxonomy"),
    ("ad_kerberos", "https://attack.mitre.org/techniques/T1550/003/", "taxonomy"),
    ("ad_ntlm", "https://attack.mitre.org/techniques/T1557/001/", "taxonomy"),
    ("ad_acl_abuse", "https://attack.mitre.org/techniques/T1222/001/", "taxonomy"),
    ("ad_acl_abuse", "https://attack.mitre.org/techniques/T1003/006/", "taxonomy"),
    ("ad_delegation", "https://attack.mitre.org/techniques/T1134/003/", "taxonomy"),
    ("adcs_abuse", "https://attack.mitre.org/techniques/T1649/", "taxonomy"),
    ("credential_access", "https://attack.mitre.org/tactics/TA0006/", "taxonomy"),
    ("internal_recon", "https://attack.mitre.org/tactics/TA0043/", "taxonomy"),
    ("exposed_services", "https://attack.mitre.org/tactics/TA0001/", "taxonomy"),
    ("lateral_movement", "https://attack.mitre.org/tactics/TA0008/", "taxonomy"),
    ("priv_escalation_win", "https://attack.mitre.org/tactics/TA0004/", "taxonomy"),
    ("smb", "https://attack.mitre.org/techniques/T1021/002/", "taxonomy"),
    ("winrm", "https://attack.mitre.org/techniques/T1021/006/", "taxonomy"),
    ("rdp", "https://attack.mitre.org/techniques/T1021/001/", "taxonomy"),
    ("ldap_enum", "https://attack.mitre.org/techniques/T1087/002/", "taxonomy"),
    ("dns_enum", "https://attack.mitre.org/techniques/T1016/001/", "taxonomy"),
    ("pass_the_hash", "https://attack.mitre.org/techniques/T1550/002/", "taxonomy"),
    ("ad_group_policy", "https://attack.mitre.org/techniques/T1484/001/", "taxonomy"),
    ("ad_trust_abuse", "https://attack.mitre.org/techniques/T1484/", "taxonomy"),
    ("exposed_rmm", "https://attack.mitre.org/techniques/T1219/", "taxonomy"),

    # --- MITRE CWE: weakness definitions ----------------------------------
    ("ad_kerberos", "https://cwe.mitre.org/data/definitions/287.html", "cwe"),
    ("ad_acl_abuse", "https://cwe.mitre.org/data/definitions/269.html", "cwe"),
    ("credential_access", "https://cwe.mitre.org/data/definitions/522.html", "cwe"),
    ("exposed_services", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("priv_escalation_win", "https://cwe.mitre.org/data/definitions/269.html", "cwe"),
    ("ad_ntlm", "https://cwe.mitre.org/data/definitions/294.html", "cwe"),
    ("smb", "https://cwe.mitre.org/data/definitions/732.html", "cwe"),
    ("ad_delegation", "https://cwe.mitre.org/data/definitions/863.html", "cwe"),
    ("ldap_enum", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("winrm", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("rdp", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("adcs_abuse", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("ad_group_policy", "https://cwe.mitre.org/data/definitions/269.html", "cwe"),
    ("ad_trust_abuse", "https://cwe.mitre.org/data/definitions/863.html", "cwe"),
    ("lateral_movement", "https://cwe.mitre.org/data/definitions/284.html", "cwe"),
    ("internal_recon", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("pass_the_hash", "https://cwe.mitre.org/data/definitions/294.html", "cwe"),
    ("dns_enum", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("exposed_rmm", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),

    # --- IETF RFCs: protocol specifications -------------------------------
    ("ad_kerberos", "https://www.rfc-editor.org/rfc/rfc4120.html", "standard"),
    ("ldap_enum", "https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
    ("ad_ldap", "https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
    ("ad_group_policy", "https://www.rfc-editor.org/rfc/rfc4124.html", "standard"),
    ("smb", "https://www.rfc-editor.org/rfc/rfc4459.html", "standard"),
    ("dns_enum", "https://www.rfc-editor.org/rfc/rfc1035.html", "standard"),

    # --- OWASP: practitioner normative guidance ---------------------------
    ("ad_ldap", "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html", "cheatsheet"),
    ("lateral_movement", "https://cheatsheetseries.owasp.org/cheatsheets/Windows_Command_Shells.html", "cheatsheet"),
    ("exposed_rmm", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "cheatsheet"),

    # --- PortSwigger Academy: practitioner guidance -----------------------
    ("smb", "https://portswigger.net/web-security/smrf", "cheatsheet"),
    ("ad_acl_abuse", "https://portswigger.net/web-security/access-control", "cheatsheet"),
    ("credential_access", "https://portswigger.net/web-security/passwords", "cheatsheet"),

    # --- Samba: independent implementation documentation -------------------
    ("ad_kerberos", "https://www.samba.org/samba/docs/stable/man-html/samba.7.html", "docs"),
    ("smb", "https://www.samba.org/samba/docs/stable/man-html/smbclient.1.html", "docs"),
    ("ad_ldap", "https://www.samba.org/samba/docs/stable/man-html/samdb.8.html", "docs"),
]


def probe(url: str, timeout: int = 25) -> tuple[int, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            r.read(2048)
            return r.status, r.headers.get("Content-Type", "")[:40]
    except urllib.error.HTTPError as e:
        return e.code, "http-error"
    except Exception as e:  # noqa: BLE001 - probe reports, never raises
        return 0, f"{type(e).__name__}: {str(e)[:60]}"


def main() -> int:
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    rows: dict[str, dict] = {}
    by_host: dict[str, dict] = {}
    seen: set[str] = set()
    for cid, url, stype in CANDIDATES:
        if url in seen:
            continue
        seen.add(url)
        if only and only not in cid:
            continue
        status, ctype = probe(url)
        host = urlparse(url).netloc
        rows[url] = {"class": cid, "host": host, "status": status, "type": stype}
        h = by_host.setdefault(host, {"ok": 0, "bad": 0, "classes": set()})
        if status == 200:
            h["ok"] += 1
            h["classes"].add(cid)
        else:
            h["bad"] += 1
        flag = "OK " if status == 200 else "DEAD"
        print(f"[{flag}] {status:>4} {host:<28} {cid:<20} {url}")

    print("\n=== HOST ROLLUP ===")
    live_hosts = []
    for host, h in sorted(by_host.items(), key=lambda kv: -kv[1]["ok"]):
        print(f"  {host:<30} ok={h['ok']:<3} dead={h['bad']:<3} classes={len(h['classes'])}")
        if h["ok"]:
            live_hosts.append(host)

    # The gate that actually matters: per class, how many LIVE hosts back it?
    print("\n=== PER-CLASS LIVE PUBLISHER HOSTS (gate = %d) ===" % config.MIN_PUBLISHER_HOSTS)
    per: dict[str, set] = {}
    for url, r in rows.items():
        if r["status"] == 200:
            per.setdefault(r["class"], set()).add(r["host"])
    unfixable = []
    for cid in sorted(per):
        hosts = sorted(per[cid])
        ok = len(hosts) >= config.MIN_PUBLISHER_HOSTS
        if not ok:
            unfixable.append(cid)
        print(f"  {'PASS' if ok else 'FAIL'} {cid:<22} {len(hosts)} host(s) {hosts}")

    out = {
        "probed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "live_hosts": live_hosts,
        "rows": rows,
        "per_class_hosts": {k: sorted(v) for k, v in per.items()},
        "classes_below_gate": unfixable,
    }
    p = config.STATE_DIR / "network-seed-probe.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nwrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
