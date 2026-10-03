"""Gap-closing probe: find live normative hosts for the classes that FAILED R5.

`tools/probe_net_sources.py` measured 4 classes below MIN_PUBLISHER_HOSTS on
the first URL set:

    ad_ldap          1 host   (only the OWASP cheat sheet)
    adcs_abuse       1 host   (only attack.mitre.org)
    internal_recon   1 host   (only attack.mitre.org)
    pass_the_hash    1 host   (only attack.mitre.org)

A class with one publisher host can NEVER be promoted — the gate refuses it at
`quality.assess` no matter how good the item is. So these are not weak classes,
they are STRUCTURALLY UNREACHABLE classes, and every research session pointed at
them fails for a reason that has nothing to do with research quality.

This probe tries a second, wider candidate set for exactly those classes. It is
deliberately verbose about what it probes: a guessed URL that 404s is worse than
no URL, because it looks configured (R5). Only 200s are written to the seed
file, and a class that still cannot reach two hosts is reported as STILL_GAP so
it can be carried as an explicit debt rather than quietly seeded.

Reads the public web only. No target, no lab, no private host.
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

# Second-pass candidates for the four failing classes. Deliberately widened to
# publisher families the first pass under-used: RFCs (very stable), ATT&CK
# tactics as well as techniques, CISA/NIST advisories, and Samba's independent
# implementation docs.
CANDIDATES: list[tuple[str, str, str]] = [
    # ---------------- ad_ldap: LDAP as an AD attack surface ---------------
    ("ad_ldap", "https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
    ("ad_ldap", "https://attack.mitre.org/techniques/T1087/002/", "taxonomy"),
    ("ad_ldap", "https://learn.microsoft.com/en-us/windows/win32/secauthz/ldap", "docs"),
    ("ad_ldap", "https://learn.microsoft.com/en-us/windows/win32/secauthz/ldap-search-strings", "docs"),
    ("ad_ldap", "https://cwe.mitre.org/data/definitions/90.html", "cwe"),
    ("ad_ldap", "https://www.samba.org/samba/docs/stable/man-html/samdb.8.html", "docs"),

    # ---------------- adcs_abuse: AD certificate services ----------------
    ("adcs_abuse", "https://attack.mitre.org/techniques/T1649/", "taxonomy"),
    ("adcs_abuse", "https://attack.mitre.org/techniques/T1587/003/", "taxonomy"),
    ("adcs_abuse", "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/overview", "docs"),
    ("adcs_abuse", "https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/ad-cs-quick-start", "docs"),
    ("adcs_abuse", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("adcs_abuse", "https://cwe.mitre.org/data/definitions/287.html", "cwe"),
    ("adcs_abuse", "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html", "cheatsheet"),

    # ---------------- internal_recon: discovery inside a network ---------
    ("internal_recon", "https://attack.mitre.org/tactics/TA0043/", "taxonomy"),
    ("internal_recon", "https://attack.mitre.org/techniques/T1018/", "taxonomy"),
    ("internal_recon", "https://attack.mitre.org/techniques/T1016/", "taxonomy"),
    ("internal_recon", "https://cwe.mitre.org/data/definitions/200.html", "cwe"),
    ("internal_recon", "https://cwe.mitre.org/data/definitions/497.html", "cwe"),
    ("internal_recon", "https://www.rfc-editor.org/rfc/rfc1918.html", "standard"),
    ("internal_recon", "https://www.cisa.gov/news-events/cybersecurity-advisories", "advisory"),

    # ---------------- pass_the_hash -------------------------------------
    ("pass_the_hash", "https://attack.mitre.org/techniques/T1550/002/", "taxonomy"),
    ("pass_the_hash", "https://attack.mitre.org/techniques/T1550/003/", "taxonomy"),
    ("pass_the_hash", "https://cwe.mitre.org/data/definitions/294.html", "cwe"),
    ("pass_the_hash", "https://cwe.mitre.org/data/definitions/916.html", "cwe"),
    ("pass_the_hash", "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/restrict-logon-locally", "docs"),
    ("pass_the_hash", "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/credentials-protection", "docs"),

    # ---------------- second-pass reinforcement for classes already at 2,
    # adding a THIRD independent host where one is cheap. More hosts means a
    # stronger pair available, not just a passing one.
    ("ad_kerberos", "https://www.rfc-editor.org/rfc/rfc4120.html", "standard"),
    ("ad_kerberos", "https://learn.microsoft.com/en-us/windows/win32/seccreds/kerberos-protocol", "docs"),
    ("ad_ntlm", "https://learn.microsoft.com/en-us/windows/win32/seccreds/ntlm", "docs"),
    ("ad_acl_abuse", "https://cwe.mitre.org/data/definitions/269.html", "cwe"),
    ("ad_delegation", "https://learn.microsoft.com/en-us/windows/win32/secauthz/delegation", "docs"),
    ("credential_access", "https://attack.mitre.org/tactics/TA0006/", "taxonomy"),
    ("credential_access", "https://cwe.mitre.org/data/definitions/522.html", "cwe"),
    ("ad_group_policy", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpdef/", "docs"),
    ("ad_trust_abuse", "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/", "docs"),
    ("lateral_movement", "https://attack.mitre.org/tactics/TA0008/", "taxonomy"),
    ("lateral_movement", "https://cwe.mitre.org/data/definitions/284.html", "cwe"),
    ("exposed_services", "https://attack.mitre.org/tactics/TA0001/", "taxonomy"),
    ("priv_escalation_win", "https://cwe.mitre.org/data/definitions/269.html", "cwe"),
    ("ldap_enum", "https://www.rfc-editor.org/rfc/rfc4511.html", "standard"),
    ("dns_enum", "https://www.rfc-editor.org/rfc/rfc1035.html", "standard"),
    ("smb", "https://www.rfc-editor.org/rfc/rfc4459.html", "standard"),
    ("exposed_rmm", "https://attack.mitre.org/techniques/T1219/", "taxonomy"),
]


def probe(url: str, timeout: int = 25) -> int:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
            r.read(2048)
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:  # noqa: BLE001 - a probe reports, never raises
        return 0


def main() -> int:
    prev_path = config.STATE_DIR / "network-seed-probe.json"
    prev = json.loads(prev_path.read_text(encoding="utf-8")) if prev_path.exists() else {}

    # Union of first-pass live rows and this pass. A seed already proven live is
    # not re-fetched, which keeps this cheap and keeps the first measurement.
    live: dict[str, dict] = {}
    for url, r in (prev.get("rows") or {}).items():
        if r.get("status") == 200:
            live[url] = r
    first_pass = set(live)

    newly_dead: list[str] = []
    seen: set[str] = set()
    for cid, url, stype in CANDIDATES:
        if url in seen or url in first_pass:
            continue
        seen.add(url)
        status = probe(url)
        if status == 200:
            live[url] = {"class": cid, "host": urlparse(url).netloc,
                         "status": 200, "type": stype}
            print(f"[OK  ] 200 {urlparse(url).netloc:<26} {cid}")
        else:
            newly_dead.append(url)
            print(f"[DEAD] {status:>4} {urlparse(url).netloc:<26} {cid}  {url}")

    # Per-class live hosts, merged across both passes.
    per: dict[str, dict[str, list[str]]] = {}
    for url, r in live.items():
        per.setdefault(r["class"], {}).setdefault(r["host"], []).append(url)

    print("\n=== MERGED PER-CLASS LIVE PUBLISHER HOSTS (gate = %d) ==="
          % config.MIN_PUBLISHER_HOSTS)
    seeds: dict[str, list[tuple[str, str]]] = {}
    still_gap: list[str] = []
    for cid in sorted(per):
        hosts = per[cid]
        ok = len(hosts) >= config.MIN_PUBLISHER_HOSTS
        if not ok:
            still_gap.append(cid)
        else:
            # One URL per host: MIN_PUBLISHER_HOSTS counts hosts, so extra URLs
            # on a host add no gate value. Keep the shortest URL per host for
            # readability, deterministic ordering.
            chosen = []
            for host in sorted(hosts):
                u = sorted(hosts[host], key=len)[0]
                stype = next(r["type"] for x, r in live.items() if x == u)
                chosen.append((u, stype))
            seeds[cid] = chosen
        print(f"  {'PASS' if ok else 'STILL_GAP'} {cid:<20} "
              f"{len(hosts)} host(s) {sorted(hosts)}")

    out = {
        "probed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "merge": "pass-1 (network-seed-probe.json) + pass-2 (this run)",
        "live_seed_set": {k: [list(x) for x in v] for k, v in seeds.items()},
        "still_gap": still_gap,
        "dead_this_pass": newly_dead,
        "live_count": len(live),
    }
    p = config.STATE_DIR / "network-seed-verified.json"
    p.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"\nclasses with a usable seed set : {len(seeds)}")
    print(f"classes STILL below the gate  : {len(still_gap)} {still_gap}")
    print(f"dead URLs this pass           : {len(newly_dead)}")
    print(f"wrote {p}")

    if len(seeds) != len(sys.argv[1:] or []):
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
