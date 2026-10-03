"""Audit: how many promoted items are actually ABOUT their class?

A class page that renders an SQL-injection sentence as a DNS-enumeration
technique is not a coverage gap, it is a corpus defect: it reads as knowledge
and teaches the wrong thing. This measures per-class topical fit using a
vocabulary probe, and prints the offenders so a human can look.

    python tools/recon_audit_offtopic.py            # table
    python tools/recon_audit_offtopic.py --json
    python tools/recon_audit_offtopic.py --class dns_enum
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys

DB = os.path.join(os.environ.get("WKS_ROOT", ""), "db", "wks.db")

# Vocabulary that must plausibly appear in a claim that is really about the
# class. Deliberately GENERIC mechanics (attacker, vulnerability, token) are
# excluded -- that is the vocabulary the filler shares with everything.
VOCAB: dict[str, list[str]] = {
    "dns_enum": ["dns", "domain name", "zone", "nameserver", "name server",
                 "axfr", "zone transfer", "record", "resolver", "srv record",
                 "txt record", "ns record", "soa", "hostname"],
    "exposed_services": ["service", "port", "banner", "exposed", "listener",
                         "protocol", "daemon", "endpoint", "version"],
    "exposed_rmm": ["rmm", "remote monitoring", "management", "agent",
                    "vnc", "rdp", "smb", "winrm", "panel", "console"],
    "service_enumeration": ["service", "enumeration", "port", "banner",
                            "scan", "fingerprint", "sweep"],
    "service_enumeration_detail": ["service", "configuration", "config",
                                   "enabling", "anonymous", "default",
                                   "credential", "policy", "version"],
    "ad_enumeration": ["active directory", "domain controller", "ldap", "ad ",
                       "sid", "samaccountname", "netbios", "forest", "domain",
                       "user", "group", "policy"],
    "ldap_enum": ["ldap", "directory", "bind", "dn", "objectclass", "rootdse"],
    "internal_recon": ["internal", "network", "segment", "lateral", "pivot",
                       "smb", "subnet", "host"],
    "segmentation_analysis": ["segmentation", "segment", "firewall", "acl",
                              "boundary", "pivot", "route"],
    "subdomain_takeover": ["subdomain", "takeover", "dangling", "cname", "dns",
                           "host", "domain", "claim"],
    "misconfig": ["misconfig", "configuration", "default", "exposed",
                  "hardened", "setting"],
    "info_disclosure": ["disclosure", "information", "leak", "exposed",
                        "verbose", "error", "metadata"],
    "smb": ["smb", "cifs", "share", "netbios", "null session", "dialect"],
    "rdp": ["rdp", "remote desktop", "nla", "credssp", "clipboard", "port 3389"],
    "winrm": ["winrm", "powershell remoting", "wsman", "5985", "5986"],
    "xss": ["xss", "cross-site scripting", "javascript", "dom", "html",
            "script", "sink", "payload", "browser"],
    "sqli": ["sql", "query", "database", "injection", "select ", "where ",
             "orm", "statement"],
    "ssrf": ["ssrf", "server-side request", "url", "fetch", "internal url",
             "outbound", "request forgery", "callback"],
    "csrf": ["csrf", "cross-site request forgery", "token", "cookie",
             "origin", "referer"],
    "authn": ["auth", "authentication", "password", "login", "session",
              "credential", "mfa", "token"],
    "authz": ["authoriz", "permission", "access control", "idor", "privilege",
              "role", "policy"],
    "oauth": ["oauth", "oidc", "token", "jwt", "redirect_uri", "scope",
              "authorization"],
    "jwt": ["jwt", "token", "claim", "signature", "alg", "hs256", "rs256"],
    "idempotent": [],
}
VOCAB.pop("idempotent", None)

# Claims that are structurally filler: they describe a whole module/course
# instead of one technique.
FILLER = re.compile(
    r"^(we (will|are going to|discuss|cover)|this module covers|"
    r"we will (cover|discuss|identify)|identify, exploit, and prevent|"
    r"we will be covering)",
    re.I,
)

# One claim can be on-topic for one class and filler for another; the probe is
# per class so that is handled naturally.
def on_topic(class_id: str, claim: str) -> bool:
    terms = VOCAB.get(class_id)
    if not terms:
        return True  # unprobed class: no verdict, never counted as a failure
    low = claim.lower()
    return any(t in low for t in terms)


def main() -> int:
    argv = sys.argv[1:]
    as_json = "--json" in argv
    only = None
    if "--class" in argv:
        only = argv[argv.index("--class") + 1]

    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    q = ("select i.class_id cid, i.claim claim, q.validation_state vs, i.kind kind "
         "from item i join quality q on q.item_id=i.id "
         "where i.status='active'")
    args: tuple = ()
    if only:
        q += " and i.class_id=?"
        args = (only,)
    rows = con.execute(q, args).fetchall()

    per: dict[str, dict] = {}
    offenders: list[dict] = []
    for r in rows:
        cid = r["cid"]
        d = per.setdefault(cid, {"total": 0, "offtopic": 0, "filler": 0})
        d["total"] += 1
        claim = (r["claim"] or "").strip()
        is_filler = bool(FILLER.match(claim))
        if is_filler:
            d["filler"] += 1
        if not on_topic(cid, claim):
            d["offtopic"] += 1
            offenders.append({"class": cid, "kind": r["kind"],
                              "validation_state": r["vs"], "claim": claim[:180]})

    total = sum(d["total"] for d in per.values())
    bad = sum(d["offtopic"] for d in per.values())
    fil = sum(d["filler"] for d in per.values())

    if as_json:
        print(json.dumps({
            "items": total, "off_topic": bad, "filler": fil,
            "off_topic_pct": round(100.0 * bad / total, 1) if total else 0.0,
            "per_class": per,
            "offenders": offenders[:400],
        }, indent=2))
        return 0

    print(f"probed items={total}  off-topic={bad} ({100.0*bad/total:.1f}%)  "
          f"module-filler={fil} ({100.0*fil/total:.1f}%)")
    print()
    print(f"{'class':28} {'items':>6} {'offtopic':>9} {'%':>6} {'filler':>7}")
    for cid, d in sorted(per.items(), key=lambda kv: -kv[1]["offtopic"]):
        if only and cid != only:
            continue
        pct = 100.0 * d["offtopic"] / d["total"] if d["total"] else 0.0
        print(f"{cid:28} {d['total']:6} {d['offtopic']:9} {pct:6.1f} "
              f"{d['filler']:7}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())