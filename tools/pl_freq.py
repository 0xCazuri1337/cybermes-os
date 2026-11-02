"""pentester.land writeups.json (6421 entries) -> a FREQUENCY signal per class.

This source is an INDEX, not prose: every row is a title, a bug-tag list, a
program, a bounty and a link. A tag like "local privilege escalation" appearing
on 245 write-ups is not a claim -- it is evidence about WHERE REAL FINDINGS LAND,
which is a different and more valuable thing than a technique.

So the output is not items. It is:
  1. per-class evidence volume, to rank the gap analysis honestly
  2. the tag -> class routing table, so any future harvest routes by the tags the
     ecosystem actually uses
  3. the specific tags with NO class at all -- that is the gap list

Fetching 6421 write-ups would be both slow and wrong: a tag count is the signal,
and one account of one engagement is not evidence (the same 2-publisher rule that
governs every item here).
"""
import collections
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import relevance, store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "cache", "pentesterland", "writeups.json")
OUT = os.path.join(ROOT, "research", "pentesterland_freq.json")

# Ecosystem tag -> our class. Only where the mapping is unambiguous. Anything
# absent from this table is reported as UNROUTED rather than guessed onto a class.
TAG_ROUTE = {
    "xss": "xss", "stored xss": "xss", "reflected xss": "xss", "dom xss": "xss",
    "blind xss": "xss", "csp bypass": "xss", "html injection": "xss",
    "self-xss": "xss", "xssi": "xss",
    "sqli": "sqli", "sql injection": "sqli", "blind sql injection": "sqli",
    "second order sql injection": "sqli", "sqlmap": "sqli",
    "ssrf": "ssrf", "blind ssrf": "ssrf",
    "xxe": "xxe", "xml external entity": "xxe",
    "ssti": "ssti", "template injection": "ssti",
    "csrf": "csrf", "cross site request forgery": "csrf",
    "idor": "idor", "bola": "idor", "insecure direct object reference": "idor",
    "broken object level authorization": "idor",
    "lfi": "path_traversal", "path traversal": "path_traversal",
    "rfi": "path_traversal", "directory traversal": "path_traversal",
    "arbitrary file read": "path_traversal",
    "os command injection": "cmd", "command injection": "cmd",
    "rce": "cmd", "remote code execution": "cmd", "arbitrary code execution": "cmd",
    "insecure deserialization": "deser", "deserialization": "deser",
    "oauth": "oauth", "saml": "oauth", "jwt": "jwt", "sso": "oauth",
    "open redirect": "open_redirect", "unvalidated redirect": "open_redirect",
    "subdomain takeover": "subdomain_takeover", "dangling dns": "subdomain_takeover",
    "account takeover": "authn", "2fa / mfa bypass": "authn",
    "authentication bypass": "authn", "missing authentication": "authn",
    "password reset": "authn", "bruteforce": "password_attacks",
    "broken authentication": "authn",
    "broken authorization": "authz",
    "broken access control": "authz", "forced browsing": "authz",
    "logic flaw": "bizlogic", "business logic": "bizlogic",
    "lack of rate limiting": "bizlogic", "race condition": "race",
    "toctou": "race", "clickjacking": "clickjacking",
    "unrestricted file upload": "file_upload", "file upload": "file_upload",
    "host header injection": "host_header", "cache poisoning": "cache_poisoning",
    "cache deception": "cache_deception", "graphql": "graphql",
    "mass assignment": "mass_assign", "http request smuggling": "smuggling",
    "desync": "smuggling", "crlf": "crlf", "cors": "cors",
    "prototype pollution": "prototype_pollution", "nosql": "nosql",
    "open s3 bucket": "misconfig", "default credentials": "misconfig",
    "information disclosure": "info_disclosure", "information exposure": "info_disclosure",
    "directory listing": "info_disclosure", "exposed git": "info_disclosure",
    "source code disclosure": "info_disclosure", "version leak": "info_disclosure",
    "ssrf to rce": "ssrf", "supply chain attack": "supply_chain",
    "dependency confusion": "supply_chain", "ci/cd": "supply_chain",
    "websocket": "websocket", "ldap injection": "ldap",
    "local privilege escalation": "PRIVESC_GAP",
    "privilege escalation": "PRIVESC_GAP",
    "windows privilege escalation": "PRIVESC_GAP",
    "linux privilege escalation": "PRIVESC_GAP",
    "mimikatz": "credential_access", "credential dumping": "credential_access",
    "privilege escalation to domain admin": "PRIVESC_GAP",
    "arbitrary dll loading": "PRIVESC_GAP",
    "named pipe impersonation": "PRIVESC_GAP",
    "token impersonation": "PRIVESC_GAP",
    "kerberoasting": "ad_kerberos", "asreproast": "ad_kerberos",
    "pass the hash": "pass_the_hash", "pass-the-hash": "pass_the_hash",
    "smb": "smb", "rdp": "rdp", "winrm": "winrm",
    "smtp": "misconfig", "dns": "dns_enum",
    "lateral movement": "lateral_movement", "pivoting": "tunneling_pivoting",
    "prompt injection": "authn", "llm jailbreak": "authn",
}


def main():
    con = store.connect()
    with open(SRC, encoding="utf-8") as fh:
        data = json.load(fh)["data"]
    print("writeups indexed: %d" % len(data))

    tag_n = collections.Counter()
    for w in data:
        for t in (w.get("Bugs") or []):
            tag_n[str(t).strip().lower()] += 1

    per_class = collections.defaultdict(lambda: {"writeups": 0, "tags": {}})
    unrouted = {}
    privesc_tags = {}
    for tag, n in tag_n.items():
        cls = TAG_ROUTE.get(tag)
        if cls is None:
            unrouted[tag] = n
            continue
        if cls == "PRIVESC_GAP":
            privesc_tags[tag] = n
            continue
        per_class[cls]["writeups"] += n
        per_class[cls]["tags"][tag] = n

    print("\n" + "=" * 74)
    print("EVIDENCE VOLUME per class (write-up instances, ecosystem reality)")
    print("=" * 74)
    our_items = dict(con.execute(
        "SELECT class_id, COUNT(*) FROM item WHERE status='active' GROUP BY class_id"))
    our_hc = dict(con.execute(
        "SELECT i.class_id, COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id"
        " WHERE i.status='active' AND q.validation_state='high_confidence'"
        " GROUP BY i.class_id"))
    rows = []
    for cls, v in per_class.items():
        rows.append((v["writeups"], cls, our_items.get(cls, 0),
                     our_hc.get(cls, 0)))
    rows.sort(reverse=True)
    print("  %-22s %8s %8s %8s" % ("class", "writeups", "items", "hi_conf"))
    for wu, cls, it, hc in rows:
        print("  %-22s %8d %8d %8d" % (cls, wu, it, hc))

    print("\n" + "=" * 74)
    print("PRIVILEGE-ESCALATION: real findings, and we have NO class for it")
    print("=" * 74)
    total_privesc = sum(privesc_tags.values())
    n_privesc_classes = con.execute(
        "SELECT COUNT(*) FROM bug_class WHERE id LIKE '%priv%' OR id LIKE '%privesc%'"
    ).fetchone()[0]
    for tag, n in sorted(privesc_tags.items(), key=lambda x: -x[1]):
        print("  %-42s %5d write-ups" % (tag, n))
    print("  %-42s %5d" % ("TOTAL privesc write-up instances", total_privesc))
    print("  our privesc classes: %d" % n_privesc_classes)

    print("\n" + "=" * 74)
    print("TOP UNROUTED TAGS (no mapping, NOT guessed onto a class)")
    print("=" * 74)
    for tag, n in sorted(unrouted.items(), key=lambda x: -x[1])[:25]:
        print("  %-46s %5d" % (tag, n))

    out = {
        "writeups": len(data),
        "distinct_tags": len(tag_n),
        "per_class": {k: v for k, v in per_class.items()},
        "privesc_tags": privesc_tags,
        "privesc_total": total_privesc,
        "unrouted": dict(sorted(unrouted.items(), key=lambda x: -x[1])),
        "top_tags": dict(tag_n.most_common(120)),
    }
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote %s" % OUT)


if __name__ == "__main__":
    main()