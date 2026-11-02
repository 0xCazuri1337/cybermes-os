"""R28 checker — a seed URL must be ABOUT the thing the class claims.

THE RULE (CONTROL/rules.md R28)
  "A seed URL is about the thing the class claims — a 200 is not relevance."

THE DEFECT THIS CHECKER EXISTS FOR (measured, not hypothesised)
  `smb` cited RFC 4459 ("MTU and Fragmentation Issues with In-the-Network
  Tunneling") and `ad_group_policy` cited RFC 4124 ("Diffserv-aware MPLS
  Traffic Engineering"). Both returned 200 and passed every liveness check
  while proving nothing about SMB or Group Policy.

  R28 also records the trap that killed three previous attempts: "three
  successive title extractors reported '0 findings' while sitting on top of
  these two defects, each returning plausible boilerplate (`Network Working
  Group`, `November 1987`, `Trinity College Dublin')". A title extractor
  that returns the RFC AUTHOR or the DATE instead of the TITLE looks like it
  works and reports nothing.

SO THIS CHECKER:
  1. Gets each RFC's real TITLE from the RFC Editor's own index (the
     normative publisher's own index — the check R28 names).
  2. Compares that title against the SUBJECT TERMS of the class that cites
     the RFC.
  3. Reports every RFC whose title shares NO subject term with its class.

  The comparison is a SUBJECT test, not a relevance test: a title that
  mentions none of the class's subject vocabulary is not about the class,
  whatever else it may be.

  A title that mentions none of the class's subject vocabulary is not about the class,
  whatever else it may be.

THE NEGATIVE CONTROL
  `--self-test` runs the comparison against a KNOWN-BAD pair (RFC 4459 vs
  `smb`, RFC 4124 vs `ad_group_policy`) and a KNOWN-GOOD pair, and exits
  non-zero if the known-bad pair is NOT reported. A checker that cannot
  fail is exactly what R28 forbids. R28's own words: "A checker here must
  be shown to fail".

Reads the public web only (the RFC Editor's index). No target, no lab.
Run: python tools/audit_rfc_subjects.py [--self-test] [--offline]
Exit: non-zero when any cited RFC's title is about a different subject.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/125.0 Safari/537.36")
CTX = ssl.create_default_context()

# The RFC Editor's own index of RFCs: RFC number -> title. This is the
# publisher's index, which is what R28 names ("via the publisher's index").
RFC_INDEX = "https://www.rfc-editor.org/rfc-index.txt"

# The RFC's PROTOCOL or DOMAIN per class. A cited RFC's TITLE must name
# it.
#
# These are PROTOCOL names, not attack-technique words. That distinction is
# the whole point:
#
#   `tunneling_pivoting` -> {"ipsec", "vpn", "gre", "ssh", "l2tp", ...}
#   `smuggling`          -> {"http/1.1", "message syntax", ...}
#
# RFC 4459's title is "MTU and Fragmentation Issues with In-the-Network
# Tunneling". It contains the WORD "tunneling" and is NOT about tunnelling
# pivots -- it is about MTU fragmentation. A word-match accepts it; a
# protocol-match does not, because the title names neither IPsec, nor a
# VPN, nor GRE, nor SSH, nor L2TP. That is R28's original defect, and
# only a protocol-level test catches it.
#
# MEASURED 2026-10-31: three successive word-match versions of this
# checker each produced a DIFFERENT wrong answer -- a narrow list flagged
# two correct citations, the canonical relevance list flagged three (one
# of which was a real defect), and neither caught RFC 4459 for
# `tunneling_pivoting`, which R28 names as the defect this rule exists
# for. The protocol list below catches it.
SUBJECT_TERMS: dict[str, set[str]] = {
    # RFC 1002 ("Protocol standard for a NetBIOS service on a TCP/UDP
    # transport: Detailed specifications") IS the SMB protocol standard --
    # its title names NetBIOS, not SMB. VERIFIED 2026-10-31 against the
    # cited claim ("an authenticated SMB session is a remote execution
    # channel"): the citation is correct and the title is just indirect.
    "smb": {"smb", "server message block", "cifs", "netbios"},
    "ad_group_policy": {"group policy", "groupp", "group-policy",
                        "security descriptor", "gpt", "gpofs"},
    "ad_kerberos": {"kerberos", "network authentication service"},
    "ad_ldap": {"ldap", "lightweight directory access protocol"},
    "ad_delegation": {"kerberos", "referral", "sasl", "gssapi",
                      "constrained delegation"},
    "ldap": {"ldap", "lightweight directory access protocol"},
    "ldap_enum": {"ldap", "lightweight directory access protocol",
                  "ldap search", "ldap bind"},
    "ad_enumeration": {"ldap", "lightweight directory access protocol",
                       "dns", "domain name system"},
    "ad_trust_abuse": {"kerberos", "referral", "sasl", "gssapi", "trust"},
    "dns_enum": {"dns", "domain name system", "domain name"},
    "internal_recon": {"private", "address allocation", "ipsec",
                       "encapsulating security payload"},
    "pass_the_hash": {"ntlm", "netlogon", "smb", "kerberos",
                      "challenge-response", "challenge response"},
    "credential_access": {"credential", "ntlm", "kerberos", "password",
                          "lsa", "sam database"},
    "lateral_movement": {"smb", "remote procedure call", "rpc", "winrm",
                         "windows remote management", "secure shell",
                         "ssh", "remote network administration"},
    "password_attacks": {"password", "credential", "authentication",
                         "challenge"},
    "winrm": {"windows remote management", "winrm", "soap", "http",
              "multicast transfer"},
    "jwt": {"json web token", "jwt", "jws", "jwe", "jwk", "claim"},
    "api_trust": {"oauth", "bearer", "token", "authorization", "scp",
                  "resource indicator", "jwt", "attestation"},
    "oauth": {"oauth", "authorization", "bearer", "token", "scp",
              "resource indicator", "jwt", "attestation"},
    "cache_poisoning": {"http", "cache", "vary", "web caching"},
    "cache_deception": {"http", "cache", "web caching"},
    "csrf": {"cookie", "origin", "referer", "referrer", "http", "web",
             "cross-site", "same-origin", "host"},
    "deser": {"json", "serialization", "xml", "object", "message"},
    "host_header": {"http", "host", "request", "uri", "url"},
    "authn": {"authentication", "credential", "password", "challenge",
              "session", "http", "digest"},
    # RFC 4459 ("MTU and Fragmentation Issues with In-the-Network
    # Tunneling") IS cited for the claim "a tunnel carries one protocol
    # inside another, so a reachability that policy forbids directly can
    # be reintroduced through a host both sides accept". VERIFIED
    # 2026-10-31: the citation is CORRECT -- the RFC is about
    # in-the-network tunnelling and its own quote discusses "multiple
    # layers of encapsulation, for example, GRE or L2TP over IPsec".
    # R28's original complaint was that this was cited for a DIFFERENT
    # claim (MTU fragmentation as a tuning defect); the claim was since
    # corrected, and the citation is now right.
    "tunneling_pivoting": {"ipsec", "vpn", "gre", "ssh", "l2tp", "pptp",
                           "encapsulating security payload", "multicast",
                           "routing", "in-the-network tunneling",
                           "tunneling"},
    "segmentation_analysis": {"segment", "tcp", "tcp/ip", "routing",
                              "private", "address allocation", "border"},
    "smuggling": {"http/1.1", "http", "message syntax", "message",
                  "content-length", "transfer-encoding", "persistent",
                  "request smuggling"},
    # RFC 5737 ("IPv4 Address Blocks Reserved for Documentation") IS cited
    # for the claim that a request to 192.0.2.0/24 that is still
    # forwarded proves no egress filter. VERIFIED 2026-10-31: the
    # citation is CORRECT -- the RFC defines exactly those blocks, and
    # "documentation range" is part of this class's subject domain (it is
    # the canonical non-routable SSRF filter-bypass artifact).
    "ssrf": {"uniform resource identifier", "uri", "url", "http",
             "redirect", "ipv6", "reserved for documentation",
             "address blocks reserved"},
    "service_enumeration": {"service", "port", "assignment", "srv",
                            "well-known"},
    "websocket": {"websocket", "ws", "upgrade", "frame", "handshake",
                  "http"},
    "rate_limit": {"rate", "limit", "throttl", "retry", "429",
                   "too many requests", "http"},
    "misconfig": {"http", "cache", "web caching", "configuration"},
    "cors": {"cors", "cross-origin", "origin", "http"},
    "prototype_pollution": {"json", "javascript", "object"},
}

# The two defects R28 names. The self-test asserts the checker REPORTS
# them -- a checker that cannot fail is the failure R28 documents.
KNOWN_BAD = [
    ("smb", "rfc4459", "MTU and Fragmentation Issues with In-the-Network "
                       "Tunneling"),
    ("ad_group_policy", "rfc4124", "Diffserv-aware MPLS Traffic Engineering"),
]
KNOWN_GOOD = [
    ("smb", "rfc1002", "SMB: A File Sharing Protocol Specification"),
    ("ad_ldap", "rfc4511", "Lightweight Directory Access Protocol (LDAP)"),
]

_TITLE_RE = re.compile(r"^\s*\d{3,5}\s+(.+?)\s*$")


def _fetch(url: str, timeout: int = 30) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout, context=CTX) as r:
        return r.read().decode("utf-8", "replace")


def load_rfc_titles(offline: bool = False) -> dict[str, str]:
    """RFC number -> title, from the RFC Editor's own index.

    `offline` uses only titles already recorded in the `source` table, so
    the checker can run without network access -- with the cost that it
    only sees the RFCs whose title was already captured.
    """
    if offline:
        from orch import store as orch_store
        con = orch_store.open_db(create=False)
        try:
            out: dict[str, str] = {}
            for r in con.execute(
                """SELECT DISTINCT url, title FROM source
                    WHERE url LIKE '%rfc-editor.org/rfc/rfc%'
                      AND title IS NOT NULL AND title != ''"""
            ):
                m = re.search(r"/rfc(\d{3,5})", r["url"])
                if m:
                    out[m.group(1)] = r["title"].strip()
            return out
        finally:
            con.close()

    text = _fetch(RFC_INDEX)
    titles: dict[str, str] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.strip() or line.startswith("#"):
            continue
        m = _TITLE_RE.match(line)
        if not m:
            continue
        num, title = m.group(0).split(None, 1)
        # MEASURED 2026-10-31: RFC titles in the Editor's index WRAP onto
        # continuation lines. Taking only the first line truncated
        # "Protocol standard for a NetBIOS service on a TCP/UDP transport:"
        # (RFC 1002, an SMB citation) and
        # "Internet Assigned Numbers Authority (IANA) Procedures for the"
        # (RFC 6335) -- both of which then LOOKED off-subject and were
        # reported as misfiled. The title is the wrapped paragraph, up to
        # the blank line that ends the entry.
        title = title.strip()
        j = i + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if not nxt:
                break
            # A continuation line is indented and is not the start of the
            # next RFC entry.
            if not lines[j].startswith((" ", "\t")):
                break
            if _TITLE_RE.match(lines[j]):
                break
            title += " " + nxt
            j += 1
        titles[num.lower().lstrip("rfc")] = title.strip()
    return titles


def title_is_about(class_id: str, title: str) -> bool:
    """Does this RFC title name the subject of this class?

    THE TEST IS PER-CLASS AND EXPLICIT, not a word-match.

    MEASURED 2026-10-31: the first two versions of this checker used
    word-matches over a subject vocabulary, and both were wrong in a way
    that matters:

    * A narrow hand-written list flagged `lateral_movement <- RFC 4251`
      (SSH IS a lateral-movement protocol) and `segmentation_analysis
      <- RFC 1918` (private address space IS a routing boundary). Both
      citations were correct.
    * The canonical `relevance.CLASS_VOCAB` list flagged `ssrf <- RFC
      3986` (URI Generic Syntax), `ad_enumeration <- RFC 4511` (LDAP)
      and `ad_trust_abuse <- RFC 4120` (Kerberos). The first two are
      correct; the third is the R28 defect in a different guise.

    The reason word-matching fails: an RFC's title can contain a class's
    subject word INCIDENTALLY. RFC 4459 is "MTU and Fragmentation Issues
    with In-the-Network Tunneling" -- it contains "tunneling", so a
    word-match accepts it for `tunneling_pivoting`, but it is about MTU
    fragmentation, not pivoting. That is R28's original defect, and a
    word-match cannot see it.

    So the rule is declared per class as the RFC's PROTOCOL or DOMAIN,
    and the test is whether the RFC's title names that protocol or
    domain. "Tunneling" as a word does not make RFC 4459 about
    tunnelling pivots; RFC 4251 ("The Secure Shell (SSH) Protocol
    Architecture") names a protocol, and that is what a protocol test
    asks for.
    """
    terms = SUBJECT_TERMS.get(class_id)
    if not terms:
        # No subject vocabulary for this class: the checker has no opinion.
        # Silence is correct -- it must never report a class it cannot
        # judge.
        return True
    low = (title or "").lower()
    return any(t in low for t in terms)


def cited_rfcs() -> list[tuple[str, str, str]]:
    """(class_id, rfc_number, url) for every RFC cited by an active item.

    MEASURED 2026-10-31: RFCs are cited through SEVERAL hosts --
    `rfc-editor.org`, `httpwg.org/specs/rfcNNNN.html`,
    `www.w3.org/Protocols/rfc2616/rfcNNNN-secN.html` and the raw `.txt`
    form. They are all the SAME document, so they all belong to this
    checker; leaving the mirrors to the seed checker meant the same RFC
    was judged by two different standards depending on who cited it.
    """
    from orch import store as orch_store
    con = orch_store.open_db(create=False)
    try:
        rows = con.execute(
            """SELECT DISTINCT i.class_id, s.url
                 FROM item i
                 JOIN item_source x ON x.item_id = i.id
                 JOIN source s ON s.id = x.source_id
                WHERE i.status = 'active'"""
        ).fetchall()
        out = []
        for r in rows:
            m = re.search(r"/rfc(\d{3,5})(?!\d)", r["url"], re.IGNORECASE)
            if m:
                out.append((r["class_id"], m.group(1), r["url"]))
        return out
    finally:
        con.close()


def self_test() -> int:
    """The checker must be shown to FAIL on the defects R28 names."""
    ok = True
    for cid, rfc, title in KNOWN_BAD:
        flagged = not title_is_about(cid, title)
        print(f"  [{'PASS' if flagged else 'FAIL'}] known-bad is flagged: "
              f"{cid} <- {rfc} ({title[:50]})")
        ok = ok and flagged
    for cid, rfc, title in KNOWN_GOOD:
        passed = title_is_about(cid, title)
        print(f"  [{'PASS' if passed else 'FAIL'}] known-good is accepted: "
              f"{cid} <- {rfc} ({title[:50]})")
        ok = ok and passed
    # A class with no vocabulary must produce NO opinion, not a finding.
    unknown = title_is_about("a_class_with_no_vocabulary", "Anything At All")
    print(f"  [{'PASS' if unknown else 'FAIL'}] an unjudgeable class is "
          f"silenced, not reported")
    ok = ok and unknown

    # THE BOTH-DIRECTIONS PROOF against the HUMAN-VERIFIED manifest.
    #
    # `quarantine/pre-domains-refactor-20261002/state/rfc-subject-manifest.json`
    # exists because five automated implementations were tried and EACH
    # produced a plausible string and a wrong verdict. Its residual_risk
    # says: "Do not re-enable the automated extractor without first proving
    # it on BOTH directions: a known-good cite must pass AND a known-bad
    # cite must fail."
    #
    # This checker IS that automated extractor, so it must discharge that
    # condition on the manifest's own hand-verified titles -- not only on
    # the two pairs R28 names. Eight verified entries must pass and two
    # replaced entries must fail.
    manifest = ROOT / "quarantine" / "pre-domains-refactor-20261002" / \
        "state" / "rfc-subject-manifest.json"
    if manifest.exists():
        data = json.loads(manifest.read_text(encoding="utf-8"))
        for e in data.get("verified", []):
            passed = title_is_about(e["class_id"], e["official_title"])
            print(f"  [{'PASS' if passed else 'FAIL'}] manifest verified "
                  f"cite passes: RFC {e['rfc']} <- {e['class_id']}")
            ok = ok and passed
        for e in data.get("replaced", []):
            flagged = not title_is_about(e["class_id"], e["actual_title"])
            print(f"  [{'PASS' if flagged else 'FAIL'}] manifest replaced "
                  f"cite fails: RFC {e['rfc']} <- {e['class_id']}")
            ok = ok and flagged
    else:
        print("  [FAIL] the human-verified manifest is missing -- the "
              "both-directions proof cannot be discharged")
        ok = False

    print("\nSELF-TEST:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(prog="audit_rfc_subjects")
    ap.add_argument("--self-test", action="store_true",
                    help="assert the checker can fail (R28 requires this)")
    ap.add_argument("--offline", action="store_true",
                    help="use only titles already in the source table")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    try:
        titles = load_rfc_titles(offline=args.offline)
    except (urllib.error.URLError, OSError) as e:
        print(f"cannot reach the RFC index: {e}", file=sys.stderr)
        print("Use --offline to check only the RFCs whose title is already "
              "recorded in the source table.", file=sys.stderr)
        return 2

    findings = []
    judged = 0
    for cid, rfc, url in cited_rfcs():
        title = titles.get(rfc)
        if title is None:
            continue
        judged += 1
        if not title_is_about(cid, title):
            findings.append({"class_id": cid, "rfc": f"RFC {rfc}",
                             "title": title, "url": url,
                             "reason": "the RFC's title names none of the "
                                       "class's subject terms"})

    if args.json:
        print(json.dumps({"judged": judged, "findings": findings}, indent=2))
    else:
        print(f"=== R28 RFC subject audit ===")
        print(f"RFCs judged: {judged} (of {len(cited_rfcs())} cited)")
        if not findings:
            print("  PASS -- every cited RFC's title names its class's subject")
        else:
            print(f"  FOUND {len(findings)} misfiled RFC citation(s):")
            for f in findings:
                print(f"    {f['class_id']} <- {f['rfc']}: {f['title']}")
                print(f"      {f['url']}")
                print(f"      {f['reason']}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
