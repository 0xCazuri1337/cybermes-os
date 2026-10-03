"""Give the 16 held items a genuine second publisher, with REAL quotes.

The rule this script exists to respect: a second citation that satisfies the
gate without saying anything the first one did not is not corroboration, it is
laundering. So nothing here is hand-written.

For each held item:
  1. choose a page from a DIFFERENT publisher org (chosen from the normative
     catalog in db/sources.json, never invented);
  2. fetch it LIVE;
  3. slice a real sentence out of the fetched text, chosen by distinctive terms
     drawn from the item's own claim;
  4. HARD-ASSERT the gate's own matcher accepts that span (find_quote);
  5. HARD-ASSERT the item will then hold >= 2 distinct publisher ORGS;
  6. write the item with its ORIGINAL claim/body/disproof untouched.

If any step fails for any item the script ABORTS and writes nothing. A
half-built file is worse than none: it would be ingested, and the quotes in it
are the part nobody re-checks by hand.

Term anchors per item are the item's own subject matter -- 'the KDC encrypts
the ticket with RC4', not the item_key. A quote is accepted only if it shares
real vocabulary with the claim it is being used to support.
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402
from wks.verify_quotes import find_quote  # noqa: E402
from wks import pipeline  # noqa: E402

# Second publisher per held item. `org` is asserted at build time -- if the
# catalog stops offering it, the build fails rather than silently re-citing.
CANDIDATE: dict[str, dict[str, Any]] = {
    # --- held on owasp.org (cheatsheetseries + wstg + api-security) --------
    "idor.prereq.client_controlled_object_identifier": {
        "url": "https://portswigger.net/web-security/access-control/idor",
        "org": "portswigger.net",
        "terms": ["user-supplied input to access objects directly",
                  "access control vulnerability", "IDOR"],
    },
    "idor.validation.two_account_cross_tenant_read": {
        "url": "https://portswigger.net/web-security/access-control/idor",
        "org": "portswigger.net",
        "terms": ["user-controlled parameter values are used to access resources",
                  "landed in the user's accounts page", "direct reference"],
    },
    # PortSwigger's GraphQL page carries no injection prose at all (measured:
    # 0 sentences for SQL/NoSQL/inject/resolver), so a second OWASP-family
    # citation would have been fabricated relevance. CWE-749 is the right
    # independent authority for "an exposed resolver reaches a dangerous
    # operation", and it is a DIFFERENT org.
    "graphql.impact.resolver_interpolation_injection": {
        "url": "https://cwe.mitre.org/data/definitions/749.html",
        "org": "mitre.org",
        "terms": ["dangerous method", "function", "GraphQL", "improperly",
                  "exposed"],
    },
    # Same reason: the SSRF page has no 169.254.169.254 / metadata prose.
    # CWE-918 is the normative definition and does carry it.
    "ssrf.technique.cloud_metadata_endpoints": {
        "url": "https://cwe.mitre.org/data/definitions/918.html",
        "org": "mitre.org",
        "terms": ["169.254.169.254", "metadata", "Server-Side Request Forgery",
                  "internal"],
    },
    # --- held on ietf.org (datatracker.ietf.org + ietf.org) ----------------
    "jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline": {
        "url": "https://portswigger.net/web-security/jwt",
        "org": "portswigger.net",
        "terms": ["alg parameter is set to none", "unsecured JWT",
                  "which algorithm it needs to use when verifying"],
    },
    "jwt.fprule.unread_claims_prove_nothing": {
        "url": "https://portswigger.net/web-security/jwt",
        "org": "portswigger.net",
        "terms": ["aud (audience) claim", "intended recipient", "claims",
                  "payload contains the actual"],
    },
    "jwt.fprule.kid_and_jku_need_a_callback_not_reflection": {
        "url": "https://portswigger.net/web-security/jwt",
        "org": "portswigger.net",
        "terms": ["jku (JSON Web Key Set URL)", "fetch a set of keys",
                  "kid (Key ID)", "self-signed JWTs via the jku"],
    },
    "ssrf.fprule.redirect_and_dns_are_separate_defects": {
        "url": "https://portswigger.net/web-security/ssrf",
        "org": "portswigger.net",
        "terms": ["whitelist of permitted values", "redirects to the target URL",
                  "different redirect codes", "blacklist-based input filters"],
    },
    # This item already cites cheatsheetseries.owasp.org + owasp.org, i.e. it is
    # held ON owasp.org -- nominating another OWASP page would have added a
    # citation without adding an org.
    "ssrf.fprule.silence_is_uninformative_without_an_egress_control": {
        "url": "https://portswigger.net/web-security/ssrf",
        "org": "portswigger.net",
        "terms": ["internal back-end systems contain sensitive functionality",
                  "connection to internal-only services",
                  "interact with the systems"],
    },
    # --- held on mitre.org (cwe.mitre.org + attack.mitre.org) --------------
    # Kerberoasting's authority IS MITRE, so the second publisher must be the
    # vendor that defines the protocol: MS-NLMP / Kerberos overview, both URLs
    # already cited elsewhere in this corpus and therefore proven live.
    "ad_kerberos.technique.kerberoast_rc4_tgs_offline_crack": {
        "url": "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview",
        "org": "microsoft.com",
        "terms": ["service ticket", "ticket-granting", "Kerberos", "KDC",
                  "session key"],
    },
    "pass_the_hash.technique.replay_hash_as_credential": {
        "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/",
        "org": "microsoft.com",
        "terms": ["NTLM", "challenge", "response", "credential", "session key"],
    },
    # --- held on microsoft.com (learn.microsoft.com + microsoft.com) -------
    "winrm.technique.winrm_remoting_is_the_lateral_execution_channel": {
        "url": "https://attack.mitre.org/techniques/T1021/006/",
        "org": "mitre.org",
        "terms": ["WinRM is the name of both a Windows service and a protocol",
                  "interact with a remote system", "winrm command"],
    },
    "ldap_enum.prerequisite.unsigned_ldap_bind_is_the_read_precondition": {
        "url": "https://www.rfc-editor.org/rfc/rfc4511.html",
        "org": "rfc-editor.org",
        "terms": ["simple bind", "SASL", "integrity", "unencrypted",
                          "name is not authenticated"],
    },
    # The ATT&CK sub-technique for RBCD could not be located by reading the
        # site's link structure -- attack.mitre.org renders its sub-technique lists
        # client-side, so a plain fetch yields no hrefs, and guessing IDs produced
        # two wrong pages (T1134/003 is "Make and Impersonate Token"). Rather than
        # cite a technique that does not cover the claim, the second publisher is
        # the IETF standard that DEFINES Kerberos delegation: RFC 4120. Different
        # org from the item's own (microsoft.com), and on point --
        #   "The ability for a client to obtain a service ticket to a server
        #    conveys no information to the client about whether the server should
        #    be trusted to accept delegated credentials."
        "ad_delegation.chain_link.rbcd_ticket_forward_hands_system_shell_to_next_link": {
            "url": "https://www.rfc-editor.org/rfc/rfc4120.html",
            "org": "rfc-editor.org",
            "terms": ["accept delegated credentials", "proxiable flags",
                      "proxy by using the proxy", "allow a service to perform"],
        },
    "pass_the_hash.chain_link.dumped_ntlm_hands_authenticated_channel_to_lateral_link": {
        "url": "https://attack.mitre.org/techniques/T1550/002/",
        "org": "mitre.org",
        "terms": ["Pass the hash (PtH) is a method of authenticating",
                  "stolen password hashes", "NTLM"],
    },
    "authz.chain_link.app_service_identity_hands_broader_scope_to_cloud_link": {
        "url": "https://cwe.mitre.org/data/definitions/862.html",
        "org": "mitre.org",
        "terms": ["improper authorization", "permission", "privilege",
                  "access control"],
    },
}

_SENT = re.compile(r"(?<=[.!?])\s+")

# Markup that survives tag-stripping because it lives INSIDE <script>/<style>.
# `find_quote` will happily confirm a CSS rule is on the page -- it checks
# presence, not sense -- so a quote chosen from this residue verifies while
# supporting nothing. Judgement belongs at extraction, not in the matcher.
_MARKUP = re.compile(
    r"(#script|#noscript|visibility\s*:|display\s*:|font-size\s*:"
    r"|function\s*\(|var\s+[A-Za-z_$]|try\s*\{|\}\s*\}|"
    r"\.\w+\s*\{|=>|\breturn\b|\bundefined\b|\bnull\b;|"
    r"\{[^{}]{0,80}\})")


def is_prose(s: str) -> bool:
    """True when a candidate span reads as a sentence a reviewer would cite.

    Rejects markup residue, unbalanced braces, and anything that does not look
    like natural language. Deliberately strict: a false rejection costs one more
    candidate, and a false ACCEPTANCE puts a CSS rule in the corpus as evidence.
    """
    if _MARKUP.search(s):
        return False
    letters = sum(c.isalpha() or c.isspace() for c in s)
    if letters / max(len(s), 1) < 0.72:
        return False
    # Must contain at least two real words of length >= 3.
    words = [w for w in re.findall(r"[A-Za-z]{3,}", s)]
    return len(words) >= 6


def sentences(text: str) -> list[str]:
    out = []
    for chunk in _SENT.split(text):
        c = " ".join(chunk.split())
        if 60 <= len(c) <= 420:
            out.append(c)
    return out


# Sentences already claimed by an earlier item in this batch. Two claims citing
# one identical span is ONE source wearing two hats, not corroboration -- and
# the gate cannot tell the difference, so the builder has to.
_used_spans: set[str] = set()


def pick_quote(page_text: str, terms: list[str], claim: str) -> str | None:
    """Choose a REAL sentence that shares vocabulary with the claim.

    Scored, not first-match: a quote that shares more of the item's own
    subject matter is a better citation. A sentence that matched only one weak
    term would satisfy the matcher while saying nothing useful, which is the
    laundering failure this whole exercise is meant to avoid.
    """
    claim_terms = {t.lower() for t in re.findall(r"[a-z0-9]{4,}", claim.lower())}
    best, best_score = None, 0
    for s in sentences(page_text):
        if not is_prose(s):
            continue
        low = s.lower()
        hits = sum(1 for t in terms if t.lower() in low)
        if hits == 0:
            continue
        overlap = len(claim_terms & set(re.findall(r"[a-z0-9]{4,}", low)))
        score = hits * 2 + overlap
        if score <= best_score:
            continue
        if s in _used_spans:
            continue
        best, best_score = s, score
    if best is None or best_score < 3:
        return None
    _used_spans.add(best)
    return best


def main() -> int:
    con = store.open_db(create=False)
    held = con.execute(
        """SELECT i.item_key, i.claim, i.kind, i.body, i.disproof, i.surface,
                  i.severity_hint, i.hunting_value
           FROM quality q JOIN item i ON i.id=q.item_id
           WHERE q.gate_reasons LIKE '%INSUFFICIENT_PUBLISHER_HOSTS%'
           ORDER BY i.item_key""").fetchall()
    if len(held) != len(CANDIDATE):
        print(f"ABORT: {len(held)} held items but {len(CANDIDATE)} candidates")
        return 2

    # existing citations per item, so the new one can be appended, not replace
    built: list[dict[str, Any]] = []
    problems: list[str] = []
    for row in held:
        key = row["item_key"]
        cand = CANDIDATE.get(key)
        if not cand:
            problems.append(f"{key}: no candidate")
            continue
        got = pipeline.fetch(cand["url"], limit=1_500_000)
        if got.get("access_state") != "ACTIVE":
            problems.append(f"{key}: {cand['url']} -> {got.get('access_state')}")
            continue
        quote = pick_quote(got["text"], cand["terms"], row["claim"])
        if not quote:
            problems.append(f"{key}: no sentence matched {cand['terms'][:3]}")
            continue
        # THE gate. Same matcher the corpus uses, on the same bytes.
        if not find_quote(got["text"], quote):
            problems.append(f"{key}: extracted span failed find_quote")
            continue
        existing = [dict(r) for r in con.execute(
            """SELECT s.url, s.host, s.source_type, x.quote, x.locator
               FROM item_source x JOIN source s ON s.id=x.source_id
               WHERE x.item_id=(SELECT id FROM item WHERE item_key=?)""",
            (key,)).fetchall()]
        orgs = {config.publisher_org(s["host"]) for s in existing}
        # The candidate must be a genuinely NEW org. Nominating a second page in
        # the org the item is already held on is the mistake this check exists
        # to catch -- it would add a citation and satisfy nothing.
        if cand["org"] in orgs:
            problems.append(
                f"{key}: candidate org {cand['org']} is already the item's org; "
                f"a second page there adds a citation, not a publisher")
            continue
        orgs = orgs | {cand["org"]}
        if len(orgs) < 2:
            problems.append(f"{key}: still <2 orgs ({orgs})")
            continue
        built.append({
            "item_key": key, "claim": row["claim"], "kind": row["kind"],
            "body": row["body"], "disproof": row["disproof"],
            "surface": row["surface"], "severity_hint": row["severity_hint"],
            "hunting_value": row["hunting_value"],
            "sources": existing + [{
                "url": cand["url"],
                "host": pipeline.host_of(cand["url"]),
                "source_type": "docs",
                "quote": quote,
                "locator": "built by wks.corroborate (verified span)",
            }],
            "_orgs_after": sorted(orgs),
        })

    if problems:
        print("ABORT -- nothing written. Problems:")
        for p in problems:
            print("  -", p)
        con.close()
        return 1

    out = Path(ROOT) / "research" / "pending" / "corroborate-16.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(
        {"generated_by": "wks/corroborate.py",
         "note": ("second-publisher citations for the 16 items held on a single "
                  "publisher org. Every quote was sliced from a live fetch and "
                  "accepted by wks.verify_quotes.find_quote at build time."),
         "items": built}, indent=1), encoding="utf-8")
    print(f"wrote {out} with {len(built)} items")
    for b in built:
        q = b["sources"][-1]["quote"]
        print(f"  {b['item_key'][:58]:58} orgs={b['_orgs_after']}")
        print(f"      + {q[:110]!r}")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())