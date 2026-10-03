"""Extend the taxonomy to the brief's Web + API class list.

Every URL here is GET-verified before it is allowed to become a seed. That is
the difference between a taxonomy and a wish list: a class whose normative pages
all 404 can never satisfy MIN_PUBLISHER_HOSTS, so it would sit in the corpus
forever reporting `items=0` for a reason that has nothing to do with research.

Rule kept from R20/R21: the SEED is normative (CWE / OWASP / vendor standards).
`research_sources.py` stays a LEAD registry and is never referenced here.

Run:
    python wks/taxonomy_ext.py --verify     # check every URL, print the report
    python wks/taxonomy_ext.py --apply      # install verified seeds into the db
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wks import config, store  # noqa: E402
from wks.taxonomy import ClassSeed  # noqa: E402

UA = {"User-Agent": "WKS-Research/1.1 (taxonomy seed verification)"}

# class_id, name, surface, CWE number, OWASP/API label, PortSwigger topic,
# aliases, summary
CATALOG: list[tuple[str, str, str, int, str, str | None, tuple[str, ...], str]] = [
    # --- access control family -------------------------------------------------
    ("idor", "IDOR / BOLA (Object-Level Authorization)", "api", 639, "API1:2023",
     "/web-security/access-control/idor",
     ("broken object level authorization", "bola", "insecure direct object reference"),
     "The server does not verify the caller is entitled to the specific object the request names."),
    ("authz", "Missing Function-Level Authorization", "api", 862, "API5:2023",
     "/web-security/access-control",
     ("bfla", "admin endpoint exposure", "missing function level authorization"),
     "An endpoint checks that the caller is authenticated but not that they hold the required role."),
    ("csrf", "Cross-Site Request Forgery", "web", 352, "A01:2021",
     "/web-security/csrf",
     ("csrf", "xsrf", "cross site request forgery"),
     "A state-changing request is honoured from a foreign origin using the victim's ambient credentials."),
    # --- injection family ------------------------------------------------------
    ("xss", "Cross-Site Scripting", "client", 79, "A03:2021",
     "/web-security/cross-site-scripting",
     ("xss", "stored xss", "reflected xss", "dom xss"),
     "Attacker-controlled data reaches a script execution context in another user's browser unneutralised."),
    ("sqli", "SQL Injection", "web", 89, "A03:2021",
     "/web-security/sql-injection",
     ("sqli", "blind sqli", "second order sqli"),
     "Attacker input is concatenated into a SQL statement so the query structure becomes attacker-controlled."),
    ("nosql", "NoSQL / Operator Injection", "web", 943, "A03:2021",
     "/web-security/nosql-injection",
     ("nosql injection", "mongo injection", "operator injection"),
     "A document query is built from a parsed structure so type and operator semantics become attacker-controlled."),
    ("ssti", "Server-Side Template Injection", "web", 1336, "A03:2021",
     "/web-security/server-side-template-injection",
     ("ssti", "template injection", "jinja injection"),
     "User input is compiled as template source rather than rendered as data."),
    ("cmd", "OS Command Injection", "web", 78, "A03:2021",
     "/web-security/os-command-injection",
     ("command injection", "rce via command", "os command injection"),
     "Attacker input reaches a shell or process launcher and becomes part of the executed command."),
    ("xxe", "XML External Entity Injection", "web", 611, "A05:2021",
     "/web-security/xxe",
     ("xxe", "xml external entity", "blxxe"),
     "An XML parser resolves external or entity-expanded content the attacker controls."),
    ("deser", "Insecure Deserialization", "web", 502, "A08:2021",
     "/web-security/deserialization",
     ("deserialization", "java deserialization", "pickle rce"),
     "Untrusted data is deserialised into a type that carries behaviour, so the payload chooses the code path."),
    # PortSwigger publishes NO LDAP-injection page -- `/web-security/ldap-injection`
    # 404s (measured 2026-10-02) -- and this row used to point at
    # `/web-security/sql-injection`, a different class, which inflated ldap's
    # publisher count with a page that never supported it. `ps` is therefore
    # None and the OWASP cheat sheet comes from OWASP_FALLBACK below. This also
    # corrects CWE-404 ("Improper Resource Shutdown"), which candidates() built
    # from this row before; CWE-90 is LDAP Injection and was always right.
    ("ldap", "LDAP / XPath / NoSQL-Style Injection", "web", 90, "A03:2021",
     None,
     ("ldap injection", "xpath injection", "orm injection"),
     "A filter or path expression is built from attacker input, changing the query structure."),
    # --- server-side request / file family -------------------------------------
    ("ssrf", "Server-Side Request Forgery", "web", 918, "A10:2021",
     "/web-security/ssrf",
     ("ssrf", "blind ssrf", "cloud metadata ssrf"),
     "The server fetches an attacker-influenced URL, crossing into networks the attacker cannot reach directly."),
    ("path_traversal", "Path Traversal / File Inclusion", "web", 22, "A01:2021",
     "/web-security/file-path-traversal",
     ("lfi", "rfi", "path traversal", "directory traversal", "file inclusion"),
     "A caller-supplied name resolves outside the intended directory."),
    ("file_upload", "Unrestricted File Upload", "web", 434, "A04:2021",
     "/web-security/file-upload",
     ("file upload", "unrestricted upload", "web shell upload"),
     "The server accepts an upload without constraining type, name, location or interpretation."),
    # --- protocol / parsing family --------------------------------------------
    ("smuggling", "Request Smuggling / HTTP Desync", "web", 444, "A04:2021",
     "/web-security/request-smuggling",
     ("request smuggling", "http desync", "cl te", "te cl"),
     "Front-end and back-end disagree about where one request ends, so one request becomes two."),
    ("cors", "CORS Misconfiguration", "web", 942, "A05:2021",
     "/web-security/cors",
     ("cors", "cross origin resource sharing", "cors misconfiguration"),
     "The cross-origin policy grants a foreign origin more access than intended."),
    ("host_header", "Host Header Injection", "web", 644, "A05:2021",
     "/web-security/host-header",
     ("host header", "password reset poisoning", "absolute url poisoning"),
     "The server builds a security-relevant URL or decision from a caller-controlled Host header."),
    ("open_redirect", "Open Redirect", "web", 601, "A01:2021",
     "/web-security/host-header",
     ("open redirect", "unvalidated redirect", "redirect uri validation"),
     "A redirect target is not constrained to a trusted destination."),
    ("crlf", "CRLF / Header Injection", "web", 93, "A03:2021",
     "/web-security/crlf-injection",
     ("crlf injection", "header injection", "response splitting"),
     "User input reaches a header or line boundary the protocol treats as a delimiter."),
    ("cache_poisoning", "Web Cache Poisoning", "web", 444, "A04:2021",
     "/web-security/web-cache-poisoning",
     ("cache poisoning", "web cache poisoning"),
     "Unkeyed attacker input is reflected into a response the cache stores and serves to others."),
    ("cache_deception", "Web Cache Deception", "web", 444, "A04:2021",
     "/web-security/web-cache-deception",
     ("cache deception", "web cache deception"),
     "A cache stores a personalised response under a key that other users can request."),
    ("clickjacking", "Clickjacking / UI Redressing", "client", 1021, "A05:2021",
     "/web-security/clickjacking",
     ("clickjacking", "ui redress", "frame embedding"),
     "A foreign page can frame and overlay the target so the user's click means something they did not intend."),
    ("prototype_pollution", "Prototype Pollution", "web", 1321, "A08:2021",
     "/web-security/prototype-pollution",
     ("prototype pollution", "pp", "object prototype pollution"),
     "Caller input reaches a property write path that mutates a shared prototype."),
    # --- identity / session ----------------------------------------------------
    ("jwt", "JWT / Token Validation Failures", "identity", 347, "API8:2023",
     "/web-security/jwt",
     ("jwt", "algorithm confusion", "none algorithm", "jwk injection"),
     "The application makes an authorisation decision from a token whose signature, algorithm or claims it never verified."),
    ("oauth", "OAuth 2.0 / OIDC Misconfiguration", "identity", 346, "API8:2023",
     "/web-security/oauth",
     ("oauth", "oidc", "redirect uri validation", "sso open redirect"),
     "The authorization server or client accepts a redirect, scope, audience or flow it should reject."),
    ("authn", "Authentication Failures", "identity", 287, "A07:2021",
     "/web-security/authentication",
     ("authentication bypass", "weak login", "password reset flaw", "mfa bypass", "account takeover"),
     "The mechanism that establishes identity can be bypassed, reused, or subverted end to end."),
    ("session", "Session Management Flaws", "identity", 384, "A07:2021",
     "/web-security/session-management",
     ("session fixation", "session management", "cookie flags", "session hijacking"),
     "Session identity, lifetime or binding is weaker than the operation's risk requires."),
    # --- logic / workflow ------------------------------------------------------
    ("bizlogic", "Business Logic Flaws", "business", 840, "A04:2021",
     "/web-security/logic-flaws",
     ("business logic", "workflow bypass", "logic flaw", "price manipulation"),
     "A sequence or amount that the business intends to constrain can be reached out of order or out of proportion."),
    ("race", "Race Conditions / TOCTOU", "business", 367, "A04:2021",
     "/web-security/race-conditions",
     ("race condition", "toctou", "double spend", "concurrency"),
     "A check and the operation it guards are not atomic, so interleaving changes the outcome."),
    ("mass_assign", "Mass Assignment / Excessive Data Exposure", "api", 915, "API1:2023",
     "/web-security/mass-assignment",
     ("mass assignment", "property level authorization", "excessive data exposure", "over-posting"),
     "The write or read surface covers fields the caller should not control or see."),
    # --- api-specific ----------------------------------------------------------
    ("graphql", "GraphQL Attack Surface", "api", 749, "API1:2023",
     "/web-security/graphql",
     ("graphql", "introspection", "graphql batching", "graphql injection"),
     "A single flexible endpoint exposes schema, depth and per-field authorisation the REST surface would separate."),
    ("websocket", "WebSocket Weaknesses", "web", 1004, "A04:2021",
     "/web-security/websockets",
     ("websockets", "ws", "cross site websocket hijacking"),
     "The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request."),
    ("api_trust", "API-to-API Trust Failures", "api", 918, "API8:2023",
     "/web-security/api-testing",
     ("api to api trust", "internal service trust", "shadow api", "undocumented api"),
     "A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced."),
    # --- information / configuration -------------------------------------------
    ("info_disclosure", "Information Disclosure", "web", 200, "A01:2021",
     "/web-security/information-disclosure",
     ("info disclosure", "information exposure", "verbose errors", "debug exposure", "secrets exposure"),
     "Error output, directory listings or metadata reveal more about the system than the caller should learn."),
    ("misconfig", "Security Misconfiguration", "web", 16, "A05:2021",
     "/web-security/misconfiguration",
     ("misconfiguration", "security headers", "debug mode", "default credentials"),
     "A deployable default or an absent hardening control leaves a capability the design assumed was closed."),
    ("supply_chain", "Dependency / Supply-Chain Risk", "web", 1104, "A06:2021",
     "/web-security/dependencies",
     ("dependency confusion", "supply chain", "outdated component", "vulnerable dependency"),
     "Trust placed in a component, its registry or its build exceeds what was actually verified."),
    ("subdomain_takeover", "Subdomain Takeover", "infra", 404, "A10:2021",
     "/web-security/misconfiguration",
     ("subdomain takeover", "dangling dns", "dangling cname"),
     "A DNS record still points at a de-provisioned service that anyone can now claim."),
]

CWE_URL = "https://cwe.mitre.org/data/definitions/{n}.html"


def ps_url(topic: str | None) -> str | None:
    return f"https://portswigger.net{topic}" if topic else None


OWASP_SHEET = "https://cheatsheetseries.owasp.org/cheatsheets/{n}_Cheat_Sheet.html"

# Classes whose PortSwigger topic 404s get an OWASP cheat sheet instead. Both
# are normative publishers and independent of each other, which is what the
# 2-host gate needs. Names verified against the live cheatsheet index.
OWASP_FALLBACK = {
    "crlf": "HTTP_Headers",
    "session": "Session_Management",
    "mass_assign": "Mass_Assignment",
    "misconfig": "Secure_Product_Design",
    "supply_chain": "Software_Supply_Chain_Security",
    "subdomain_takeover": "Subdomain_Takeover_Prevention",
    "info_disclosure": "Error_Handling",
    "api_trust": "Microservices_Security",
    # PortSwigger has no LDAP-injection page (404, measured 2026-10-02), so
    # `ldap` needs the OWASP sheet to reach two independent publishers.
    "ldap": "LDAP_Injection_Prevention",
}


def candidates(cid: str, cwe: int, ps: str | None) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = [(CWE_URL.format(n=cwe), "taxonomy")]
    u = ps_url(ps)
    if u:
        out.append((u, "cheatsheet"))
    sheet = OWASP_FALLBACK.get(cid)
    if sheet:
        out.append((OWASP_SHEET.format(n=sheet), "cheatsheet"))
    return out


def verify(urls: list[str], timeout: int = 25) -> dict[str, dict[str, Any]]:
    rep: dict[str, dict[str, Any]] = {}
    for u in urls:
        try:
            with urllib.request.urlopen(urllib.request.Request(u, headers=UA),
                                        timeout=timeout) as f:
                body = f.read()
            # A page that returns a 200 stub is not a source. pipeline.fetch
            # refuses bodies under 2000 chars for exactly this reason.
            rep[u] = {"status": 200, "chars": len(body),
                      "ok": len(body) >= 2000}
        except Exception as e:
            rep[u] = {"status": getattr(e, "code", 0) or 0, "chars": 0,
                      "ok": False, "error": str(e)[:120]}
    return rep


def build(root: Path | None = None) -> tuple[list[ClassSeed], dict[str, Any]]:
    all_urls = sorted({u for c in CATALOG for u, _ in candidates(c[0], c[3], c[5])})
    rep = verify(all_urls)
    seeds: list[ClassSeed] = []
    report: dict[str, Any] = {"classes": [], "dead_urls": [],
                              "ok": 0, "unverifiable": []}
    for cid, name, surface, cwe, owasp, ps, aliases, summary in CATALOG:
        got: list[tuple[str, str]] = []
        for u, t in candidates(cid, cwe, ps):
            r = rep.get(u)
            if r is None:
                # A URL that was never verified is treated as unusable, never
                # as acceptable. candidates() and the fetch list must agree.
                report["dead_urls"].append({"class": cid, "url": u,
                                            "status": "NEVER-FETCHED"})
                continue
            if r["ok"]:
                got.append((u, t))
            else:
                report["dead_urls"].append({"class": cid, "url": u,
                                            "status": r["status"]})
        hosts = {u.split("/")[2] for u, _ in got}
        entry = {"class_id": cid, "cwe": cwe, "urls": len(got),
                 "hosts": sorted(hosts), "corroboration_possible": len(hosts) >= 2}
        if len(hosts) >= 2:
            seeds.append(ClassSeed(cid, name, surface, cwe=cwe, owasp=owasp,
                                   aliases=aliases, summary=summary,
                                   sources=tuple(got)))
            report["ok"] += 1
            entry["registered"] = True
        else:
            report["unverifiable"].append(cid)
            entry["registered"] = False
        report["classes"].append(entry)
    return seeds, report


def apply(seeds: list[ClassSeed], root: Path | None = None) -> dict[str, int]:
    con = store.open_db(create=True)
    n = 0
    for s in seeds:
        store.upsert_class(con, s.id, s.name, s.surface, cwe=s.cwe, owasp=s.owasp,
                           aliases=s.aliases, summary=s.summary, status="planned")
        n += 1
    con.commit()
    total = con.execute("SELECT count(*) FROM bug_class").fetchone()[0]
    con.close()
    return {"upserted": n, "classes_in_db": total}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="taxonomy_ext")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    seeds, rep = build()
    out = config.runtime_dir() /  "taxonomy-ext-verification.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rep, indent=2), encoding="utf-8")

    print(f"catalog={len(CATALOG)} corroborated={rep['ok']} "
          f"unverifiable={len(rep['unverifiable'])} dead_urls={len(rep['dead_urls'])}")
    for e in rep["classes"]:
        flag = "" if e["registered"] else "  <-- CAN NEVER CORROBORATE"
        print(f"  {e['class_id']:20} urls={e['urls']} hosts={','.join(e['hosts'])}{flag}")
    if rep["dead_urls"]:
        print("\nDEAD / UNUSABLE:")
        for d in rep["dead_urls"]:
            print(f"  {d['class']:20} {d['status']:>4} {d['url']}")
    print(f"\nwritten: {out}")
    if a.apply:
        print(json.dumps(apply(seeds), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())