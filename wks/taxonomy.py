"""Bug class taxonomy + seed sources.

Taxonomy is seeded, not declared complete (§8): `python -m wks.cli verify-seeds`
checks every seed URL is live and that every class has >= MIN_PUBLISHER_HOSTS
distinct hosts. A class whose seeds sit on one host can NEVER pass the
corroboration gate, so that is checked before any research is spent on it.

Two lessons are already encoded here, both paid for in the previous system:
  1. Seeding N URLs is not corroboration. Count distinct publisher HOSTS.
  2. A dead seed URL is worse than none, because it looks configured.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ClassSeed:
    id: str
    name: str
    surface: str
    cwe: str = ""
    owasp: str = ""
    aliases: tuple[str, ...] = ()
    summary: str = ""
    sources: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    # (url, source_type) — type sets the authority tier in config.py


# Publishers are deliberately spread across independent hosts: a taxonomy page
# (cwe/owasp) plus a practitioner's guidance (portswigger/hacktricks) is a real
# pair of independent authorities. Two pages on owasp.org is one publisher.
_SEED = (
    ClassSeed(
        "idor", "IDOR / BOLA (Object-Level Authorization)", "api",
        cwe="CWE-639", owasp="API1:2023",
        aliases=("broken object level authorization", "bola", "insecure direct object reference",
                 "object level authorization failure", "horizontal privilege escalation via id"),
        summary="A server fails to verify that the authenticated caller is entitled to the "
                "specific object identified by the request, so one user reaches another's data.",
        sources=(
            ("https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/", "taxonomy"),
            ("https://portswigger.net/web-security/access-control/idor", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/639.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "sqli", "SQL Injection", "web",
        cwe="CWE-89", owasp="A03:2021",
        aliases=("sql injection", "sqli", "second order sql injection", "nosql injection operator"),
        summary="Attacker-controlled input is concatenated into a SQL statement, so the "
                "query structure becomes attacker-controlled.",
        sources=(
            ("https://owasp.org/www-community/attacks/SQL_Injection", "cheatsheet"),
            ("https://portswigger.net/web-security/sql-injection", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/89.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "ssrf", "Server-Side Request Forgery", "web",
        cwe="CWE-918", owasp="A10:2021",
        aliases=("ssrf", "server side request forgery", "blind ssrf", "cloud metadata ssrf"),
        summary="The server fetches a URL influenced by the attacker, crossing a trust "
                "boundary into networks the attacker cannot reach directly.",
        sources=(
            ("https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "cheatsheet"),
            ("https://portswigger.net/web-security/ssrf", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/918.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "xss", "Cross-Site Scripting", "client",
        cwe="CWE-79", owasp="A03:2021",
        aliases=("xss", "cross site scripting", "stored xss", "reflected xss", "dom xss"),
        summary="Attacker-controlled data reaches a script execution context in another "
                "user's browser without neutralisation.",
        sources=(
            ("https://owasp.org/www-community/attacks/xss/", "cheatsheet"),
            ("https://portswigger.net/web-security/cross-site-scripting", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/79.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "authz", "Missing Function-Level Authorization", "api",
        cwe="CWE-862", owasp="API5:2023",
        aliases=("missing function level authorization", "bfla", "admin endpoint exposure",
                 "unauthorized access to administrative function"),
        summary="An endpoint checks that a caller is authenticated but not that they hold "
                "the role or permission the operation requires.",
        sources=(
            ("https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/", "taxonomy"),
            ("https://portswigger.net/web-security/access-control", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/862.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "jwt", "JWT / Token Validation Failures", "identity",
        cwe="CWE-347", owasp="API8:2023",
        aliases=("jwt", "algorithm confusion", "none algorithm attack", "jwk injection",
                 "token signature not verified", "kid injection"),
        summary="The application fails to verify a token's signature, algorithm or claims "
                "before making an authorization decision.",
        sources=(
            ("https://portswigger.net/web-security/jwt", "cheatsheet"),
            ("https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/347.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "oauth", "OAuth 2.0 / OIDC Misconfiguration", "identity",
        cwe="CWE-346", owasp="API8:2023",
        aliases=("oauth", "oidc", "oauth misconfiguration", "redirect_uri validation",
                 "open redirect in oauth", "sso open redirect"),
        summary="The authorization server or client accepts a redirect, scope, token "
                "audience or PKCE flow that it should reject.",
        sources=(
            ("https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html", "cheatsheet"),
            ("https://portswigger.net/web-security/oauth", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/346.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "race", "Race Conditions / TOCTOU", "business",
        cwe="CWE-367", owasp="A04:2021",
        aliases=("race condition", "toctou", "time of check time of use",
                 "double spend", "concurrent request limit bypass"),
        summary="Server-side state is read and acted upon non-atomically, so concurrent "
                "requests observe a check result that another request has already invalidated.",
        sources=(
            ("https://owasp.org/API-Security/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/367.html", "taxonomy"),
            ("https://portswigger.net/web-security/logic-flaws", "cheatsheet"),
        ),
    ),
    ClassSeed(
        "csrf", "Cross-Site Request Forgery", "web",
        cwe="CWE-352", owasp="A01:2021",
        aliases=("csrf", "cross site request forgery", "xsrf", "csrf token bypass"),
        summary="A state-changing request is accepted from another origin because the "
                "server never proves the request was intentionally initiated.",
        sources=(
            ("https://owasp.org/www-community/attacks/csrf", "cheatsheet"),
            ("https://portswigger.net/web-security/csrf", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/352.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "graphql", "GraphQL-Specific Attack Surface", "api",
        cwe="CWE-1004", owasp="API8:2023",
        aliases=("graphql", "graphql introspection", "graphql batching", "alias overload",
                 "graphql injection", "deeply nested query dos"),
        summary="A single flexible endpoint replaces many REST routes, so authorization "
                "must hold per resolved object rather than per route.",
        sources=(
            ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/4-GraphQL_Testing", "taxonomy"),
            ("https://portswigger.net/web-security/graphql", "cheatsheet"),
            ("https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html", "cheatsheet"),
            ("https://graphql.org/learn/global-object-identification/", "standard"),
            ("https://relay.dev/graphql/objectidentification.htm", "standard"),
        ),
    ),
    ClassSeed(
        "mass_assign", "Mass Assignment / Excessive Data Exposure", "api",
        cwe="CWE-915", owasp="API3:2023",
        aliases=("mass assignment", "excessive data exposure", "over posting",
                 "unintended json properties", "graphql over fetch"),
        summary="The server binds client-supplied fields straight onto a model, so a "
                "client can set properties the UI never exposes — including privilege fields.",
        sources=(
            ("https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/", "taxonomy"),
            ("https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/4-Web_Application_Testing/4-1-Testing_for_Weak_Access_Control", "taxonomy"),
            ("https://cwe.mitre.org/data/definitions/915.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "bizlogic", "Business Logic Flaws", "business",
        cwe="CWE-840", owasp="A04:2021",
        aliases=("business logic", "workflow bypass", "price manipulation",
                 "coupon abuse", "purchase flow manipulation"),
        summary="The application performs each step correctly in isolation but enforces "
                "no invariant across the sequence, so the sequence itself is the attack.",
        sources=(
            ("https://portswigger.net/web-security/logic-flaws", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/840.html", "taxonomy"),
            ("https://portswigger.net/web-security/logic-flaws", "cheatsheet"),
        ),
    ),
    ClassSeed(
        "ssti", "Server-Side Template Injection", "web",
        cwe="CWE-1336", owasp="A03:2021",
        aliases=("ssti", "server side template injection", "template injection",
                 "jinja2 ssti", "twig template injection"),
        summary="Untrusted input is compiled by the template engine rather than treated as "
                "data, so the engine's expression language executes.",
        sources=(
            ("https://cwe.mitre.org/data/definitions/1336.html", "taxonomy"),
            ("https://portswigger.net/web-security/server-side-template-injection", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/1336.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "path_traversal", "Path Traversal / File Inclusion", "web",
        cwe="CWE-22", owasp="A01:2021",
        aliases=("path traversal", "directory traversal", "lfi", "rfi", "file inclusion"),
        summary="A filename or path built from user input escapes its intended directory.",
        sources=(
            ("https://owasp.org/www-community/attacks/Path_Traversal", "cheatsheet"),
            ("https://portswigger.net/web-security/file-path-traversal", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/22.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "deser", "Insecure Deserialization", "web",
        cwe="CWE-502", owasp="A08:2021",
        aliases=("insecure deserialization", "deserialization", "pickle deserialization",
                 "java deserialization gadget", "php object injection"),
        summary="Data is reconstructed into a live object graph whose type system then "
                "invokes attacker-reachable behaviour.",
        sources=(
            ("https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html", "cheatsheet"),
            ("https://portswigger.net/web-security/deserialization", "cheatsheet"),
            ("https://cwe.mitre.org/data/definitions/502.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "eol_software", "End-of-Life / Unsupported Software", "web",
        cwe="CWE-1104", owasp="A06:2021",
        aliases=("end of life", "eol software", "unsupported software",
                 "outdated component", "unpatched software", "end of support",
                 "unmaintained third party component"),
        summary="A component no longer receives security fixes, so a known defect "
                "stays exploitable long after a patched version exists.",
        sources=(
            ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "advisory"),
            ("https://cwe.mitre.org/data/definitions/1104.html", "taxonomy"),
        ),
    ),
    ClassSeed(
        "otp", "One-Time Password / MFA Bypass", "identity",
        cwe="CWE-287", owasp="A07:2021",
        aliases=("one-time password", "otp", "totp", "hotp", "mfa bypass",
                 "otp brute force", "one time password", "authentication code reuse"),
        summary="A one-time code is predictable, replayable, or not bound to the "
                "authentication attempt, so the second factor does not prove presence.",
        sources=(
            ("https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html", "cheatsheet"),
            ("https://pages.nist.gov/800-63-3/sp800-63b.html", "standard"),
        ),
    ),
    ClassSeed(
        "rate_limit", "Rate Limiting / Resource Exhaustion", "api",
        cwe="CWE-770", owasp="API4:2023",
        aliases=("rate limit", "rate limiting", "brute force protection",
                 "request throttling", "unrestricted resource consumption",
                 "429 bypass", "quota abuse"),
        summary="A sensitive operation accepts unbounded requests, so an attacker "
                "can brute-force, enumerate, or exhaust a resource that should be throttled.",
        sources=(
            ("https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html", "cheatsheet"),
            ("https://developers.cloudflare.com/waf/rate-limiting-rules/", "docs"),
        ),
    ),
)

CLASSES = {c.id: c for c in _SEED}
SEEDS: dict[str, list[str]] = {
    c.id: [u for u, _ in c.sources] for c in _SEED
}
SEED_TYPES: dict[str, tuple[str, ...]] = {
    c.id: tuple(t for _, t in c.sources) for c in _SEED
}
