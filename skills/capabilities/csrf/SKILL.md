---
name: csrf
description: "Canonical CSRF capability: hunting, validating, and simulating Cross-Site Request Forgery across form, JSON, GraphQL, WebSocket, OAuth/SAML, and BFF surfaces. Consolidates 2 sub-skills: hunt-csrf, performing-csrf-attack-simulation. Use when hunting or validating CSRF-related vulnerabilities."
sources: consolidated
---

# CSRF — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Cross-Site Request Forgery (CSRF) security testing. It consolidates 2 previously separate sub-skills (`hunt-csrf`, `performing-csrf-attack-simulation`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover state-changing endpoints reachable cross-origin from an authenticated victim browser.
- Validate anti-CSRF defenses (tokens, SameSite, Origin/Referer, custom headers, double-submit) with proof.
- Exploit missing or bypassable CSRF only with concrete account-level or financial impact.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Traditional form POST/PUT/DELETE/PATCH CSRF.
- JSON API CSRF via `text/plain`, `application/x-www-form-urlencoded`, and `multipart/form-data` simple requests.
- GET-based state changes, GraphQL mutations via GET, OAuth/SAML `state`/`RelayState` binding, WebSocket CSRF (CSWSH).
- SameSite bypasses (Lax top-level navigation, sibling subdomain, subdomain takeover).
- Framework misconfiguration (disabled middleware, Duende BFF antiforgery), path-traversal token bypass, mobile deeplink CSRF.

Out of scope (hand off):
- Pure reflection/XSS without state change -> `hunt-xss` (chain once script execution is possible).
- Authentication bypass without cross-site delivery -> `hunt-auth-bypass`.
- OAuth provider-side flaws unrelated to CSRF state -> `hunt-oauth`.
- Infrastructure/subdomain takeover used only as a primitive -> cloud/recon capabilities, but document the chain.

## 3. Invocation and routing

Use this capability when:
- A target has authenticated, state-changing browser actions (email/password change, transfers, settings, linking, admin actions).
- You need to test anti-CSRF tokens, SameSite cookie attributes, Origin/Referer validation, or custom headers.
- A finding involves cross-origin request forgery, login CSRF, account-linking CSRF, or CSRF-over-WebSocket.

Routing notes:
- Hunting/discovery routes to `references/hunt-csrf.md` (attack surface, bypasses, disclosed cases, Duende BFF).
- Structured simulation/validation routes to `references/performing-csrf-attack-simulation.md` (Burp PoC, token tests, SameSite checks).
- OAuth/SAML state issues route to `hunt-oauth` and `hunt-auth-bypass` references for chaining.

## 4. Inputs and outputs

Inputs:
- Target base URLs, authenticated test accounts (victim + attacker), session cookies.
- Captured state-changing requests (Burp/Proxy history), forms, API specs, JS bundles.
- Browser/Origin context (subdomains, SameSite attributes, cookie domains).

Outputs:
- Confirmed or refuted CSRF findings with raw request/response proof.
- Anti-CSRF defense matrix (token, SameSite, Origin/Referer, custom header, double-submit).
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include target hosts, test accounts, and impact boundaries.
- Use only test accounts; never trigger state changes on real users' data.
- Avoid destructive actions (deletion, irreversible transfers) unless explicitly authorized in a sandbox.
- Respect rate limits and stop at account/tenant boundaries.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Spider authenticated sessions and collect all POST/PUT/DELETE/PATCH requests; note forms and AJAX calls.
2. Inspect `Set-Cookie` for `SameSite` (Strict/Lax/None) and `Domain` attributes on session cookies.
3. Harvest CSRF token field names and values (`csrf_token`, `authenticity_token`, `_token`, `csrfmiddlewaretoken`, `__RequestVerificationToken`, `meta[name=csrf-token]`).
4. Identify JSON APIs and check Content-Type enforcement (does it also accept `text/plain` or form-encoded?).
5. Enumerate OAuth/SAML flows for `state`/`RelayState` validation; social-account linking endpoints.
6. Enumerate WebSocket hubs (`/hubs/*`, `/signalr/*`, `/ws/*`) and check antiforgery carve-outs.
7. Subdomain inventory + DNS-takeover scan when cookies use `Domain=.example.com`.
8. Fingerprint frameworks (Rails, Django, ASP.NET, Express, Duende BFF, Grafana) to select known bypasses.

See `references/hunt-csrf.md` (attack surface signals, Duende BFF hunting checklist).

## 7. Detection methodology

Core detection flow:
1. Map state-changing endpoints and classify by impact (email/password change, transfer, admin, linking).
2. Test token omission: POST without the CSRF token field; success (2xx, no "invalid token") = CSRF candidate.
3. Test token substitution/empty/invalid values; acceptance = broken validation.
4. Test JSON endpoints for form-POST CSRF (content-type confusion, `text/plain` JSON).
5. Test Origin/Referer handling (omit, spoof, null origin, subdomain bypass).
6. Test SameSite behavior (Lax top-level GET, sibling subdomain, cookie domain wildcarding).
7. Test OAuth/SAML `state`/`RelayState` binding and account-linking callbacks.
8. Test WebSocket endpoints for CSWSH (open without antiforgery header).
9. Validate each candidate with a clean reproduction (PoC page or raw HTTP).

References by phase:
- Hunting/bypasses: `references/hunt-csrf.md`.
- Simulation/PoC: `references/performing-csrf-attack-simulation.md`.

## 8. Technique selection

Select techniques by observed defenses:
- No token present -> basic form POST PoC; confirm cookies sent and action executes.
- Token present but weak -> omission, empty, invalid, cross-session substitution, staticness tests.
- JSON API -> `text/plain` enctype PoC producing valid JSON; content-type confusion.
- SameSite=Lax -> top-level GET navigation, redirect-chain POST->GET conversion.
- SameSite via sibling subdomain -> host PoC on `*.parent` and use fetch with credentials.
- Origin/Referer check -> null origin (sandboxed iframe), subdomain bypass, Referer stripping, weak string matching.
- Double-submit cookie -> cookie injection via subdomain takeover; set matching cookie+field.
- Custom header (e.g., `X-CSRF: 1`) -> test if value is constant/user-unbound; replay across roles; WebSocket carve-out.
- OAuth/SAML -> RelayState/state omission, predictable/reusable state, callback CSRF.
- Mobile -> custom-scheme deeplink state-changing actions.

See `references/hunt-csrf.md` (Duende BFF attack classes) and `references/performing-csrf-attack-simulation.md` (Burp PoC).

## 9. Execution steps

1. Establish baseline request for each state-changing endpoint (method, headers, body, auth, token).
2. Replay with one controlled change at a time; record status, body, timing, headers.
3. For token tests, compare responses across omission/empty/invalid/substitution.
4. For content-type tests, send `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`, and JSON variants.
5. For header checks, send requests with no/evil/spoofed `Origin` and `Referer`.
6. For SameSite, test cross-origin browser delivery (real page) only when spoofed headers cannot satisfy enforcement.
7. For authorization-impact, use two accounts/roles and confirm the action executes on the victim.
8. Build PoC HTML and host locally; have victim visit while authenticated; confirm the state change.
9. Confirm exploitability with a clean reproduction (curl or raw HTTP where applicable).
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, CSRF PoC generator, Comparer), mitmproxy.
- HTTP clients: curl, Python requests/httpx (raw header spoofing for header-check CSRF).
- Browsers: two profiles (victim/attacker), DevTools for cookies/SameSite.
- Local server: Python `http.server` for hosting PoC pages.
- Scanners: OWASP ZAP, XSRFProbe (in-scope only).
- Evidence: saved requests/responses, PoC HTML, screenshots, canary values.

See `references/performing-csrf-attack-simulation.md` (tools) and `references/hunt-csrf.md`.

## 11. Payloads and test cases

Basic form POST PoC:
```html
<html><body onload="document.forms[0].submit()">
  <form method="POST" action="https://target.com/api/account/change-email">
    <input type="hidden" name="email" value="attacker@evil.com" />
  </form>
</body></html>
```

JSON CSRF via `text/plain`:
```html
<form method="POST" action="https://target.com/api/settings" enctype="text/plain">
  <input type="hidden" name='{"email":"attacker@evil.com","x":"' value='"}' />
</form>
```

curl token omission:
```bash
curl -s -X POST https://target.com/settings/email -H "Cookie: session=YOUR_SESSION" -d "email=attacker@evil.com" -w "%{http_code}"
```

curl token reuse across sessions:
```bash
TOKEN_A=$(curl -s https://target.com/settings -H "Cookie: session=SESSION_A" | grep -oP 'authenticity_token[^"]*value="\K[^"]+')
curl -s -X POST https://target.com/settings/update -H "Cookie: session=SESSION_B" -d "authenticity_token=$TOKEN_A&email=test@test.com" -v
```

Null Origin (sandboxed iframe):
```html
<iframe sandbox="allow-scripts allow-forms" srcdoc="<form method=POST action=https://target.com/x><input name=a value=b></form><script>document.forms[0].submit()</script>"></iframe>
```

GET-based CSRF (SameSite=Lax bypass):
```html
<img src="https://target.com/settings?disable_2fa=true" style="display:none" />
```

GraphQL mutation via GET:
```html
<img src="https://target.com/api/graphql?query=mutation{createSnippet(input:{title:%22x%22}){snippet{id}}}" />
```

Duende BFF replay (constant X-CSRF: 1, unbound to user):
```bash
curl -s -X POST https://target.com/bff/admin/users/delete?id=42 -H "X-CSRF: 1" -b "session=LOWPRIV_SESSION" -w "%{http_code}"
```

WebSocket CSRF (CSWSH):
```javascript
const ws = new WebSocket("wss://target.com/hubs/admin"); // browser sends session cookie, no X-CSRF
```

Mobile deeplink CSRF:
```
scheme://action?follow=attacker_id  (delivered via link or QR code)
```

Additional payload variants (form-encoded, multipart, Burp PoC, SameSite=Lax bypass, multi-step iframe) live in `references/performing-csrf-attack-simulation.md`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP, form body, or GraphQL operation).
- Authentication context (victim/attacker accounts, roles, sessions).
- Anti-CSRF defenses present and whether enforced.
- Canary values or modified fields and server-side effect.
- PoC HTML or script and hosting steps.
- Impact assessment (ATO, financial loss, data change) and affected scope.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session where possible.
- Validate with two accounts/roles (victim executes attacker's forged request).
- Confirm persistence/state change in the application.
- For header-check bypasses, confirm with a raw HTTP client first, then (if needed) a real cross-origin page.
- For SameSite bypasses, confirm with a real browser delivery and document cookie attributes.
- Mark as refuted if the action does not execute or no concrete impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- The endpoint is not state-changing or has no victim impact.
- Login/logout CSRF with no account-level consequence.
- A token is present and enforced (omission/invalid returns 403).
- `SameSite=Strict` blocks cross-site delivery and no bypass exists.
- Origin/Referer validation is genuine same-origin enforcement (not naive string match).
- JSON endpoint rejects all simple content types (`text/plain`, form-encoded, multipart).
- Custom header value is user-bound and verified server-side.
- WebSocket endpoint requires and validates an antiforgery token.
- Response differences are due to caching, localization, or benign metadata.

## 15. Impact

Impact guidance:
- Critical: account takeover (email/password change, OAuth linking), financial transfer, admin action.
- High: settings modification enabling ATO (2FA disable, notification change), persistent account linking.
- Medium: state change with limited business impact, activity tracking under victim identity.
- Low: non-sensitive state change, logout CSRF, missing hardening without exploit path.

Always tie impact to concrete victim loss; "a request executed" is not impact.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type (CSRF), action, impact.
- Scope/authorization: test accounts, test window.
- Steps to reproduce: numbered, minimal.
- Proof of concept: raw request/response and/or PoC HTML.
- Anti-CSRF defenses tested: token/SameSite/Origin/Referer/custom header matrix.
- Impact: business and data scope.
- Remediation: synchronizer token pattern, SameSite=Strict, Origin/Referer validation, re-auth for sensitive ops, custom header enforcement, framework middleware enabled.
- References: OWASP CSRF, relevant CVEs/advisories.

## 17. Failure modes

- Surface not fully discovered -> expand recon (JS bundles, mobile, versions, content types).
- No test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, or parser differentials.
- Rate limiting stops testing -> coordinate throttling or test windows.
- SameSite blocks delivery -> test Lax top-level GET, sibling subdomain, cookie domain wildcarding.
- Inconclusive token result -> repeat with fresh sessions and diff; mark not confirmed if ambiguous.
- WebSocket requires browser -> use a real browser/Playwright to open the socket and send frames.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-csrf.md` | `hunt-csrf` | Hunting/bypasses, attack surface, disclosed cases, Duende BFF |
| `references/performing-csrf-attack-simulation.md` | `performing-csrf-attack-simulation` | Simulation, Burp PoC, token/SameSite testing |

Original sub-skills remain intact under `hunt-csrf/` and `performing-csrf-attack-simulation/` (including `api-reference.md` and `scripts/agent.py` under the latter).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_csrf_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger CSRF, OWASP WebGoat, DVWA.
- Mastery criteria: independently discover, validate, and report a CSRF finding with full reproduction, defense matrix, and impact.


## Knowledge sources

- WKS bug classes: csrf
- Domain knowledge: csrf
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
