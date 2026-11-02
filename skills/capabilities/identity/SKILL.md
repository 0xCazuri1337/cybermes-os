---
name: identity
description: "Canonical identity capability: hunting, validating, and exploiting authentication, authorization, account-takeover, and session-management weaknesses. Consolidates 18 sub-skills: accounttakeover-hunter, hunt-ato, hunt-brute-force, hunt-forgot-password, hunt-mfa-bypass, hunting-credential-stuffing-attacks, auth-hunter, bypassing-authentication-with-forced-browsing, hunt-auth-bypass, authorization-hunter, detecting-broken-object-property-level-authorization, exploiting-broken-function-level-authorization, exploiting-idor-vulnerabilities, hunt-idor, idor-hunter, testing-api-for-broken-object-level-authorization, testing-for-broken-access-control, hunt-session. Use when hunting or validating identity-related vulnerabilities."
sources: consolidated
---

# IDENTITY — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for identity security testing. It consolidates 18 previously separate sub-skills (`accounttakeover-hunter`, `hunt-ato`, `hunt-brute-force`, `hunt-forgot-password`, `hunt-mfa-bypass`, `hunting-credential-stuffing-attacks`, `auth-hunter`, `bypassing-authentication-with-forced-browsing`, `hunt-auth-bypass`, `authorization-hunter`, `detecting-broken-object-property-level-authorization`, `exploiting-broken-function-level-authorization`, `exploiting-idor-vulnerabilities`, `hunt-idor`, `idor-hunter`, `testing-api-for-broken-object-level-authorization`, `testing-for-broken-access-control`, `hunt-session`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover identity flows (login, signup, recovery, MFA, session, authorization) and map trust boundaries.
- Validate authentication bypasses, authorization gaps (IDOR/BOLA/BFLA/BOPLA), account-takeover primitives, and session lifecycle flaws with proof.
- Exploit reset poisoning, MFA bypass, forced browsing, IDOR, privilege escalation, and session fixation only with concrete identity/privilege impact.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Authentication: login/logout, MFA/2FA, password reset/recovery, forced browsing, SAML/OAuth/OIDC trust chains, JWT-as-session claim handling.
- Authorization: object-level (IDOR/BOLA), function-level (BFLA), property-level (BOPLA excessive exposure & mass assignment), vertical/horizontal privilege escalation, multi-tenant leakage.
- Account takeover: password reset poisoning, token prediction/reuse, email change without re-auth, OAuth account-link CSRF, session fixation, social recovery, credential stuffing, brute force, enumeration.
- Session management: fixation, insufficient invalidation on logout/password/email change, predictable session IDs, refresh-token rotation/reuse, cookie attributes, device-bound sessions.

Out of scope (hand off):
- Pure JWT cryptographic forging (alg:none, key confusion, kid/jku) -> `hunt-jwt-crypto` / canonical `jwt`.
- OAuth provider-side redirect/state flaws unrelated to account takeover -> `hunt-oauth`.
- SAML XML signature wrapping/XXE -> `hunt-saml` / canonical `xxe`.
- General cache/session side channels -> `hunt-cache-poison`.
- Web cache deception of identity endpoints -> `hunt-cache-deception`.

## 3. Invocation and routing

Use this capability when:
- A target authenticates users with passwords, MFA, OAuth/OIDC/SAML, or session cookies/tokens.
- You need to test password reset/recovery, MFA enforcement, session lifecycle, or access control.
- A finding involves account takeover, privilege escalation, cross-tenant data access, or session hijacking.

Routing notes:
- ATO chains and password-reset poisoning -> `references/hunt-ato.md` and `references/accounttakeover-hunter.md`.
- Rate limiting / brute force / enumeration -> `references/hunt-brute-force.md`.
- Forgot-password primitives (enumeration, token exposure/reuse, no rate limit) -> `references/hunt-forgot-password.md`.
- MFA/2FA bypass -> `references/hunt-mfa-bypass.md`.
- Credential stuffing detection -> `references/hunting-credential-stuffing-attacks.md`.
- Authentication bypasses (EAR, SAML no-sig, session swap) -> `references/auth-hunter.md`.
- Forced browsing / unprotected pages -> `references/bypassing-authentication-with-forced-browsing.md`.
- Cross-protocol auth bypass (SAML XSW, JWT-in-SSO, partner portals) -> `references/hunt-auth-bypass.md`.
- Broken access control overview -> `references/authorization-hunter.md`.
- BOPLA / excessive data exposure / mass assignment -> `references/detecting-broken-object-property-level-authorization.md`.
- BFLA / admin endpoint reachability -> `references/exploiting-broken-function-level-authorization.md`.
- IDOR exploitation (UUID/GID/numeric) -> `references/exploiting-idor-vulnerabilities.md` and `references/idor-hunter.md`.
- Hunting IDOR at scale -> `references/hunt-idor.md`.
- API BOLA testing -> `references/testing-api-for-broken-object-level-authorization.md`.
- Broad broken-access-control audit -> `references/testing-for-broken-access-control.md`.
- Session management flaws -> `references/hunt-session.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, authenticated test accounts (at least two roles/tenants), session cookies/tokens.
- Captured requests (login, reset, MFA, profile, admin) and API specs/OpenAPI.
- Tech stack, framework, IdP (SAML/OAuth/OIDC) signals, JS bundles.
- Rate-limit/CAPTCHA observations, WAF behavior.

Outputs:
- Confirmed or refuted identity findings with raw request/response proof.
- ATO chains demonstrating takeover of a second test account.
- Authorization matrix (role x endpoint x object) with pass/fail.
- Defense matrix (MFA enforcement, session invalidation, rate limits, cookie attrs, RBAC).
- Reproduction steps, impact assessment, remediation guidance.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include hosts, accounts, and impact boundaries.
- Use only test accounts; never take over real users' accounts.
- Avoid destructive actions (account deletion, password changes on shared accounts) unless explicitly authorized in a sandbox.
- Coordinate rate limits and MFA/OTP issuance throttling with the owner.
- Treat all captured tokens, reset links, and OTPs as secrets; do not share externally.

## 6. Reconnaissance

Recon steps:
1. Map identity surface: `/login`, `/signup`, `/forgot-password`, `/reset-password`, `/mfa`, `/2fa`, `/oauth/*`, `/saml/*`, `/sso/*`, `/session`, `/logout`, `/account/*`, `/admin/*`, `/api/*`.
2. Capture login/reset/MFA requests; record parameters (`email`, `user`, `token`, `code`, `state`, `redirect_uri`, `client_id`, `otp`, `session`).
3. Inspect JS bundles for `isAdmin`, `role`, `tenant_id`, `permissions`, `mfa`, `recovery`, `cognito`, `auth0`, `firebase`, `signup_workflow`.
4. Enumerate hidden/legacy endpoints (`/xmlrpc.php`, `/api/v1`, `/api/v2`, `/_admin`, `/internal-api`, `/debug/*`).
5. Identify IdP/OAuth/OIDC/SAML flows and JWKS/discovery endpoints; note SSO enforcement and legacy password flows.
6. Record session cookie names/attributes (`Secure`, `HttpOnly`, `SameSite`, `__Host-`, `__Secure-`) and token storage (header/cookie/localStorage).
7. Establish two test accounts in different roles/tenants for differential testing.
8. Check rate-limit/CAPTCHA behavior on login, OTP, and reset endpoints.

## 7. Detection methodology

Core detection flow:
1. Authentication: test forced browsing to protected/admin pages without session; test EAR (Execution After Redirect); test session swap/identity substitution in OTP/logout/re-auth.
2. MFA: attempt skip to post-MFA URL; OTP replay; brute small key spaces; recovery-code exposure; backup-factor downgrade; race on OTP validation.
3. Password reset/recovery: username enumeration (response/status/length/timing); token in response; token replay; no rate limit; host-header poisoning (OOB); Referer leak; predictable tokens.
4. Brute force/enumeration: missing rate limits, weak password policy, credential stuffing signals, IP-bypass via `X-Forwarded-For`.
5. Authorization: enumerate object IDs and substitute across two sessions; test function-level admin endpoints with low-priv creds; test mass assignment and excessive data exposure; test property-level authorization.
6. Session: fixation (token unchanged on login); survival after logout/password/email change; predictable IDs; refresh-token reuse; cookie attributes.
7. ATO chains: combine primitives (cookie theft + no step-up, lax redirect_uri, dangling CNAME) and demonstrate takeover of account B.
8. Validate each candidate against real protected data/actions; only cross-identity access or privilege gain counts as proof.

## 8. Technique selection

Select techniques by observed surface and defenses:
- No MFA server-side enforcement -> forced browsing / direct navigation first.
- Reset token in response or predictable -> immediate ATO; confirm with account B.
- Host-header poisoning -> OOB Collaborator confirmation before claiming.
- IDOR/BOLA -> differential two-account testing; try numeric/UUID/GID/slug variants.
- BFLA -> direct admin endpoint access with low-priv session; try method switching and path variants.
- BOPLA -> compare response fields vs. UI; inject extra properties in PUT/PATCH.
- Session fixation -> compare pre/post login token.
- No rate limit -> enumeration/brute; document key space and feasibility.
- SSO present -> test legacy password reset bypass and cross-IdP assertion reuse.

See `references/` for per-technique depth.

## 9. Execution steps

1. Complete reconnaissance (section 6) and establish two accounts.
2. Run authentication bypass checks (forced browsing, EAR, session swap).
3. Test MFA enforcement and OTP handling.
4. Test password reset/recovery full flow (enumeration -> token -> use -> replay).
5. Test rate limiting and brute force feasibility.
6. Test authorization matrix (IDOR/BOLA, BFLA, BOPLA) across two sessions.
7. Test session lifecycle (fixation, invalidation, cookies, refresh tokens).
8. Chain primitives toward ATO and demonstrate takeover of account B.
9. Document blocked vectors and move on; do not loop on one failed primitive.
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Burp Suite (Proxy, Repeater, Intruder, Authorize/Auth Analyzer extensions): differential testing, fuzzing, session handling.
- ffuf / wfuzz: endpoint/parameter enumeration, brute force.
- jwt_tool / PyJWT: token decode/forge where JWT is used as session (hand crypto forging to `jwt`).
- Burp Collaborator / interactsh: OOB confirmation for host-header poisoning, blind leaks.
- curl / Python requests / httpx: raw request delivery and response capture.
- sqlmap: only where IDOR/auth flows touch DB (kid/ID injection).
- Browser DevTools: cookie attributes, client-side MFA enforcement, network tab.
- Splunk/raw logs: credential-stuffing detection rules.

## 11. Payloads and test cases

Password reset host-header poisoning:
```http
POST /forgot-password HTTP/1.1
Host: attacker.com
email=victimB@company.com
```
Also test `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, dual-Host smuggling.

IDOR substitution:
```
GET /api/users/123/profile  ->  GET /api/users/124/profile
POST /api/orders  {"order_id": 1001}  ->  {"order_id": 1002}
```
GID manipulation:
```
gid://app/Resource/244  ->  gid://app/Resource/245 (base64 re-encoded)
```

MFA skip:
```
Login -> pre-MFA session -> GET /dashboard (expect redirect; if 200 with data = bypass)
```

OTP replay:
```
Submit valid OTP twice across two login attempts; second accepted = replay
```

Mass assignment:
```json
PUT /api/users/me {"role":"admin","is_admin":true,"email":"attacker@x.com"}
```

Session fixation:
```
Pre-login session cookie == post-login session cookie -> fixation
```

Forced browsing:
```bash
curl -s -o /dev/null -w "%{http_code}" https://target.com/admin/settings
```

Enumeration:
```
POST /forgot-password {"email":"victim@target.com"} vs {"email":"nope@fake.com"}
Compare status/body/length/timing
```

Additional variants and automation live in `references/`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or tool output) showing the bypass/access/leak.
- Authentication context (attacker/victim accounts, roles, sessions, tenants).
- For ATO: proof of takeover of account B (session/token for B obtained by A).
- For IDOR/BOLA: object IDs used, both sessions, data accessed.
- For authorization: role/endpoint matrix and which check is missing.
- Anti-defenses present and whether enforced (MFA, rate limit, session invalidation, cookie attrs, RBAC).
- Impact assessment (identity assumed, data scope, admin action).
- Remediation guidance.

## 13. Reproduction and validation

- Reproduce with curl or saved raw requests in a clean session where possible.
- Validate with two accounts/roles/tenants; confirm cross-identity data access or privilege gain, not just a 200.
- For ATO, demonstrate real takeover of account B from attacker A's session/IP/device.
- For host-header poisoning, confirm via OOB (Collaborator) reading the actual email/token.
- For session invalidation, replay old token after logout/password change.
- For enumeration, show measurably different responses (message/status/length/timing).
- Mark as refuted if no concrete identity/privilege impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- A 200 returns only the caller's own data (no cross-identity impact).
- Forced browsing page is public or non-sensitive.
- MFA skip returns a redirect/empty shell without user data.
- OTP replay is rejected on second use.
- Host header is reflected in email but actual link domain is server-pinned.
- IDOR object ID change returns 403/404 or same data.
- BFLA endpoint returns 401/403 for low-priv user.
- Mass assignment field is ignored or validated.
- Session token rotates on login and invalidates on logout.
- Rate limit exists (429/lockout/CAPTCHA) even if high threshold.
- Scanner output alone without exploit proof.

## 15. Impact

Impact guidance:
- Critical: authentication bypass; ATO of arbitrary/privileged account; cross-tenant data access; admin privilege escalation; session fixation to admin hijack.
- High: IDOR exposing PII/financial data; BFLA to non-admin elevated function; MFA bypass; session surviving password change; credential stuffing feasibility.
- Medium: username enumeration; excessive data exposure (PII); mass assignment with limited fields; missing rate limit on low-value endpoint.
- Low: missing hardening without exploit path (cookie attr, long expiry) or theoretical weakness.

Always tie impact to concrete identity/privilege loss; "a request returned 200" is not impact without data/action proof.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type (auth/authz/ATO/session), technique, impact.
- Scope/authorization: test accounts and window.
- Steps to reproduce: numbered, minimal.
- Evidence: raw requests/responses, object IDs, forged sessions/tokens.
- Defenses tested: MFA enforcement, rate limits, session invalidation, cookie attrs, RBAC checks.
- Impact: identity/privilege/data scope, accounts affected.
- Remediation: enforce auth middleware server-side; MFA on all sensitive actions; invalidate sessions on logout/password/email change; rotate session IDs on login; HttpOnly/Secure/SameSite cookies; per-object authorization checks; RBAC/function-level guards; allowlist mass-assignment fields; rate limit + CAPTCHA + lockout; bind reset tokens to user/IP and expire/reuse-prevent; host-header allowlisting.
- References: OWASP ASVS, OWASP Testing Guide, relevant CVEs/advisories.

## 17. Failure modes

- Surface not fully discovered -> expand recon (mobile, SSO, refresh tokens, WebSocket, legacy endpoints).
- No second account -> request credentials or scope clarification; differential testing impossible without it.
- WAF/gateway blocks -> try alternate encoding, headers, or lower request rate.
- Rate limiting -> coordinate throttling or test windows; document threshold.
- Blind/asymmetric endpoints -> focus on response diffs, timing, OOB.
- Inconclusive result -> repeat with fresh sessions, decode sent tokens, mark not confirmed if ambiguous.
- Out of scope vector -> document and hand off to appropriate capability (jwt/oauth/saml/cache).

## 18. References

All 18 sub-skill references are preserved and must resolve. Organized by subdomain:

Account takeover:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/accounttakeover-hunter.md` | `accounttakeover-hunter` | ATO playbook: reset poisoning, workflow manipulation, JWT leakage |
| `references/hunt-ato.md` | `hunt-ato` | ATO taxonomy: 9 paths + chains |
| `references/hunt-brute-force.md` | `hunt-brute-force` | Rate limiting, brute force, enumeration |
| `references/hunt-forgot-password.md` | `hunt-forgot-password` | Forgot-password primitives |
| `references/hunt-mfa-bypass.md` | `hunt-mfa-bypass` | MFA/2FA bypass patterns |
| `references/hunting-credential-stuffing-attacks.md` | `hunting-credential-stuffing-attacks` | Credential stuffing detection |

Authentication:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/auth-hunter.md` | `auth-hunter` | Authentication bypass patterns |
| `references/bypassing-authentication-with-forced-browsing.md` | `bypassing-authentication-with-forced-browsing` | Forced browsing / unprotected pages |
| `references/hunt-auth-bypass.md` | `hunt-auth-bypass` | Cross-protocol auth bypass (SAML/JWT-in-SSO) |

Authorization:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/authorization-hunter.md` | `authorization-hunter` | Broken access control overview |
| `references/detecting-broken-object-property-level-authorization.md` | `detecting-broken-object-property-level-authorization` | BOPLA / excessive exposure / mass assignment |
| `references/exploiting-broken-function-level-authorization.md` | `exploiting-broken-function-level-authorization` | BFLA / admin endpoints |
| `references/exploiting-idor-vulnerabilities.md` | `exploiting-idor-vulnerabilities` | IDOR exploitation techniques |
| `references/hunt-idor.md` | `hunt-idor` | Hunting IDOR at scale |
| `references/idor-hunter.md` | `idor-hunter` | Focused IDOR (UUID/GID/automation) |
| `references/testing-api-for-broken-object-level-authorization.md` | `testing-api-for-broken-object-level-authorization` | API BOLA testing |
| `references/testing-for-broken-access-control.md` | `testing-for-broken-access-control` | Broad access-control audit |

Session:
| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-session.md` | `hunt-session` | Session management flaws |

Original sub-skills remain intact under their directories (including each sub-skill's own api-reference.md and agent.py where present).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_identity_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger (auth/access-control), OWASP WebGoat, DVWA, HackTheBox.
- Mastery criteria: independently discover, validate, and report an identity finding with full reproduction, defense matrix, and impact.


## Knowledge sources

- WKS bug classes: authn, jwt, oauth, otp, session, rate_limit
- Domain knowledge: authn, jwt, oauth, otp, session, rate_limit
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
