---
name: oauth
description: "Canonical OAuth capability: hunting, validating, and exploiting OAuth 2.0/OIDC misconfigurations, token theft, SAML SSO, deep-link abuse, consent-grant attacks, scope minimization, and Entra ID detection. Consolidates 14 sub-skills: attacking-oauth-with-device-code-phishing, configuring-oauth2-authorization-flow, detecting-oauth-token-theft, detecting-suspicious-oauth-application-consent, exploiting-deeplink-vulnerabilities, exploiting-oauth-misconfiguration, hunt-oauth, hunt-saml, hunting-saas-sso-token-abuse, oauth-browser-probe, oauth-fragment-redirect, oauth-hunter, performing-oauth-scope-minimization-review, testing-oauth2-implementation-flaws. Use when hunting or validating OAuth-related vulnerabilities."
sources: consolidated
---

# OAUTH — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for OAuth 2.0 / OpenID Connect security testing and hardening. It consolidates 14 previously separate sub-skills (`attacking-oauth-with-device-code-phishing`, `configuring-oauth2-authorization-flow`, `detecting-oauth-token-theft`, `detecting-suspicious-oauth-application-consent`, `exploiting-deeplink-vulnerabilities`, `exploiting-oauth-misconfiguration`, `hunt-oauth`, `hunt-saml`, `hunting-saas-sso-token-abuse`, `oauth-browser-probe`, `oauth-fragment-redirect`, `oauth-hunter`, `performing-oauth-scope-minimization-review`, `testing-oauth2-implementation-flaws`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover OAuth/OIDC authorization servers, clients, redirect URIs, scopes, tokens, and SSO/SAML flows.
- Validate redirect_uri validation, state/nonce handling, PKCE enforcement, token binding, expiry, revocation, and audience checks with proof.
- Exploit redirect_uri bypass, fragment smuggling, state CSRF, PKCE bypass, token leakage, code reuse, account linking, deep-link hijacking, device-code phishing, and illicit consent grants only with concrete account-takeover or data-access impact.
- Detect token theft/replay and suspicious consent grants in Entra ID/Okta; harden flows and minimize scopes.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- OAuth 2.0 / OIDC authorization code, implicit, hybrid, client credentials, device authorization, refresh token flows.
- Redirect URI validation (exact/prefix/regex/host/path), state parameter CSRF, nonce replay, PKCE (S256/plain) enforcement, scope escalation.
- Token handling: leakage via Referer/fragments/logs, authorization code reuse, token audience/issuer validation, expiry/revocation, refresh token rotation and binding.
- Account takeover via OAuth: email-verification bypass, pre-auth account linking, token swapping, social-login misvalidation.
- Fragment-based redirects and SPA post-login routing bypasses.
- Mobile deep links (custom URL schemes, App Links, Universal Links) and WebView loading.
- SAML 1.1/2.0 SSO: XML Signature Wrapping, comment injection, signature stripping, XXE, audience/NameID manipulation, replay.
- Entra ID / Microsoft 365: device-code phishing, illicit consent grants, token replay, PRT abuse.
- Detection engineering: Entra/Okta sign-in log correlation, suspicious consent grants, stolen-session hunting.
- Scope minimization and third-party app risk review.

Out of scope (hand off):
- Pure session-management flaws without OAuth/SAML -> `hunt-session`.
- JWT cryptographic flaws rooted in token forgery -> `jwt` (this capability covers OAuth flows; JWT-specific forgery lives there).
- General API authorization (BOLA/IDOR) not rooted in token/OAuth flaws -> `hunt-idor` / `hunt-authz`.
- SSRF beyond OAuth metadata fetching -> `hunt-ssrf`.
- XSS beyond OAuth callback leakage chaining -> `hunt-xss`.

## 3. Invocation and routing

Use this capability when:
- A target uses "Sign in with Google/Facebook/GitHub", OIDC, SAML SSO, or OAuth-protected APIs.
- You need to test redirect_uri validation, state/nonce, PKCE, token handling, or scope enforcement.
- A finding involves OAuth/SAML account takeover, token theft, consent grants, or deep-link abuse.
- You are hardening OAuth flows, detecting token theft, or minimizing third-party scopes.

Routing notes:
- Device-code phishing / illicit consent (Entra) -> `references/attacking-oauth-with-device-code-phishing.md`.
- Secure flow configuration / PKCE / token lifecycle -> `references/configuring-oauth2-authorization-flow.md`.
- Token theft detection (Entra) -> `references/detecting-oauth-token-theft.md`.
- Suspicious consent-grant detection -> `references/detecting-suspicious-oauth-application-consent.md`.
- Mobile deep-link exploitation -> `references/exploiting-deeplink-vulnerabilities.md`.
- Redirect URI manipulation / code theft / scope escalation -> `references/exploiting-oauth-misconfiguration.md`.
- Hunting methodology + H1 patterns -> `references/hunt-oauth.md`.
- SAML/SSO attacks -> `references/hunt-saml.md`.
- Stolen-session / token-replay hunting (Entra/Okta) -> `references/hunting-saas-sso-token-abuse.md`.
- Browser-based redirect_uri probe when curl blocked -> `references/oauth-browser-probe.md`.
- Fragment-based redirect reflection (SPA) -> `references/oauth-fragment-redirect.md`.
- OAuth hunter playbook + triage -> `references/oauth-hunter.md`.
- Scope minimization review -> `references/performing-oauth-scope-minimization-review.md`.
- Implementation flaw testing (Burp/EsPReSSO) -> `references/testing-oauth2-implementation-flaws.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, OAuth/OIDC discovery (`/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`).
- Client IDs, redirect URIs, scopes, grant types, PKCE support signals.
- Authenticated test accounts on both provider and relying party; attacker-controlled callback server.
- Captured authorization requests/responses, tokens, codes, state/nonce values.
- Mobile APKs/IPAs for deep-link enumeration; Entra/Okta tenant logs for detection.

Outputs:
- Confirmed or refuted OAuth/SAML findings with raw request/response proof.
- Manipulated redirect_uri/state/nonce/PKCE payloads and observed server behavior.
- Forged/leaked tokens, codes, and the exact claim/parameter changed.
- Detection queries (KQL/SPL), scope-minimization reports, hardening recommendations.
- Reproduction steps, impact assessment, remediation guidance.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include hosts, tenants, accounts, and impact boundaries.
- Use only test accounts; never steal or replay real users' tokens without authorization.
- Avoid destructive admin actions unless explicitly authorized in a sandbox.
- Coordinate rate limits and token-issuance throttling with the owner.
- Treat all captured tokens, codes, and secrets as secrets; do not paste production tokens into third-party services.
- Do not perform device-code phishing or illicit consent against real users without explicit RoE.

## 6. Reconnaissance

Recon steps:
1. Discover OAuth/OIDC endpoints via `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`; record authorization, token, userinfo, JWKS, revocation, introspection endpoints.
2. Capture a full authorization request: `client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code_challenge`, `code_challenge_method`.
3. Capture the callback: where codes/tokens land, how state/nonce are validated, token storage (localStorage/cookies).
4. Enumerate registered redirect URIs (app directory, JS bundles, Wayback, mobile manifests); grep JS for `client_id`, `redirect_uri`, `postMessage`.
5. Identify grant types supported and whether implicit/hybrid flows are enabled.
6. For mobile: decompile APK/IPA; extract URL schemes, intent filters, App/Universal Links, WebView loaders.
7. For SSO: find `/saml/acs`, `/sso/saml`, ADFS/ Shibboleth endpoints; capture SAMLResponse.
8. For Entra/Okta: confirm log availability (SigninLogs, AADNonInteractiveUserSignInLogs, System Log) and IP enrichment.
9. Check token lifetime (`exp`), refresh token rotation, revocation behavior, and audience/issuer claims.

## 7. Detection methodology

Core detection flow:
1. Test redirect_uri validation: exact match, host suffix, path traversal, parameter pollution, case, encoding, open-redirect chaining, fragment reflection.
2. Test state parameter: remove/reuse/predictable; confirm client-side validation; CSRF on account linking.
3. Test nonce: replay across flows, validation after token exchange, referrer leakage.
4. Test PKCE: authorization without PKCE, token exchange without/wrong verifier, S256->plain downgrade, implicit flow enabled.
5. Test code/token theft: Referer leakage, fragment persistence across redirects, code reuse, token substitution across clients.
6. Test scope escalation: elevated scopes accepted at authorize and token exchange; refresh token scope escalation; client credentials elevated scope.
7. Test account takeover vectors: unverified email linking, pre-auth session grant, token swapping (wrong audience client_id).
8. For mobile deep links: enumerate schemes, test injection/traversal/SSRF/WebView loading, link hijacking verification.
9. For SAML: XSW, comment injection, signature stripping, XXE, NameID/audience manipulation, replay.
10. For Entra/Okta: correlate sessions by SessionId/UniqueTokenIdentifier; impossible travel; refresh-token reuse; hosting-ASN token use; suspicious consent grants.
11. Validate each candidate against a concrete outcome (code/token stolen, session issued, data accessed); a reflected parameter alone is not a finding.

## 8. Technique selection

Select techniques by observed flow and defenses:
- Strict redirect_uri (exact match) -> test fragment-based reflection, open-redirect chaining, parser differentials (path traversal, encoding).
- No state validation -> CSRF account binding/linking; high impact if no user interaction beyond clicking.
- No PKCE on public client -> authorization code interception (mobile/network).
- Implicit flow enabled -> token in fragment leakage via Referer.
- Code reusable -> replay stolen code even after legitimate exchange.
- Weak audience validation -> token substitution across clients/services.
- SAML present -> XSW, signature stripping, comment injection; check parser consistency.
- Mobile deep links present -> scheme hijacking, WebView injection, parameter traversal.
- Entra tenant in scope -> device-code phishing and illicit consent grants; token replay hunting.
- Third-party OAuth grants -> scope minimization review and consent-grant detection.

See `references/hunt-oauth.md` (H1 patterns, chaining) and `references/oauth-hunter.md` (triage/severity).

## 9. Execution steps

1. Run reconnaissance (section 6) and record the full flow, endpoints, parameters, and defenses.
2. Forge/test candidate payloads per technique (redirect_uri bypasses, state/nonce removal, PKCE downgrade, scope elevation, code reuse, fragment reflection).
3. Deliver payloads via browser or crafted links; capture redirects, codes, tokens, and responses.
4. For mobile: invoke deep links via ADB/Frida; capture triggered API calls and storage.
5. For SAML: manipulate assertions; submit to ACS; observe session/role outcome.
6. For Entra/Okta detection: run KQL/SPL hunts; enumerate consent grants; score app risk.
7. Decode and confirm any token/code actually captured carries the intended claims/scopes.
8. Escalate to a concrete account takeover or data access when authorized; otherwise document the weakness and the gap.
9. Document blocked vectors and move on; do not loop on a single failed bypass.
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Burp Suite Professional + EsPReSSO/OAuth Hacker extensions: intercept redirects, manipulate parameters, automate bypass fuzzing.
- Browser DevTools / `browser_exec`: observe redirect chains, fragment handling, storage.
- curl / Python requests / httpx / oauthlib: raw flow testing, token exchange, scope probes.
- jwt.io / PyJWT: decode OAuth access/ID tokens.
- OWASP ZAP: passive OAuth misconfiguration scanning.
- apktool / JADX / Drozer / ADB / Frida / Objection: mobile deep-link and manifest analysis.
- SAML Raider (Burp), samlmagic, xmllint: SAML manipulation and XSW testing.
- TokenTactics, ROADtools (roadrecon/roadtx), AADInternals: Entra device-code phishing and enumeration.
- Microsoft Graph API / MSAL: consent-grant enumeration and scope review.
- Sentinel/Log Analytics (KQL), Splunk (SPL): token-replay and consent detection hunts.
- ffuf: redirect_uri fuzzing.

## 11. Payloads and test cases

Redirect URI bypass candidates:
```
https://evil.com
https://app.example.com.evil.com/callback
https://***@evil.com/callback
https://app.example.com/callback/../../../evil.com
https://app.example.com/callback?next=https://evil.com
https://app.example.com/callback%23evil.com
https://APP.EXAMPLE.COM/callback
http://app.example.com/callback
```

State/nonce tests:
```
# Remove state entirely
# Reuse fixed state across sessions
# Predictable/sequential state
# Replay captured nonce in a second flow
```

PKCE tests:
```
# Authorization without code_challenge
# Token exchange without code_verifier
# Token exchange with wrong code_verifier
# code_challenge_method=plain with verifier as challenge
```

Scope escalation:
```
openid profile email admin
openid profile email write:users
*
```

Fragment reflection probe:
```
GET /login?redirect=https://evil.com
# Inspect Location header for ...#/login?redirect=https%3A%2F%2Fevil.com
```

Authorization code replay:
```
POST /oauth/token grant_type=authorization_code&code=CAPTURED_CODE (repeat 2-3x)
```

SAML signature stripping:
```
1. base64 -d SAMLResponse -> saml.xml
2. Delete <Signature> element; change NameID to admin@target.com
3. base64 -w0 saml.xml -> resubmit
```

Deep link injection (Android):
```
adb shell am start -a android.intent.action.VIEW -d "myapp://profile?redirect=https://evil.com" com.target.app
adb shell am start -a android.intent.action.VIEW -d "myapp://open?url=javascript:alert(document.cookie)" com.target.app
```

Device-code phishing (Entra):
```
POST https://login.microsoftonline.com/organizations/oauth2/v2.0/devicecode
client_id=d3590ed6-52b3-4102-aeff-aad2292ab01c
scope=https://graph.microsoft.com/.default offline_access
```

Additional variants, full Python/Burp code, and chaining playbooks live in `references/`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or tool output) showing the bypass/theft/detection.
- The manipulated parameter/payload and the observed server behavior.
- Authentication context (victim/attacker accounts, roles, sessions, tenants).
- Captured code/token (redacted appropriately) and where it was obtained.
- Defenses present and whether enforced (redirect_uri validation, state, nonce, PKCE, audience, expiry, revocation, consent policy).
- Impact assessment (account taken over, data accessed, persistence, scope of consent).
- For detections: query, log evidence, affected users/apps, and remediation.
- For scope review: inventory, risk classification, findings, and reduction plan.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session where possible.
- Confirm the server's response actually grants a code/token/session, not just a 200.
- Validate with two accounts/roles/tenants; confirm cross-identity data access or admin action.
- For redirect_uri bypass, show the code/token delivered to an attacker-controlled endpoint or a confirmed client-side navigation.
- For fragment reflection, complete the flow in a browser and confirm post-auth navigation.
- For SAML, show the resulting session/role, not just XML acceptance.
- For device-code phishing, show MFA bypass and token usability across a resource.
- For detection hunts, validate queries against known-bad and known-good data.
- Mark as refuted if no concrete account/data impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- A reflected `redirect_uri` is not actually used to deliver a code/token (server validates at token step).
- State/nonce present and validated server-side; removal is rejected.
- PKCE enforced and downgrade rejected; code unusable without verifier.
- Implicit flow disabled; no token in fragment.
- Authorization code is single-use and short-lived.
- Audience/issuer validated; cross-client token rejected.
- A 200 response returns only the caller's own data (no cross-identity impact).
- Deep link requires auth state and does not bypass authorization.
- SAML signature present and validated; manipulation rejected.
- Detection alert has no corroborating log evidence or maps to benign behavior.
- Scope review flags only approved, in-use, least-privilege grants.

## 15. Impact

Impact guidance:
- Critical: full account takeover with no/minimal user interaction; admin token theft; cross-tenant data access; illicit consent granting broad mailbox/file access; SAML XSW/signature stripping to admin.
- High: ATO with user click; device-code phishing MFA bypass; deep-link code theft; refresh-token theft enabling persistent access; suspicious consent grants with high-risk scopes.
- Medium: token leakage requiring additional chaining; scope escalation with limited reach; fragment-based phishing; stale/over-broad consent grants.
- Low: missing hardening without exploit path (long expiry, verbose errors) or theoretical weakness.

Always tie impact to concrete identity/privilege/data loss; "a parameter was reflected" is not impact without delivery proof.

## 16. Reporting

Report template:
- Summary: endpoint/flow, vulnerability type (OAuth/SAML/deep-link/consent), technique, impact.
- Scope/authorization: test accounts and window.
- Steps to reproduce: numbered, minimal, with payloads.
- Evidence: raw requests/responses, captured codes/tokens (redacted), screenshots of redirect chains.
- Defenses tested: redirect_uri validation, state, nonce, PKCE, audience, expiry/revocation, consent policy.
- Impact: identity/privilege/data scope, persistence.
- Remediation: exact redirect_uri allowlist (no wildcards/prefix), enforce PKCE S256 for all clients, validate state+nonce server-side, disable implicit flow, single-use short-lived codes, audience/issuer validation, token binding (DPoP/mTLS), CA/device-code restrictions, consent governance, scope minimization, SAML signature/audience enforcement and safe XML parsing.
- References: RFC 6749/7636/8628/9700, OWASP, relevant CVEs.

## 17. Failure modes

- Surface not fully discovered -> expand recon (mobile manifests, SAML endpoints, well-known docs, JS bundles, app directories).
- No test account -> request credentials or scope clarification; do not test without authorization.
- WAF/gateway blocks crafted requests -> use browser probe (`references/oauth-browser-probe.md`), encoding, or chunking.
- Captcha gates login -> document as PoC blocker; do not fabricate final hop.
- Rate limiting on token issuance -> coordinate throttling or test windows.
- Inconclusive bypass result -> repeat with fresh sessions, decode sent token, mark not confirmed if ambiguous.
- Detection data unavailable -> scope hunt to available logs; document gaps.

## 18. References

All 14 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/attacking-oauth-with-device-code-phishing.md` | `attacking-oauth-with-device-code-phishing` | Device-code phishing, illicit consent, Entra token theft |
| `references/configuring-oauth2-authorization-flow.md` | `configuring-oauth2-authorization-flow` | Secure flow config, PKCE, token lifecycle, OAuth 2.1 |
| `references/detecting-oauth-token-theft.md` | `detecting-oauth-token-theft` | Token theft detection in Entra |
| `references/detecting-suspicious-oauth-application-consent.md` | `detecting-suspicious-oauth-application-consent` | Suspicious consent grants, Graph API audit |
| `references/exploiting-deeplink-vulnerabilities.md` | `exploiting-deeplink-vulnerabilities` | Mobile deep-link / WebView exploitation |
| `references/exploiting-oauth-misconfiguration.md` | `exploiting-oauth-misconfiguration` | Redirect URI manipulation, code theft, scope escalation |
| `references/hunt-oauth.md` | `hunt-oauth` | Hunting methodology, H1 patterns, chaining |
| `references/hunt-saml.md` | `hunt-saml` | SAML/SSO attacks |
| `references/hunting-saas-sso-token-abuse.md` | `hunting-saas-sso-token-abuse` | Stolen-session/token-replay hunting (Entra/Okta) |
| `references/oauth-browser-probe.md` | `oauth-browser-probe` | Browser-based redirect_uri probe when curl blocked |
| `references/oauth-fragment-redirect.md` | `oauth-fragment-redirect` | Fragment-based redirect reflection (SPA) |
| `references/oauth-hunter.md` | `oauth-hunter` | OAuth hunter playbook, triage, severity |
| `references/performing-oauth-scope-minimization-review.md` | `performing-oauth-scope-minimization-review` | Scope minimization review, third-party app risk |
| `references/testing-oauth2-implementation-flaws.md` | `testing-oauth2-implementation-flaws` | Implementation flaw testing (Burp/EsPReSSO) |

Original sub-skills remain intact under their directories (including each sub-skill's own api-reference.md, standards.md, workflows.md, assets, scripts, and agent.py where present).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_oauth_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger OAuth, OWASP WebGoat, DVWA, HackTheBox, custom Entra test tenant.
- Mastery criteria: independently discover, validate, and report an OAuth/SAML finding with full reproduction, defense matrix, and impact; or run a detection/scope review with validated queries and remediation.


## Knowledge sources

- WKS bug classes: oauth
- Domain knowledge: oauth
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
