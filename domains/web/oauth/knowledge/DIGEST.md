# OAuth 2.0 / OIDC Misconfiguration

> surface: `identity` · CWE: CWE-346 · OWASP: API8:2023
> maturity: **mature** — 16 items, 16 supported, 5 FP rules, 3 chains

The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.

**Aliases:** oauth, oidc, oauth misconfiguration, redirect_uri validation, open redirect in oauth, sso open redirect

## Prerequisite

- **OAuth is only attackable where a live authorization endpoint accepts client_id, redirect_uri and response_type; nothing to hunt if that first hop never appears.**  
  `high_confidence` · score 0.855 · disproved by: No authorization request with OAuth-specific query parameters appears anywhere in the flow; login is plain password/OIDC-less form auth.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- **Code interception is only exploitable when the client is public (SPA/mobile) or PKCE is not enforced; a confidential client with client_secret + PKCE blocks redemption of a stolen code.**  
  `high_confidence` · score 0.8275 · disproved by: Authorization request always sends code_challenge=S256 and the token endpoint rejects a redemption without the matching code_verifier.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Signal

- **The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.**  
  `high_confidence` · score 0.894 · disproved by: The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- **response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.**  
  `high_confidence` · score 0.855 · disproved by: response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Technique

- **An authorization request with no state/nonce lets an attacker pre-initiate the flow and bind the victim's client-side session to the attacker's AS identity.**  
  `high_confidence` · score 0.885 · disproved by: A random, single-use state bound to the user agent is present and the callback rejects any state the client did not issue for that browser session.
  sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- **Redirect URI allowlists are bypassable via prefix/duplicate/localhost tricks, path traversal on the callback path, or a dangling wildcard subdomain.**  
  `high_confidence` · score 0.8575 · disproved by: Every mutated redirect_uri outside the exact registered string is rejected (invalid_redirect_uri / 400), Location always stays on the registered host, and no dangling subdomain exists.
  sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- **Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.**  
  `high_confidence` · score 0.839 · disproved by: Both exchanges return invalid_scope, or the issued token's scope claim equals exactly the consented scope.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Validation

- **Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.**  
  `high_confidence` · score 0.8825 · disproved by: Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- **Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.**  
  `high_confidence` · score 0.8275 · disproved by: The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Fp Rule

- **A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.**  
  `high_confidence` · score 0.8575 · disproved by: A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
  sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- **A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.**  
  `high_confidence` · score 0.8 · disproved by: The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Impact

- **An OAuth application authorized on behalf of a signed-in user inherits exactly the scopes the user or admin consented to, so an over-scoped grant is a standing application principal whose authority is bounded by nobody reviewing it again.**  
  `high_confidence` · score 0.8355 · disproved by: Refuted when every sensitive scope requires administrator consent and is reviewed before grant, or when the tenant revokes existing grants automatically when a sign-in event looks anomalous; then the application never retains a durable principal.
  sources: <https://redcanary.com/blog/threat-detection/oauth-app-attacks/> · <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection>
- **A leaked OAuth code or access token yields login as the victim on every client application registered with that authorization server, not just the target.**  
  `high_confidence` · score 0.784 · disproved by: The stolen artifact is single-use, audience-bound, short-lived and yields no authenticated session or API data beyond the attacker's own account.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Bypass

- **Even strict redirect_uri matching can be bypassed via mix-up attacks, open-redirect chain with fragment reattachment, or trailing path traversal on the callback path.**  
  `high_confidence` · score 0.8665 · disproved by: The client validates iss on every authorization response, and every redirect_uri outside the exact registered string - including traversal forms - is rejected outright.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Chain Link

- **An OAuth consent grant captured or induced for an over-scoped application hands the attacker a durable token-bearing principal whose scopes outlive the login that produced it, turning a single authorization event into persistent application access.**  
  `high_confidence` · score 0.8715 · disproved by: Refuted if the tenant enforces admin-consent for the granted scopes and the authorization server binds the issued token to a client certificate or device identity the attacker does not hold; a stolen code alone then cannot be redeemed.
  sources: <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection> · <https://www.wiz.io/blog/detecting-malicious-oauth-applications>
- **An OAuth open redirect on the callback path, chained with implicit/fragment flows, escalates a low-severity redirect bug into token theft and account takeover.**  
  `high_confidence` · score 0.8275 · disproved by: No open redirect exists on the callback host and fragment response_mode is refused, so nothing is ever forwarded to an external domain.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## False-positive rules

- **Hypothesis:** Tokens stored in localStorage are readable by any script, therefore account takeover
  - **Invalidated by:** No script execution was demonstrable on any origin; the token was not readable cross-origin and no XSS existed to read it
  - **Rule:** Token storage location is only a finding when a script-execution primitive is separately demonstrable; localStorage alone is a hardening gap, not account takeover

- **Hypothesis:** A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.
  - **Invalidated by:** A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
  - **Rule:** A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.

- **Hypothesis:** A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.
  - **Invalidated by:** The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
  - **Rule:** A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.

## Related classes (via chains)

- `authn` Authentication Failures (3 chains)
