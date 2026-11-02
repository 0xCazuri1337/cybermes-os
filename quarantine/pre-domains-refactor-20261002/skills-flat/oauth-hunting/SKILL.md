---
name: oauth-hunting
description: Use when hunting OAuth 2.0 / OIDC Misconfiguration in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# OAuth 2.0 / OIDC Misconfiguration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE CWE-346 · OWASP API8:2023
> evidence: 16 items, 16 supported, 5 FP rules, 3 chains
> maturity: **mature**

The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.

**Also called:** oauth, oidc, oauth misconfiguration, redirect_uri validation, open redirect in oauth, sso open redirect


## Prerequisites (do not start without these)

- OAuth is only attackable where a live authorization endpoint accepts client_id, redirect_uri and response_type; nothing to hunt if that first hop never appears.
  - **Disproof:** No authorization request with OAuth-specific query parameters appears anywhere in the flow; login is plain password/OIDC-less form auth.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- Code interception is only exploitable when the client is public (SPA/mobile) or PKCE is not enforced; a confidential client with client_secret + PKCE blocks redemption of a stolen code.
  - **Disproof:** Authorization request always sends code_challenge=S256 and the token endpoint rejects a redemption without the matching code_verifier.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Recon signals (where to look)

- The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.
  - **Disproof:** The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.
  - **Disproof:** response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Techniques (what to change)

- An authorization request with no state/nonce lets an attacker pre-initiate the flow and bind the victim's client-side session to the attacker's AS identity.
  - **Disproof:** A random, single-use state bound to the user agent is present and the callback rejects any state the client did not issue for that browser session.
  - Sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- Redirect URI allowlists are bypassable via prefix/duplicate/localhost tricks, path traversal on the callback path, or a dangling wildcard subdomain.
  - **Disproof:** Every mutated redirect_uri outside the exact registered string is rejected (invalid_redirect_uri / 400), Location always stays on the registered host, and no dangling subdomain exists.
  - Sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.
  - **Disproof:** Both exchanges return invalid_scope, or the issued token's scope claim equals exactly the consented scope.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Validation bar (how to prove it)

- Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.
  - **Disproof:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.
  - **Disproof:** Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## False-positive rules (when to reject it)

- A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.
  - **Disproof:** A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
  - Sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.
  - **Disproof:** The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Impact framing

- An OAuth application authorized on behalf of a signed-in user inherits exactly the scopes the user or admin consented to, so an over-scoped grant is a standing application principal whose authority is bounded by nobody reviewing it again.
  - **Disproof:** Refuted when every sensitive scope requires administrator consent and is reviewed before grant, or when the tenant revokes existing grants automatically when a sign-in event looks anomalous; then the application never retains a durable principal.
  - Sources: <https://redcanary.com/blog/threat-detection/oauth-app-attacks/> · <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection>
- A leaked OAuth code or access token yields login as the victim on every client application registered with that authorization server, not just the target.
  - **Disproof:** The stolen artifact is single-use, audience-bound, short-lived and yields no authenticated session or API data beyond the attacker's own account.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Defence bypasses

- Even strict redirect_uri matching can be bypassed via mix-up attacks, open-redirect chain with fragment reattachment, or trailing path traversal on the callback path.
  - **Disproof:** The client validates iss on every authorization response, and every redirect_uri outside the exact registered string - including traversal forms - is rejected outright.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Chaining opportunities

- An OAuth consent grant captured or induced for an over-scoped application hands the attacker a durable token-bearing principal whose scopes outlive the login that produced it, turning a single authorization event into persistent application access.
  - **Disproof:** Refuted if the tenant enforces admin-consent for the granted scopes and the authorization server binds the issued token to a client certificate or device identity the attacker does not hold; a stolen code alone then cannot be redeemed.
  - Sources: <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection> · <https://www.wiz.io/blog/detecting-malicious-oauth-applications>
- An OAuth open redirect on the callback path, chained with implicit/fragment flows, escalates a low-severity redirect bug into token theft and account takeover.
  - **Disproof:** No open redirect exists on the callback host and fragment response_mode is refused, so nothing is ever forwarded to an external domain.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Rejected before you report

- **Tokens stored in localStorage are readable by any script, therefore account takeover**
  - Killed by: No script execution was demonstrable on any origin; the token was not readable cross-origin and no XSS existed to read it
  - Rule: Token storage location is only a finding when a script-execution primitive is separately demonstrable; localStorage alone is a hardening gap, not account takeover
- **A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.**
  - Killed by: A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
  - Rule: A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.
- **A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.**
  - Killed by: The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
  - Rule: A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.

## Chains to

- `authn` (3 shared chain(s))

---
Full class document: `skills/Web/oauth/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
