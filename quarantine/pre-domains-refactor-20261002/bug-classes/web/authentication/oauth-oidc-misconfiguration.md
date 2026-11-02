# OAuth 2.0 / OIDC Misconfiguration

## Definition

The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.

- **CWE:** CWE-346
- **OWASP:** API8:2023
- **Surface:** identity
- **Aliases:** ["oauth", "oidc", "oauth misconfiguration", "redirect_uri validation", "open redirect in oauth", "sso open redirect"]

Canonical home for `oauth`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**OAuth is only attackable where a live authorization endpoint accepts client_id, redirect_uri and response_type; nothing to hunt if that first hop never appears.**

Proxy the social/SSO login, then filter for GET /authorize or /oauth/authorize. Confirm client_id, redirect_uri, response_type, scope, state are echoed in the query string. Also fetch /.well-known/openid-configuration and /.well-known/oauth-authorization-server on that host to enumerate endpoints, response_types_supported and code_challenge_methods_supported before touching anything.

*Disproof:* No authorization request with OAuth-specific query parameters appears anywhere in the flow; login is plain password/OIDC-less form auth.

**Code interception is only exploitable when the client is public (SPA/mobile) or PKCE is not enforced; a confidential client with client_secret + PKCE blocks redemption of a stolen code.**

Determine client type: does the bundle or app contain a client_secret (public client), or is it a server-side confidential client? Then check whether the authorization request carries code_challenge with method S256. RFC 9700 requires PKCE for public clients and code_verifier enforcement at /token whenever code_challenge was sent. No code_challenge anywhere = interception/injection path open.

*Disproof:* Authorization request always sends code_challenge=S256 and the token endpoint rejects a redemption without the matching code_verifier.

## Attack Surface

Surface: **identity**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.**

Capture the full GET /authorization?client_id=...&redirect_uri=...&response_type=...&scope=...&state=... line. Absence of state or nonce is the loudest signal. Identify the provider from the Host header, then pull /.well-known/openid-configuration for the full endpoint list and supported grant/response types.

*Disproof:* The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.

**response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.**

Flip response_type=code to response_type=token on a live authorization request; if the AS returns #access_token= in the fragment the implicit grant is enabled and the front channel is your exfil path. Separately grep JS bundles, apk smali and .env files for client_secret / clientSecret alongside client_id - a secret in a public bundle makes the client effectively public.

*Disproof:* response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.

## Exploitation

**An authorization request with no state/nonce lets an attacker pre-initiate the flow and bind the victim's client-side session to the attacker's AS identity.**

Start an authorization request from your own browser with your own account and no state, then serve the resulting callback URL as a link/auto-submit form to the victim. If the client logs the victim in as you (or links your social account to their profile), that is forced account linking / login CSRF. Same shape without state: strip the code parameter or swap it for an attacker code to inject a session.

*Disproof:* A random, single-use state bound to the user agent is present and the callback rejects any state the client did not issue for that browser session.

**Redirect URI allowlists are bypassable via prefix/duplicate/localhost tricks, path traversal on the callback path, or a dangling wildcard subdomain.**

Baseline redirect_uri=https://client.example/cb, then mutate: append path/query/fragment; try https://client.example.evil.tld, duplicate ?redirect_uri=cb&redirect_uri=evil.tld, localhost.evil.tld, client.example@evil.tld. Then /authorized/callback/../evil and /oauth/callback/../../example/path - back-ends normalise the path and serve another page on the whitelisted host that leaks the query string. For https://*.client.example/* patterns hunt an unclaimed CNAME subdomain.

*Disproof:* Every mutated redirect_uri outside the exact registered string is rejected (invalid_redirect_uri / 400), Location always stays on the registered host, and no dangling subdomain exists.

**Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.**

Register your own client, run a normal openid email authorization, then re-POST /token adding &scope=openid%20email%20profile. If the JSON access_token response echoes a scope wider than the consented one, the AS ignored the stored scope. Same test on the implicit path: call /userinfo with the stolen bearer token plus an extra scope= parameter and read back fields you were never granted.

*Disproof:* Both exchanges return invalid_scope, or the issued token's scope claim equals exactly the consented scope.

## Variations

**Even strict redirect_uri matching can be bypassed via mix-up attacks, open-redirect chain with fragment reattachment, or trailing path traversal on the callback path.**

Mix-up: client talks to two AS - if the client never checks iss in the authorization response or the ID Token, send the code from the honest AS to your own AS token endpoint. Fragment trick: a strict redirect_uri plus a client-side open redirect still leaks tokens, because a Location header without a fragment makes the browser reattach #access_token=. Traversal: /cb/../evil still resolves on the allowed host and can leak the code.

*Disproof:* The client validates iss on every authorization response, and every redirect_uri outside the exact registered string - including traversal forms - is rejected outright.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `oauth-open-redirect-to-ato` — OAuth redirect_uri validation failure to account takeover (goal: `account_takeover`)
- `oauth-state-missing-to-login-csrf-binding` — Missing OAuth state parameter to login CSRF to attacker-bound victim session (goal: `account_takeover`)
- `saml-assertion-signature-wrapping-to-session-identity-substitution` — SAML assertion signature wrapping to attacker-selected session identity (goal: `account_takeover`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.**

Before reporting redirect_uri manipulation, confirm the code actually landed on a host you control: capture the 302/303 Location and the follow-up request to your listener. If the AS rejected every out-of-allowlist host with invalid_redirect_uri, or the only accepted variants stay on the registered host, the finding is a scanner artefact - exact string matching is the required behaviour per BCP 240.

*Disproof:* A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.

**A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.**

Re-run every proof in a clean browser profile with no pre-existing cookies: a takeover demo that depends on your authenticated session is invalid. Likewise a token sitting in localStorage is only reportable as a chain when you separately demonstrate script execution on the same origin (a working XSS or an injected script reading it); HttpOnly cookies cannot be read by XSS, so token storage alone is not the impact.

*Disproof:* The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
**Hypothesis:** A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.
- Invalidated by: A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
- **Rejection rule:** A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.

**Hypothesis:** A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.
- Invalidated by: The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
- **Rejection rule:** A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.

**Hypothesis:** Tokens stored in localStorage are readable by any script, therefore account takeover
- Invalidated by: No script execution was demonstrable on any origin; the token was not readable cross-origin and no XSS existed to read it
- **Rejection rule:** Token storage location is only a finding when a script-execution primitive is separately demonstrable; localStorage alone is a hardening gap, not account takeover

## Validation

**Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.**

Run the full flow with your own AS account as the victim stand-in: send the tampered authorization request, approve as yourself, and let the victim's browser (clean session) hit the redirect_uri. Then load the client application homepage and confirm the displayed account is your attacker identity. Note that state/nonce protection is useless here because the attacker generated those values from their own browser.

*Disproof:* The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.

**Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.**

After the upgraded exchange, call the resource server with the token and request a field behind the extra scope (e.g. GET /userinfo returns address/phone, or GET /api/v2/... returns data outside the consented scope). Also replay the same token against a second audience/API host - if a token minted for audience A is accepted by audience B, audience validation is missing and the finding is real.

*Disproof:* Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.

## Impact

**An OAuth application authorized on behalf of a signed-in user inherits exactly the scopes the user or admin consented to, so an over-scoped grant is a standing application principal whose authority is bounded by nobody reviewing it again.**

The impact statement follows from how delegated authorization is defined rather than from any single exploit. An application is authorized to act on behalf of a signed-in user constrained by the scopes permissions the app requests and the user or admin consents to, and consent governs both whether an authorization code is issued and which scopes are permitted. Because the grant is evaluated once and then persists, the effective privilege of a compromised or malicious application is decided at consent time by a user who cannot enumerate the permission list. Two behaviours compound this: user-consentable scopes such as mail.read or offline_access can be granted by an ordinary user with no administrator in the loop, and an offline_access grant yields refresh-token durability that outlives the session. Detection therefore has to treat an unexpected consented application as a credential-compromise signal rather than as an application-inventory record.

*Disproof:* Refuted when every sensitive scope requires administrator consent and is reviewed before grant, or when the tenant revokes existing grants automatically when a sign-in event looks anomalous; then the application never retains a durable principal.

**A leaked OAuth code or access token yields login as the victim on every client application registered with that authorization server, not just the target.**

Impact statement for the report: with a valid code (public client) or bearer token the attacker logs in as the victim, reads the profile/email scopes, and acts in the victim's context on any other relying party sharing the AS. With implicit, the token also works directly against the resource server's API, exposing data the client UI never shows. State the concrete data set reached, not just 'token leaked'.

*Disproof:* The stolen artifact is single-use, audience-bound, short-lived and yields no authenticated session or API data beyond the attacker's own account.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/346.html>
- **elastic.co** (research)
  - <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/oauth>
- **redcanary.com** (research)
  - <https://redcanary.com/blog/threat-detection/oauth-app-attacks/>
- **rfc-editor.org** (docs)
  - <https://www.rfc-editor.org/rfc/rfc9700.html>
- **wiz.io** (research)
  - <https://www.wiz.io/blog/detecting-malicious-oauth-applications>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
