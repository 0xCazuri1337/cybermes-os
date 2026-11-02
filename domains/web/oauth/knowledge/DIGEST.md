# OAuth 2.0 / OIDC Misconfiguration

> surface: `identity` · CWE: CWE-346 · OWASP: API8:2023
> maturity: **mature** — 29 items, 26 supported, 6 FP rules, 3 chains

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

- **Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.**  
  `high_confidence` · score 0.9065 · disproved by: Seeing the token request or the API calls in captured traffic shows they are front-channel and refutes the assumption that this leg is server-side only.
  sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
- **The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.**  
  `high_confidence` · score 0.894 · disproved by: The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- **A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.**  
  `high_confidence` · score 0.879 · disproved by: If the authorization request uses a different response_type, or no /authorization request and provider redirect are captured at all, this flow signature does not identify the grant in use.
  sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
- **response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.**  
  `high_confidence` · score 0.855 · disproved by: response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- **In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.**  
  `high_confidence` · score 0.8515 · disproved by: A callback that delivers the code outside the query string means the code is not exposed in the captured GET request.
  sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>

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
- **Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.**  
  `high_confidence` · score 0.824 · disproved by: An assertion that is genuinely encrypted rather than base64-encoded, or a capture that never exposes the message, cannot be read by decoding it.
  sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://kathan19.gitbook.io/howtohunt/saml/saml.md>

## Test

- **A callback CSRF finding requires replaying an authorization response carrying a state value that the receiving browser session never issued, and observing that the client completes the code exchange and binds the resulting session anyway.**  
  `high_confidence` · score 0.934 · disproved by: The claim is false when the client rejects every state it did not itself issue for the current browser session, including the copied-from-another-client value, since the binding value is supposed to let the client verify the request by matching it to the user-agent's authenticated state. It is also false when a state parameter was never present in the authorization request and the client never expected one, because the server's obligation to echo state is conditional on the client having sent it. And it is false as an account-takeover claim on a flow where the attacker would also need the victim's credentials to complete the AS-side authentication step, or where the AS displays the real client name on a genuine consent screen so the user aborts - consent is a mitigating layer, not a control to assume away.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc6749.html>
- **A mix-up finding is proved only when the authorization response carries an iss value that is not the issuer of the authorization server the client sent the request to, and the resulting code is then accepted by a token endpoint belonging to that other issuer.**  
  `high_confidence` · score 0.934 · disproved by: The claim is false when the callback's iss value is identical to the issuer of the authorization server the request was actually sent to, or when the single-AS client never receives a response from a server other than the one it addressed - RFC 9207 states plainly that a client talking to only one authorization server is not vulnerable to mix-up attacks. It is also false if the client rejects the response on mismatch, which is the required behaviour: comparison by simple string comparison, and rejection of the authorization response with no further grant processing when it does not match. A third disproof is a rediscovery: if the iss the client compares against came from a discovery document an attacker also controls, the comparison is worthless, so an impersonating discovery document whose issuer Claim is the honest OP's issuer but whose endpoints and signing keys are the attacker's is itself the finding, not a mitigation.
  sources: <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://openid.net/specs/openid-connect-discovery-1_0.html> · <https://www.rfc-editor.org/rfc/rfc9207.html>
- **Code interception is only proved when an authorization code obtained without ever seeing the victim's code_verifier is successfully exchanged at the token endpoint, which happens if and only if the server either recorded no code_challenge or silently accepted a plain or substituted one.**  
  `high_confidence` · score 0.934 · disproved by: The claim is false whenever the redemption fails with invalid_grant or an equivalent error, which is the required behaviour when the values are not equal. It is also false where the client is confidential and its code is bound to a client_secret, since an interceptor holding only the code cannot authenticate the redemption at all, and where the code is single-use and invalidated on first redemption, so the interception race is closed independently of PKCE. Native clients are explicitly required to implement PKCE and servers to support it, so on a native-app flow a redemption that succeeds without the verifier is a real server-side defect, whereas on a legacy implicit or resource-owner-password flow the absence of a code_challenge is by design and is not this finding.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://www.rfc-editor.org/rfc/rfc8252.html>
- **Cross-tenant token confusion is proved when a token whose aud names resource A is presented to the resource server for resource B and B returns the protected data instead of rejecting it, which can only happen if B skipped the aud check entirely rather than merely checking it loosely.**  
  `high_confidence` · score 0.918 · disproved by: The claim is false if B rejects the token, and it is also false if the aud claim in T1 in fact names both resources - a token whose audience legitimately includes B is a correctly scoped token, not a confused one, and the multi-audience case is exactly what the resource indicator mechanism produces when a client requests several resources in one authorization. It is further false when the successful B response returns only data B would serve to any authenticated principal with no per-tenant content in it, since that is an authorization gap in B rather than a token-validation failure, and belongs to a different class. Finally, if B's boundary is enforced downstream of the API by a gateway that does check aud, an API-layer 200 does not demonstrate attacker-reachable confusion and must be re-tested at the layer that actually makes the authorization decision.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9068.html>

## Validation

- **Reporting a missing mix-up defence on a single-issuer client is a false positive, because RFC 9700 states the defence is only required when the client interacts with two or more authorization servers.**  
  `under_review` · score 0.8905 · disproved by: The claim is false when the client does federate even if only one server is reachable during the test - a mobile or multi-tenant app with a configurable issuer list, an aggregator that brokers several identity providers, or a client whose issuer list is set from configuration the tester cannot see, all require the defence and can be misreported as single-issuer. It also fails as an assessment where the issuer identifier is unavailable: RFC 9700 contemplates that and points to alternative binding strategies, so the absence of an iss response parameter alone is not proof the client is unprotected. And a client that sends the issuer as an extra parameter and pins the response to it satisfies the requirement even without RFC 9207.
  sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
- **Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.**  
  `under_review` · score 0.8825 · disproved by: Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
- **A client that sends code_challenge proves nothing on its own: PKCE defeats code injection only if the authorization server enforced the challenge and the client supplied the matching code_verifier at the token endpoint.**  
  `high_confidence` · score 0.879 · disproved by: The claim is false when the challenge cannot be substituted because the client generates it inside the flow and signs or encrypts the authorization request, or where the authorization server binds the challenge to a value the attacker cannot influence. It is also false when the server rejects a code_challenge_method it does not support rather than silently downgrading to plain, which is the classic downgrade to a challenge the verifier trivially satisfies. And PKCE is not the only valid defence - a confidential client whose code is bound to a client secret, or a single-use code invalidated immediately after first redemption, breaks the attack independently, so the absence of PKCE is not itself the finding.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://www.rfc-editor.org/rfc/rfc7636.txt>
- **Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.**  
  `high_confidence` · score 0.8275 · disproved by: The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>

## Fp Rule

- **A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.**  
  `high_confidence` · score 0.8575 · disproved by: A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
  sources: <https://cwe.mitre.org/data/definitions/346.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
- **Registering a wildcard redirection URI pattern is a configuration weakness worth reporting once, but it is not proof of account takeover - the pattern has to actually match an attacker-controlled origin and the authorization server has to honour the match.**  
  `high_confidence` · score 0.8355 · disproved by: The claim is false when the wildcard is scoped to a domain the attacker cannot obtain an origin under, or when the pattern syntax the tester assumes is not the syntax the server implements - a regex-based matcher, a strict host-suffix check, or a literal-string comparison that happens to contain an asterisk. It is also false as an account-takeover claim when the authorization server detects the mismatch and shows the user rather than redirecting, which RFC 9700 describes as a legitimate response: it SHOULD only automatically redirect if it trusts the redirection URI, and MAY inform the user otherwise. And a third-party consent screen showing the real client name to the user is a mitigating layer, not a control the attacker can be assumed to defeat.
  sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
- **A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.**  
  `high_confidence` · score 0.8 · disproved by: The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Evidence

- **A convincing observation for this class is: That comparison is the observable - an authorization response carrying an iss different from the one the request went to, accepted without abort.**  
  `under_review` · score 0.863 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (oauth.validation.mix_up_defence_is_only_required_when_a_client_talks_to_two_authorization_servers) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>

## Impact

- **An OAuth application authorized on behalf of a signed-in user inherits exactly the scopes the user or admin consented to, so an over-scoped grant is a standing application principal whose authority is bounded by nobody reviewing it again.**  
  `high_confidence` · score 0.8355 · disproved by: Refuted when every sensitive scope requires administrator consent and is reviewed before grant, or when the tenant revokes existing grants automatically when a sign-in event looks anomalous; then the application never retains a durable principal.
  sources: <https://redcanary.com/blog/threat-detection/oauth-app-attacks/> · <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection>
- **A leaked OAuth code or access token yields login as the victim on every client application registered with that authorization server, not just the target.**  
  `high_confidence` · score 0.784 · disproved by: The stolen artifact is single-use, audience-bound, short-lived and yields no authenticated session or API data beyond the attacker's own account.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>

## Bypass

- **The authorization server can enforce exact redirect_uri matching perfectly and still leak the code, because browsers reattach the URL fragment to a Location redirect that contains no fragment of its own.**  
  `high_confidence` · score 0.8905 · disproved by: The claim does not apply to the authorization code flow, because the code is delivered in the query string rather than the fragment and the attacker cannot redeem it without the client secret or the PKCE verifier - RFC 9700 lists binding the code to a confidential client or PKCE challenge among the countermeasures that stop this attack. It also fails against strict exact redirect_uri matching, which the document explicitly states is not circumvented, and against servers that attach a fragment to their own Location headers. And it needs the precondition of a reachable open redirector on the same host as the registered callback, which is a separate finding that must be demonstrated, not assumed.
  sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
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
