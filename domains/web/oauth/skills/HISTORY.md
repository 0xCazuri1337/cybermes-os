# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 16 (supported 16), FP rules 5, chains 3, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 16 (supported 16), FP rules 5, chains 3, state mature

```diff
--- oauth@current
+++ oauth@new
@@ -107,4 +107,4 @@
 - `authn` (3 shared chain(s))
 
 ---
-Full class document: `domains/web/oauth/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
+Full class document: `domains/web/oauth/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id oauth`
```

## 2026-10-03 01:46 — 102 diff lines
- items: 33 (supported 27), FP rules 6, chains 3, state mature

```diff
--- oauth@current
+++ oauth@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `identity` · CWE CWE-346 · OWASP API8:2023
-> evidence: 16 items, 16 supported, 5 FP rules, 3 chains
+> evidence: 33 items, 27 supported, 6 FP rules, 3 chains
 > maturity: **mature**
 
 The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.
@@ -32,6 +32,24 @@
 - The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.
   - **Disproof:** The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
+- Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request. _(unverified)_
+  - **Disproof:** Seeing the token request or the API calls in captured traffic shows they are front-channel and refutes the assumption that this leg is server-side only.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
+- A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack. _(unverified)_
+  - **Disproof:** If the authorization request uses a different response_type, or no /authorization request and provider redirect are captured at all, this flow signature does not identify the grant in use.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
+- In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side. _(unverified)_
+  - **Disproof:** A callback that delivers the code outside the query string means the code is not exposed in the captured GET request.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
+- Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.
+  - **Disproof:** Seeing the token request or the API calls in captured traffic shows they are front-channel and refutes the assumption that this leg is server-side only.
+  - Sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
+- A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.
+  - **Disproof:** If the authorization request uses a different response_type, or no /authorization request and provider redirect are captured at all, this flow signature does not identify the grant in use.
+  - Sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
+- In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.
+  - **Disproof:** A callback that delivers the code outside the query string means the code is not exposed in the captured GET request.
+  - Sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
 - response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.
   - **Disproof:** response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>
@@ -47,12 +65,39 @@
 - Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.
   - **Disproof:** Both exchanges return invalid_scope, or the issued token's scope claim equals exactly the consented scope.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
+- Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis. _(unverified)_
+  - **Disproof:** An assertion that is genuinely encrypted rather than base64-encoded, or a capture that never exposes the message, cannot be read by decoding it.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://kathan19.gitbook.io/howtohunt/saml/saml.md>
+- Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.
+  - **Disproof:** An assertion that is genuinely encrypted rather than base64-encoded, or a capture that never exposes the message, cannot be read by decoding it.
+  - Sources: <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://kathan19.gitbook.io/howtohunt/saml/saml.md>
+
+## Tests
+
+- A callback CSRF finding requires replaying an authorization response carrying a state value that the receiving browser session never issued, and observing that the client completes the code exchange and binds the resulting session anyway.
+  - **Disproof:** The claim is false when the client rejects every state it did not itself issue for the current browser session, including the copied-from-another-client value, since the binding value is supposed to let the client verify the request by matching it to the user-agent's authenticated state. It is also false when a state parameter was never present in the authorization request and the client never expected one, because the server's obligation to echo state is conditional on the client having sent it. And it is false as an account-takeover claim on a flow where the attacker would also need the victim's credentials to complete the AS-side authentication step, or where the AS displays the real client name on a genuine consent screen so the user aborts - consent is a mitigating layer, not a control to assume away.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html> · <https://cwe.mitre.org/data/definitions/565.html> · <https://www.rfc-editor.org/rfc/rfc6749.html>
+- A mix-up finding is proved only when the authorization response carries an iss value that is not the issuer of the authorization server the client sent the request to, and the resulting code is then accepted by a token endpoint belonging to that other issuer.
+  - **Disproof:** The claim is false when the callback's iss value is identical to the issuer of the authorization server the request was actually sent to, or when the single-AS client never receives a response from a server other than the one it addressed - RFC 9207 states plainly that a client talking to only one authorization server is not vulnerable to mix-up attacks. It is also false if the client rejects the response on mismatch, which is the required behaviour: comparison by simple string comparison, and rejection of the authorization response with no further grant processing when it does not match. A third disproof is a rediscovery: if the iss the client compares against came from a discovery document an attacker also controls, the comparison is worthless, so an impersonating discovery document whose issuer Claim is the honest OP's issuer but whose endpoints and signing keys are the attacker's is itself the finding, not a mitigation.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://openid.net/specs/openid-connect-discovery-1_0.html> · <https://www.rfc-editor.org/rfc/rfc9207.html>
+- Code interception is only proved when an authorization code obtained without ever seeing the victim's code_verifier is successfully exchanged at the token endpoint, which happens if and only if the server either recorded no code_challenge or silently accepted a plain or substituted one. _(unverified)_
+  - **Disproof:** The claim is false whenever the redemption fails with invalid_grant or an equivalent error, which is the required behaviour when the values are not equal. It is also false where the client is confidential and its code is bound to a client_secret, since an interceptor holding only the code cannot authenticate the redemption at all, and where the code is single-use and invalidated on first redemption, so the interception race is closed independently of PKCE. Native clients are explicitly required to implement PKCE and servers to support it, so on a native-app flow a redemption that succeeds without the verifier is a real server-side defect, whereas on a legacy implicit or resource-owner-password flow the absence of a code_challenge is by design and is not this finding.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc7636.html> · <https://www.rfc-editor.org/rfc/rfc8252.html>
+- Cross-tenant token confusion is proved when a token whose aud names resource A is presented to the resource server for resource B and B returns the protected data instead of rejecting it, which can only happen if B skipped the aud check entirely rather than merely checking it loosely.
+  - **Disproof:** The claim is false if B rejects the token, and it is also false if the aud claim in T1 in fact names both resources - a token whose audience legitimately includes B is a correctly scoped token, not a confused one, and the multi-audience case is exactly what the resource indicator mechanism produces when a client requests several resources in one authorization. It is further false when the successful B response returns only data B would serve to any authenticated principal with no per-tenant content in it, since that is an authorization gap in B rather than a token-validation failure, and belongs to a different class. Finally, if B's boundary is enforced downstream of the API by a gateway that does check aud, an API-layer 200 does not demonstrate attacker-reachable confusion and must be re-tested at the layer that actually makes the authorization decision.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9068.html>
 
 ## Validation bar (how to prove it)
 
 - Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.
   - **Disproof:** The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth> · <https://www.rfc-editor.org/rfc/rfc9700.html>
+- Reporting a missing mix-up defence on a single-issuer client is a false positive, because RFC 9700 states the defence is only required when the client interacts with two or more authorization servers.
+  - **Disproof:** The claim is false when the client does federate even if only one server is reachable during the test - a mobile or multi-tenant app with a configurable issuer list, an aggregator that brokers several identity providers, or a client whose issuer list is set from configuration the tester cannot see, all require the defence and can be misreported as single-issuer. It also fails as an assessment where the issuer identifier is unavailable: RFC 9700 contemplates that and points to alternative binding strategies, so the absence of an iss response parameter alone is not proof the client is unprotected. And a client that sends the issuer as an extra parameter and pins the response to it satisfies the requirement even without RFC 9207.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
+- A client that sends code_challenge proves nothing on its own: PKCE defeats code injection only if the authorization server enforced the challenge and the client supplied the matching code_verifier at the token endpoint. _(unverified)_
+  - **Disproof:** The claim is false when the challenge cannot be substituted because the client generates it inside the flow and signs or encrypts the authorization request, or where the authorization server binds the challenge to a value the attacker cannot influence. It is also false when the server rejects a code_challenge_method it does not support rather than silently downgrading to plain, which is the classic downgrade to a challenge the verifier trivially satisfies. And PKCE is not the only valid defence - a confidential client whose code is bound to a client secret, or a single-use code invalidated immediately after first redemption, breaks the attack independently, so the absence of PKCE is not itself the finding.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://www.rfc-editor.org/rfc/rfc7636.txt>
 - Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.
   - **Disproof:** Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
@@ -65,6 +110,15 @@
 - A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.
   - **Disproof:** The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://portswigger.net/web-security/oauth>
+- Registering a wildcard redirection URI pattern is a configuration weakness worth reporting once, but it is not proof of account takeover - the pattern has to actually match an attacker-controlled origin and the authorization server has to honour the match.
+  - **Disproof:** The claim is false when the wildcard is scoped to a domain the attacker cannot obtain an origin under, or when the pattern syntax the tester assumes is not the syntax the server implements - a regex-based matcher, a strict host-suffix check, or a literal-string comparison that happens to contain an asterisk. It is also false as an account-takeover claim when the authorization server detects the mismatch and shows the user rather than redirecting, which RFC 9700 describes as a legitimate response: it SHOULD only automatically redirect if it trusts the redirection URI, and MAY inform the user otherwise. And a third-party consent screen showing the real client name to the user is a mitigating layer, not a control the attacker can be assumed to defeat.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
+
+## Evidence requirements
+
+- A convincing observation for this class is: That comparison is the observable - an authorization response carrying an iss different from the one the request went to, accepted without abort.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (oauth.validation.mix_up_defence_is_only_required_when_a_client_talks_to_two_authorization_servers) states the full boundary.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
 
 ## Impact framing
 
@@ -77,6 +131,9 @@
 
 ## Defence bypasses
 
+- The authorization server can enforce exact redirect_uri matching perfectly and still leak the code, because browsers reattach the URL fragment to a Location redirect that contains no fragment of its own.
+  - **Disproof:** The claim does not apply to the authorization code flow, because the code is delivered in the query string rather than the fragment and the attacker cannot redeem it without the client secret or the PKCE verifier - RFC 9700 lists binding the code to a confidential client or PKCE challenge among the countermeasures that stop this attack. It also fails against strict exact redirect_uri matching, which the document explicitly states is not circumvented, and against servers that attach a fragment to their own Location headers. And it needs the precondition of a reachable open redirector on the same host as the registered callback, which is a separate finding that must be demonstrated, not assumed.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9700.txt> · <https://openid.net/specs/openid-connect-core-1_0.html>
 - Even strict redirect_uri matching can be bypassed via mix-up attacks, open-redirect chain with fragment reattachment, or trailing path traversal on the callback path.
   - **Disproof:** The client validates iss on every authorization response, and every redirect_uri outside the exact registered string - including traversal forms - is rejected outright.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9700.html>
```
