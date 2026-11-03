<!-- GENERATED from db/wks.db — do not edit -->
# OAuth 2.0 / OIDC Misconfiguration

## Definition

The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.

- **CWE:** CWE-346
- **OWASP:** API8:2023
- **Surface:** identity
- **Aliases:** ["oauth", "oidc", "oauth misconfiguration", "redirect_uri validation", "open redirect in oauth", "sso open redirect"]

Canonical home for `oauth`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

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

**Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.**

Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

*Disproof:* Seeing the token request or the API calls in captured traffic shows they are front-channel and refutes the assumption that this leg is server-side only.

**A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.**

A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

*Disproof:* If the authorization request uses a different response_type, or no /authorization request and provider redirect are captured at all, this flow signature does not identify the grant in use.

**In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.**

In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

*Disproof:* A callback that delivers the code outside the query string means the code is not exposed in the captured GET request.

**Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.**

Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

*Disproof:* Seeing the token request or the API calls in captured traffic shows they are front-channel and refutes the assumption that this leg is server-side only.

**A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.**

A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

*Disproof:* If the authorization request uses a different response_type, or no /authorization request and provider redirect are captured at all, this flow signature does not identify the grant in use.

**In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.**

In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

*Disproof:* A callback that delivers the code outside the query string means the code is not exposed in the captured GET request.

**response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.**

Flip response_type=code to response_type=token on a live authorization request; if the AS returns #access_token= in the fragment the implicit grant is enabled and the front channel is your exfil path. Separately grep JS bundles, apk smali and .env files for client_secret / clientSecret alongside client_id - a secret in a public bundle makes the client effectively public.

*Disproof:* response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.

**A convincing observation for this class is: That comparison is the observable - an authorization response carrying an iss different from the one the request went to, accepted without abort.**

Derived from oauth.validation.mix_up_defence_is_only_required_when_a_client_talks_to_two_authorization_servers, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (oauth.validation.mix_up_defence_is_only_required_when_a_client_talks_to_two_authorization_servers) states the full boundary.

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

**Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.**

Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.

HackTricks reference: saml (https://kathan19.gitbook.io/howtohunt/saml/saml.md)

*Disproof:* An assertion that is genuinely encrypted rather than base64-encoded, or a capture that never exposes the message, cannot be read by decoding it.

**Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.**

Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.

HackTricks reference: saml (https://kathan19.gitbook.io/howtohunt/saml/saml.md)

*Disproof:* An assertion that is genuinely encrypted rather than base64-encoded, or a capture that never exposes the message, cannot be read by decoding it.

## Variations

**The authorization server can enforce exact redirect_uri matching perfectly and still leak the code, because browsers reattach the URL fragment to a Location redirect that contains no fragment of its own.**

This is the highest-value OAuth bypass in the corpus because it survives a control that testers usually treat as decisive. RFC 9700 walks it through: the attack combines the client acting as an open redirector with the user agent's fragment-reattachment behaviour, and it circumvents even very narrow redirection URI patterns but not strict URL matching. The mechanics: the registered pattern permits query parameters on the callback, the callback host exposes a redirect_to-style endpoint, and because that endpoint's 303 Location header carries no fragment, the browser reattaches the original #access_token to the attacker's URL. That is why the guidance tells web servers hosting redirection URIs not to expose open redirectors at all, and separately offers the defensive trick of appending an arbitrary fragment identifier such as #_ to Location headers so the browser will not reattach. When you find a wildcard callback, hunt the callback host for a redirector before concluding the wildcard is harmless.

*Disproof:* The claim does not apply to the authorization code flow, because the code is delivered in the query string rather than the fragment and the attacker cannot redeem it without the client secret or the PKCE verifier - RFC 9700 lists binding the code to a confidential client or PKCE challenge among the countermeasures that stop this attack. It also fails against strict exact redirect_uri matching, which the document explicitly states is not circumvented, and against servers that attach a fragment to their own Location headers. And it needs the precondition of a reachable open redirector on the same host as the registered callback, which is a separate finding that must be demonstrated, not assumed.

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

**Registering a wildcard redirection URI pattern is a configuration weakness worth reporting once, but it is not proof of account takeover - the pattern has to actually match an attacker-controlled origin and the authorization server has to honour the match.**

A wildcard pattern such as https://*.somesite.example/* looks alarming in a client registration and is routinely reported as 'redirect_uri bypass'. The test that distinguishes a real finding from a configuration smell is whether a URL under an origin the attacker controls satisfies the pattern and is accepted by the live server. The comparison the server performs is the only thing that matters, and RFC 9700's position is that pattern matching is inherently risky to implement and manage correctly - it explicitly advises simplifying to exact matching instead, with a single exception for native apps using a localhost URI, where variable port numbers must be allowed. So the correct framing for a report is: the pattern is broader than necessary per that guidance, AND separately, here is the request the server accepted that it should not have. If you cannot get the server to accept a foreign origin, the finding is the configuration risk, not a demonstrated credential leak.

*Disproof:* The claim is false when the wildcard is scoped to a domain the attacker cannot obtain an origin under, or when the pattern syntax the tester assumes is not the syntax the server implements - a regex-based matcher, a strict host-suffix check, or a literal-string comparison that happens to contain an asterisk. It is also false as an account-takeover claim when the authorization server detects the mismatch and shows the user rather than redirecting, which RFC 9700 describes as a legitimate response: it SHOULD only automatically redirect if it trusts the redirection URI, and MAY inform the user otherwise. And a third-party consent screen showing the real client name to the user is a mitigating layer, not a control the attacker can be assumed to defeat.
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

**Reporting a missing mix-up defence on a single-issuer client is a false positive, because RFC 9700 states the defence is only required when the client interacts with two or more authorization servers.**

Mix-up attacks need a client that federates. RFC 9700 conditions the requirement on that topology: when an OAuth client can only interact with one authorization server, a mix-up defence is not required; where a client interacts with two or more, clients MUST prevent mix-up attacks. This is a valuable fp_rule because the report is easy to write from a code read and impossible to demonstrate from HTTP behaviour alone - you would need to stand up a second authorization server and convince the client to route a response through it. When the topology does hold, the required defence is concrete: for each authorization request the client stores the issuer it sent the request to and binds that to the user agent, and on receipt of the response compares the received issuer identifier against the stored one, aborting on mismatch. That comparison is the observable - an authorization response carrying an iss different from the one the request went to, accepted without abort.

*Disproof:* The claim is false when the client does federate even if only one server is reachable during the test - a mobile or multi-tenant app with a configurable issuer list, an aggregator that brokers several identity providers, or a client whose issuer list is set from configuration the tester cannot see, all require the defence and can be misreported as single-issuer. It also fails as an assessment where the issuer identifier is unavailable: RFC 9700 contemplates that and points to alternative binding strategies, so the absence of an iss response parameter alone is not proof the client is unprotected. And a client that sends the issuer as an extra parameter and pins the response to it satisfies the requirement even without RFC 9207.

**A client that sends code_challenge proves nothing on its own: PKCE defeats code injection only if the authorization server enforced the challenge and the client supplied the matching code_verifier at the token endpoint.**

RFC 9700 is explicit about how PKCE works as a defence and about how it fails. When the attacker injects an authorization code, the code_verifier check fails: the client uses its correct verifier while the code is associated with a code_challenge that does not match it. That failure only happens if a challenge was registered in the first place, so the pass condition has three parts: the authorize request carried code_challenge and code_challenge_method, the server recorded it against the issued code, and the token request carried the matching code_verifier. The document also names the limits: an attacker who can modify the nonce or code_challenge values in the victim's authorization request can circumvent the countermeasure, which is the code_challenge_substitution variant, and it requires the attacker to be able to tamper with the victim's outbound authorization URL. So the field test is the substitution, not the omission - substitute your own challenge and try to redeem the resulting code with your own verifier.

*Disproof:* The claim is false when the challenge cannot be substituted because the client generates it inside the flow and signs or encrypts the authorization request, or where the authorization server binds the challenge to a value the attacker cannot influence. It is also false when the server rejects a code_challenge_method it does not support rather than silently downgrading to plain, which is the classic downgrade to a challenge the verifier trivially satisfies. And PKCE is not the only valid defence - a confidential client whose code is bound to a client secret, or a single-use code invalidated immediately after first redemption, breaks the attack independently, so the absence of PKCE is not itself the finding.

**Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.**

After the upgraded exchange, call the resource server with the token and request a field behind the extra scope (e.g. GET /userinfo returns address/phone, or GET /api/v2/... returns data outside the consented scope). Also replay the same token against a second audience/API host - if a token minted for audience A is accepted by audience B, audience validation is missing and the finding is real.

*Disproof:* Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.

**A callback CSRF finding requires replaying an authorization response carrying a state value that the receiving browser session never issued, and observing that the client completes the code exchange and binds the resulting session anyway.**

The state test is a cross-session replay, not a missing-parameter observation. Start the authorization request in browser profile A so it receives a state value S_A, abort before the callback lands, and note S_A. Now, in a clean browser profile B that has an authenticated session but never initiated a flow, navigate to the callback URL carrying the aborted response - code=...&state=S_A. Two variants must both fail for the control to hold: the state-only variant (no code) must be refused by the client, and the full variant, where you also have a code from a flow you initiated yourself, must be refused before any token exchange. A client that accepts the S_A-bearing response and establishes a session is the finding. Then run the discriminating sub-test that separates a real CSRF from a client that merely compares state loosely: submit a syntactically valid but never-issued state such as 16 random characters, and a state copied from an entirely different client or flow. RFC 6749 requires the state value used for CSRF protection to be non-guessable, so the pass condition is that all three of the never-issued, cross-flow and cross-session values are rejected, while the session's own current state is accepted exactly once. Record which of the three the client rejects, because a client that accepts a well-formed but unknown state has a predictable-value defect even if it binds the session properly.

*Disproof:* The claim is false when the client rejects every state it did not itself issue for the current browser session, including the copied-from-another-client value, since the binding value is supposed to let the client verify the request by matching it to the user-agent's authenticated state. It is also false when a state parameter was never present in the authorization request and the client never expected one, because the server's obligation to echo state is conditional on the client having sent it. And it is false as an account-takeover claim on a flow where the attacker would also need the victim's credentials to complete the AS-side authentication step, or where the AS displays the real client name on a genuine consent screen so the user aborts - consent is a mitigating layer, not a control to assume away.

**A mix-up finding is proved only when the authorization response carries an iss value that is not the issuer of the authorization server the client sent the request to, and the resulting code is then accepted by a token endpoint belonging to that other issuer.**

Run the flow twice against two authorization servers you control, A (the honest one, whose issuer is https://a.example) and B (the attacker-registered one, issuer https://b.example). Send the authorization request to A with redirect_uri set to the callback, and observe whether the callback receives code=...&state=... with no iss parameter at all. That absence is the first half of the evidence, because RFC 9207 states the baseline authorization response carries no information about which authorization server issued it, so the client cannot tell an honest response from one routed to it by a hostile server. To complete the test, take the code obtained in the attacker-routed flow and redeem it at B's token endpoint with the code_verifier you generated for that flow: if B issues an access token, the code and the verifier are now bound to B, and a client that blindly posts to whatever endpoint it was sent to has handed B the credentials. The pass condition is the iss mismatch, observed as an iss value in the callback that is https://b.example while the request went to A - or no iss value at all on an AS that publishes authorization_response_iss_parameter_supported: true. Record the exact callback query string, not a screenshot of a rendered page.

*Disproof:* The claim is false when the callback's iss value is identical to the issuer of the authorization server the request was actually sent to, or when the single-AS client never receives a response from a server other than the one it addressed - RFC 9207 states plainly that a client talking to only one authorization server is not vulnerable to mix-up attacks. It is also false if the client rejects the response on mismatch, which is the required behaviour: comparison by simple string comparison, and rejection of the authorization response with no further grant processing when it does not match. A third disproof is a rediscovery: if the iss the client compares against came from a discovery document an attacker also controls, the comparison is worthless, so an impersonating discovery document whose issuer Claim is the honest OP's issuer but whose endpoints and signing keys are the attacker's is itself the finding, not a mitigation.

**Code interception is only proved when an authorization code obtained without ever seeing the victim's code_verifier is successfully exchanged at the token endpoint, which happens if and only if the server either recorded no code_challenge or silently accepted a plain or substituted one.**

The discriminating request is the redemption, not the authorization URL. Capture a code from a flow you initiated against the client's own authorization request (begin the flow in your own browser, let the AS issue the code, then intercept the callback so you hold code but never the verifier) and POST that code to the token endpoint with grant_type=authorization_code, the client_id, the same redirect_uri, and a code_verifier you generated yourself. Success - HTTP 200 with an access_token - means the server verified nothing about the verifier, because a correct server recomputes the challenge from the received verifier and compares it to the one associated with the code, and any verifier you made up fails that comparison. Then run the negative control that separates 'no PKCE' from 'PKCE with a downgrade': replay the same request with code_challenge_method=plain and a code_verifier equal to a challenge you can predict from the authorization request, because a server that honours plain accepts code_verifier == code_challenge with no hashing at all. A third variant is challenge substitution - substitute your own challenge in the victim's authorization request and redeem with your own matching verifier, which defeats PKCE even when the challenge was present and honoured. Log the token endpoint status code and the response body keys for each of the three.

*Disproof:* The claim is false whenever the redemption fails with invalid_grant or an equivalent error, which is the required behaviour when the values are not equal. It is also false where the client is confidential and its code is bound to a client_secret, since an interceptor holding only the code cannot authenticate the redemption at all, and where the code is single-use and invalidated on first redemption, so the interception race is closed independently of PKCE. Native clients are explicitly required to implement PKCE and servers to support it, so on a native-app flow a redemption that succeeds without the verifier is a real server-side defect, whereas on a legacy implicit or resource-owner-password flow the absence of a code_challenge is by design and is not this finding.

**Cross-tenant token confusion is proved when a token whose aud names resource A is presented to the resource server for resource B and B returns the protected data instead of rejecting it, which can only happen if B skipped the aud check entirely rather than merely checking it loosely.**

Build the pair of APIs first, because a single API cannot demonstrate this. Mint token T1 normally against resource A (authorize with resource=https://a.example or the audience-specific scope) and decode the payload: aud contains A's identifier and not B's. Then replay the identical bearer header against B's protected endpoint - /me, /orders, anything behind a single-tenant boundary. The three outcomes separate cleanly. Rejection with invalid_token or 401 is the pass condition, and it is the behaviour the JWT access token profile requires of a resource server. A 200 with B's real data is the finding, and the reportable artefact is the decoded aud value paired with the successful B response, because that pairing shows the token was never for B. The 200-with-empty-body case is the ambiguous one: it usually means B validated the token's signature and issuer but never checked aud, so re-run against a B endpoint that returns object data rather than a liveness ping, and compare against a token minted for a third unrelated audience to rule out that B simply ignores identity. Decode and record iss, aud, sub, exp and scope for every token used.

*Disproof:* The claim is false if B rejects the token, and it is also false if the aud claim in T1 in fact names both resources - a token whose audience legitimately includes B is a correctly scoped token, not a confused one, and the multi-audience case is exactly what the resource indicator mechanism produces when a client requests several resources in one authorization. It is further false when the successful B response returns only data B would serve to any authenticated principal with no per-tenant content in it, since that is an authorization gap in B rather than a token-validation failure, and belongs to a different class. Finally, if B's boundary is enforced downstream of the API by a gateway that does check aud, an API-layer 200 does not demonstrate attacker-reachable confusion and must be re-tested at the layer that actually makes the authorization decision.

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
  - <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/346.html>
  - <https://cwe.mitre.org/data/definitions/565.html>
- **elastic.co** (research)
  - <https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md>
  - <https://kathan19.gitbook.io/howtohunt/saml/saml.md>
- **openid.net** (writeup)
  - <https://openid.net/specs/openid-connect-core-1_0.html>
  - <https://openid.net/specs/openid-connect-discovery-1_0.html>
- **portswigger.net** (cheatsheet)
  - <https://portswigger.net/web-security/oauth>
- **redcanary.com** (research)
  - <https://redcanary.com/blog/threat-detection/oauth-app-attacks/>
- **rfc-editor.org** (writeup)
  - <https://www.rfc-editor.org/rfc/rfc6749.html>
  - <https://www.rfc-editor.org/rfc/rfc7636.html>
  - <https://www.rfc-editor.org/rfc/rfc7636.txt>
  - <https://www.rfc-editor.org/rfc/rfc8252.html>
  - <https://www.rfc-editor.org/rfc/rfc9068.html>
  - <https://www.rfc-editor.org/rfc/rfc9207.html>
  - <https://www.rfc-editor.org/rfc/rfc9700.html>
  - <https://www.rfc-editor.org/rfc/rfc9700.txt>
- **wiz.io** (research)
  - <https://www.wiz.io/blog/detecting-malicious-oauth-applications>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
