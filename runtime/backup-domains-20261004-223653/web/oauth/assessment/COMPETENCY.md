# Methodology — OAuth 2.0 / OIDC Misconfiguration

> Derived from 27 verified items. Regenerate with `python -m wks.methodgen --class oauth --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The authorization server or client accepts a redirect, scope, token audience or PKCE flow that it should reject.

**References.** CWE-346 · API8:2023

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**OAuth is only attackable where a live authorization endpoint accepts client_id, redirect_uri and response_type; nothing to hunt if that first hop never appears.**

Proxy the social/SSO login, then filter for GET /authorize or /oauth/authorize. Confirm client_id, redirect_uri, response_type, scope, state are echoed in the query string. Also fetch /.well-known/openid-configuration and /.well-known/oauth-authorization-server on that host to enumerate endpoints, response_types_supported and code_challenge_methods_supported before touching anything.

- *Disproof:* No authorization request with OAuth-specific query parameters appears anywhere in the flow; login is plain password/OIDC-less form auth.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

**Code interception is only exploitable when the client is public (SPA/mobile) or PKCE is not enforced; a confidential client with client_secret + PKCE blocks redemption of a stolen code.**

Determine client type: does the bundle or app contain a client_secret (public client), or is it a server-side confidential client? Then check whether the authorization request carries code_challenge with method S256. RFC 9700 requires PKCE for public clients and code_verifier enforcement at /token whenever code_challenge was sent. No code_challenge anywhere = interception/injection path open.

- *Disproof:* Authorization request always sends code_challenge=S256 and the token endpoint rejects a redemption without the matching code_verifier.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.**

Only the front-channel legs of the authorization code flow appear in the proxy: the code-for-access-token exchange and the subsequent API calls run back-end and are never observed, so the flow must be identified from response_type=code plus an authorization code parameter on the /callback request.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

- *Disproof:* Seeing the token request or the API calls in captured traffic shows they are front-channel and refutes the assumption that this leg is server-side only.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/565.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.txt)

**The authorization request URL itself is the recon artifact: its parameters reveal client_id, redirect_uri, response_type, scope and whether state/nonce are used.**

Capture the full GET /authorization?client_id=...&redirect_uri=...&response_type=...&scope=...&state=... line. Absence of state or nonce is the loudest signal. Identify the provider from the Host header, then pull /.well-known/openid-configuration for the full endpoint list and supported grant/response types.

- *Disproof:* The authorization request is a POST-only or fully server-side flow with no browser-visible query parameters and no third-party AS.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth)

**A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.**

A front-channel GET to the /authorization endpoint carrying response_type=code, followed by a redirect of the user to the registered redirect_uri after consent, is how a hunter confirms the client is using the authorization code grant and captures the endpoints to attack.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

- *Disproof:* If the authorization request uses a different response_type, or no /authorization request and provider redirect are captured at all, this flow signature does not identify the grant in use.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/565.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.txt)

**response_type=token still being honoured, or a client_secret shipped inside an SPA/mobile bundle, means tokens and client credentials are exposed by design.**

Flip response_type=code to response_type=token on a live authorization request; if the AS returns #access_token= in the fragment the implicit grant is enabled and the front channel is your exfil path. Separately grep JS bundles, apk smali and .env files for client_secret / clientSecret alongside client_id - a secret in a public bundle makes the client effectively public.

- *Disproof:* response_type=token is rejected with unsupported_response_type, and no client_secret exists in any client-side artifact.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

**In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.**

In the authorization code grant the credential is handed over in the front-channel redirect, arriving as a query parameter on the redirect_uri, so it is visible in proxy history and server logs rather than kept server-side.

HackTricks reference: oauth 2.0 hunting methodology (https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md)

- *Disproof:* A callback that delivers the code outside the query string means the code is not exposed in the captured GET request.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/565.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/oauth/oauth-2.0-hunting-methodology.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.txt)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An authorization request with no state/nonce lets an attacker pre-initiate the flow and bind the victim's client-side session to the attacker's AS identity.**

Start an authorization request from your own browser with your own account and no state, then serve the resulting callback URL as a link/auto-submit form to the victim. If the client logs the victim in as you (or links your social account to their profile), that is forced account linking / login CSRF. Same shape without state: strip the code parameter or swap it for an attacker code to inject a session.

- *Disproof:* A random, single-use state bound to the user agent is present and the callback rejects any state the client did not issue for that browser session.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/346.html); [portswigger.net](https://portswigger.net/web-security/oauth)

**Redirect URI allowlists are bypassable via prefix/duplicate/localhost tricks, path traversal on the callback path, or a dangling wildcard subdomain.**

Baseline redirect_uri=https://client.example/cb, then mutate: append path/query/fragment; try https://client.example.evil.tld, duplicate ?redirect_uri=cb&redirect_uri=evil.tld, localhost.evil.tld, client.example@evil.tld. Then /authorized/callback/../evil and /oauth/callback/../../example/path - back-ends normalise the path and serve another page on the whitelisted host that leaks the query string. For https://*.client.example/* patterns hunt an unclaimed CNAME subdomain.

- *Disproof:* Every mutated redirect_uri outside the exact registered string is rejected (invalid_redirect_uri / 400), Location always stays on the registered host, and no dangling subdomain exists.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/346.html); [portswigger.net](https://portswigger.net/web-security/oauth)

**Adding scope= to the /token exchange or to /userinfo returns a token with more privilege than the user ever consented to.**

Register your own client, run a normal openid email authorization, then re-POST /token adding &scope=openid%20email%20profile. If the JSON access_token response echoes a scope wider than the consented one, the AS ignored the stored scope. Same test on the implicit path: call /userinfo with the stolen bearer token plus an extra scope= parameter and read back fields you were never granted.

- *Disproof:* Both exchanges return invalid_scope, or the issued token's scope claim equals exactly the consented scope.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth)

**Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.**

Base64 in a SAML message is an encoding and not a protection, so a captured assertion decodes in one step and exposes the identity claims it carries for tampering analysis.

HackTricks reference: saml (https://kathan19.gitbook.io/howtohunt/saml/saml.md)

- *Disproof:* An assertion that is genuinely encrypted rather than base64-encoded, or a capture that never exposes the message, cannot be read by decoding it.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/565.html); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/saml/saml.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc7636.html)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Reporting a missing mix-up defence on a single-issuer client is a false positive, because RFC 9700 states the defence is only required when the client interacts with two or more authorization servers.**

Mix-up attacks need a client that federates. RFC 9700 conditions the requirement on that topology: when an OAuth client can only interact with one authorization server, a mix-up defence is not required; where a client interacts with two or more, clients MUST prevent mix-up attacks. This is a valuable fp_rule because the report is easy to write from a code read and impossible to demonstrate from HTTP behaviour alone - you would need to stand up a second authorization server and convince the client to route a response through it. When the topology does hold, the required defence is concrete: for each authorization request the client stores the issuer it sent the request to and binds that to the user agent, and on receipt of the response compares the received issuer identifier against the stored one, aborting on mismatch. That comparison is the observable - an authorization response carrying an iss different from the one the request went to, accepted without abort.

- *Disproof:* The claim is false when the client does federate even if only one server is reachable during the test - a mobile or multi-tenant app with a configurable issuer list, an aggregator that brokers several identity providers, or a client whose issuer list is set from configuration the tester cannot see, all require the defence and can be misreported as single-issuer. It also fails as an assessment where the issuer identifier is unavailable: RFC 9700 contemplates that and points to alternative binding strategies, so the absence of an iss response parameter alone is not proof the client is unprotected. And a client that sends the issuer as an extra parameter and pins the response to it satisfies the requirement even without RFC 9207.
- *Evidence:* high_confidence — [openid.net](https://openid.net/specs/openid-connect-core-1_0.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.txt)

**Scope escalation is proven by replaying the upgraded token against a resource you were never granted, not by observing a wider scope string in the response.**

After the upgraded exchange, call the resource server with the token and request a field behind the extra scope (e.g. GET /userinfo returns address/phone, or GET /api/v2/... returns data outside the consented scope). Also replay the same token against a second audience/API host - if a token minted for audience A is accepted by audience B, audience validation is missing and the finding is real.

- *Disproof:* Every out-of-scope field and every secondary audience returns 403/invalid_scope, or the response scope equals the consented scope exactly.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth)

**Account takeover is proven only when the victim's browser session is bound to the attacker's AS identity, not merely when a code was observed.**

Run the full flow with your own AS account as the victim stand-in: send the tampered authorization request, approve as yourself, and let the victim's browser (clean session) hit the redirect_uri. Then load the client application homepage and confirm the displayed account is your attacker identity. Note that state/nonce protection is useless here because the attacker generated those values from their own browser.

- *Disproof:* The victim's session resolves to their own pre-existing identity, or the client rejects the callback and never issues a session cookie.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A redirect_uri allowlist entry must match the host EXACTLY: example.com does not permit evil-example.com, example.com.evil.tld, or example.com@evil.tld.**

Before reporting redirect_uri manipulation, confirm the code actually landed on a host you control: capture the 302/303 Location and the follow-up request to your listener. If the AS rejected every out-of-allowlist host with invalid_redirect_uri, or the only accepted variants stay on the registered host, the finding is a scanner artefact - exact string matching is the required behaviour per BCP 240.

- *Disproof:* A victim-simulated authorization request returns Location pointing to an attacker-controlled domain carrying code= or access_token=.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/346.html); [portswigger.net](https://portswigger.net/web-security/oauth); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

**Registering a wildcard redirection URI pattern is a configuration weakness worth reporting once, but it is not proof of account takeover - the pattern has to actually match an attacker-controlled origin and the authorization server has to honour the match.**

A wildcard pattern such as https://*.somesite.example/* looks alarming in a client registration and is routinely reported as 'redirect_uri bypass'. The test that distinguishes a real finding from a configuration smell is whether a URL under an origin the attacker controls satisfies the pattern and is accepted by the live server. The comparison the server performs is the only thing that matters, and RFC 9700's position is that pattern matching is inherently risky to implement and manage correctly - it explicitly advises simplifying to exact matching instead, with a single exception for native apps using a localhost URI, where variable port numbers must be allowed. So the correct framing for a report is: the pattern is broader than necessary per that guidance, AND separately, here is the request the server accepted that it should not have. If you cannot get the server to accept a foreign origin, the finding is the configuration risk, not a demonstrated credential leak.

- *Disproof:* The claim is false when the wildcard is scoped to a domain the attacker cannot obtain an origin under, or when the pattern syntax the tester assumes is not the syntax the server implements - a regex-based matcher, a strict host-suffix check, or a literal-string comparison that happens to contain an asterisk. It is also false as an account-takeover claim when the authorization server detects the mismatch and shows the user rather than redirecting, which RFC 9700 describes as a legitimate response: it SHOULD only automatically redirect if it trusts the redirection URI, and MAY inform the user otherwise. And a third-party consent screen showing the real client name to the user is a mitigating layer, not a control the attacker can be assumed to defeat.
- *Evidence:* high_confidence — [openid.net](https://openid.net/specs/openid-connect-core-1_0.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.txt)

**A 'successful' takeover that only reproduces because your own session was already logged in, or tokens in localStorage without demonstrable XSS, is not a finding.**

Re-run every proof in a clean browser profile with no pre-existing cookies: a takeover demo that depends on your authenticated session is invalid. Likewise a token sitting in localStorage is only reportable as a chain when you separately demonstrate script execution on the same origin (a working XSS or an injected script reading it); HttpOnly cookies cannot be read by XSS, so token storage alone is not the impact.

- *Disproof:* The same result reproduces in an incognito session with no cookies, or no script-execution primitive exists on the origin holding the token.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**The authorization server can enforce exact redirect_uri matching perfectly and still leak the code, because browsers reattach the URL fragment to a Location redirect that contains no fragment of its own.**

This is the highest-value OAuth bypass in the corpus because it survives a control that testers usually treat as decisive. RFC 9700 walks it through: the attack combines the client acting as an open redirector with the user agent's fragment-reattachment behaviour, and it circumvents even very narrow redirection URI patterns but not strict URL matching. The mechanics: the registered pattern permits query parameters on the callback, the callback host exposes a redirect_to-style endpoint, and because that endpoint's 303 Location header carries no fragment, the browser reattaches the original #access_token to the attacker's URL. That is why the guidance tells web servers hosting redirection URIs not to expose open redirectors at all, and separately offers the defensive trick of appending an arbitrary fragment identifier such as #_ to Location headers so the browser will not reattach. When you find a wildcard callback, hunt the callback host for a redirector before concluding the wildcard is harmless.

- *Disproof:* The claim does not apply to the authorization code flow, because the code is delivered in the query string rather than the fragment and the attacker cannot redeem it without the client secret or the PKCE verifier - RFC 9700 lists binding the code to a confidential client or PKCE challenge among the countermeasures that stop this attack. It also fails against strict exact redirect_uri matching, which the document explicitly states is not circumvented, and against servers that attach a fragment to their own Location headers. And it needs the precondition of a reachable open redirector on the same host as the registered callback, which is a separate finding that must be demonstrated, not assumed.
- *Evidence:* high_confidence — [openid.net](https://openid.net/specs/openid-connect-core-1_0.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.txt)

**Even strict redirect_uri matching can be bypassed via mix-up attacks, open-redirect chain with fragment reattachment, or trailing path traversal on the callback path.**

Mix-up: client talks to two AS - if the client never checks iss in the authorization response or the ID Token, send the code from the honest AS to your own AS token endpoint. Fragment trick: a strict redirect_uri plus a client-side open redirect still leaks tokens, because a Location header without a fragment makes the browser reattach #access_token=. Traversal: /cb/../evil still resolves on the allowed host and can leak the code.

- *Disproof:* The client validates iss on every authorization response, and every redirect_uri outside the exact registered string - including traversal forms - is rejected outright.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An OAuth consent grant captured or induced for an over-scoped application hands the attacker a durable token-bearing principal whose scopes outlive the login that produced it, turning a single authorization event into persistent application access.**

Consent is the pivot of the chain, not the login. Consent governs whether the app can receive an authorization code and what scopes are permitted, so the security question is never how strong the authentication was but which scopes the application was permitted to obtain. An application is authorized to act on behalf of a signed-in user constrained only by the scopes the app requests and the user or admin consents to. Research across vendors converges on OAuth applications in Entra ID being a common persistence and privilege escalation mechanism, because once the consent exists the application keeps operating against the user's data without further prompts. Chained to authorization-code interception on a permissive redirect and to forged-token acceptance, the grant becomes standing account access rather than a one-shot token theft.

- *Disproof:* Refuted if the tenant enforces admin-consent for the granted scopes and the authorization server binds the issued token to a client certificate or device identity the attacker does not hold; a stolen code alone then cannot be redeemed.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection); [wiz.io](https://www.wiz.io/blog/detecting-malicious-oauth-applications)

**An OAuth open redirect on the callback path, chained with implicit/fragment flows, escalates a low-severity redirect bug into token theft and account takeover.**

Chain: (1) find redirect_to=/?url= open redirect on the whitelisted client host, (2) register/confirm implicit or response_mode=fragment is enabled, (3) craft redirect_uri=https://client.example/cb&redirect_to=https://evil.tld so the AS's 303 passes validation, (4) the client 303s without a fragment and the browser reattaches #access_token= to evil.tld. Token theft -> impersonation on every client registered with that AS.

- *Disproof:* No open redirect exists on the callback host and fragment response_mode is refused, so nothing is ever forwarded to an external domain.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9700.html)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**An OAuth application authorized on behalf of a signed-in user inherits exactly the scopes the user or admin consented to, so an over-scoped grant is a standing application principal whose authority is bounded by nobody reviewing it again.**

The impact statement follows from how delegated authorization is defined rather than from any single exploit. An application is authorized to act on behalf of a signed-in user constrained by the scopes permissions the app requests and the user or admin consents to, and consent governs both whether an authorization code is issued and which scopes are permitted. Because the grant is evaluated once and then persists, the effective privilege of a compromised or malicious application is decided at consent time by a user who cannot enumerate the permission list. Two behaviours compound this: user-consentable scopes such as mail.read or offline_access can be granted by an ordinary user with no administrator in the loop, and an offline_access grant yields refresh-token durability that outlives the session. Detection therefore has to treat an unexpected consented application as a credential-compromise signal rather than as an application-inventory record.

- *Disproof:* Refuted when every sensitive scope requires administrator consent and is reviewed before grant, or when the tenant revokes existing grants automatically when a sign-in event looks anomalous; then the application never retains a durable principal.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/entra-id-oauth-phishing-detection); [redcanary.com](https://redcanary.com/blog/threat-detection/oauth-app-attacks/)

**A leaked OAuth code or access token yields login as the victim on every client application registered with that authorization server, not just the target.**

Impact statement for the report: with a valid code (public client) or bearer token the attacker logs in as the victim, reads the profile/email scopes, and acts in the victim's context on any other relying party sharing the AS. With implicit, the token also works directly against the resource server's API, exposing data the client UI never shows. State the concrete data set reached, not just 'token leaked'.

- *Disproof:* The stolen artifact is single-use, audience-bound, short-lived and yields no authenticated session or API data beyond the attacker's own account.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/oauth)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
