# Session Management Flaws

## Definition

Session identity, lifetime or binding is weaker than the operation's risk requires.

- **CWE:** 384
- **OWASP:** A07:2021
- **Surface:** identity
- **Aliases:** ["session fixation", "session management", "cookie flags", "session hijacking"]

Canonical home for `session`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A session cookie must be revalidated server-side on every request that relies on it, so any endpoint that acts on the cookie without a lookup or signature check sits outside the session boundary and is a session-trust defect on its own.**

Take the captured session cookie and hit one authenticated endpoint twice: once with the cookie, once with the cookie header removed entirely, and compare status codes and bodies byte-for-byte. A correct deployment returns 200 then a 401 or a 302 to login, because validation happens per request and a failed cookie sends the client back to the authorization endpoint. Okta's own session guidance states the server should validate the cookie before processing any request on it, and Auth0's cookie flow shows the 302 raised specifically on unsuccessful cookie validation, which is the observable to look for. Record the exact status code and Location header in both cases.

*Disproof:* The claim fails if a cached or CDN-fronted response returns the same 200 body with no cookie because it was served from cache rather than a session lookup, or if the endpoint is deliberately public and returns identical bytes to an authenticated user. Both are artefacts of the test, not a missing validation.

## Attack Surface

Surface: **identity**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A session identifier that is a self-contained JWT keeps serving the claims captured at issuance, so a role or entitlement revoked server-side is still honoured in the session until the token expires; staleness shows up as a user retaining access they were demonstrably stripped of.**

Sign in as a test user and capture the session or access token, then decode the payload and note every authorization claim (roles, groups, plan, tenant). Have an administrator revoke the user's role or disable the account, confirm the revocation landed in the admin or IdP view, then replay the exact original request with the original token untouched. If it still returns 200 with the revoked privilege reflected in the response body, the session is carrying stale authorization. Okta's guidance that the information inside a JWT is a snapshot in time, and that a JWT cannot be revoked, is the mechanism you are testing for rather than assuming.

*Disproof:* The finding collapses if the replayed request was rejected, if the server re-derives authorization from live server-side session state rather than from the token claims, or if the revocation never actually took effect and the account is still enabled server-side, leaving no staleness to observe.

**Comparing a session token or secret with a plain string equality operator is a distinct defect from a missing cookie attribute, because it is a server-side timing oracle over attacker-chosen bytes, so a report must quote the comparison site rather than the Set-Cookie header.**

Mechanism: Comparing a session token or secret with a plain string equality operator is a distinct defect from a missing cookie attribute, because it is a server-side timing oracle over attacker-chosen bytes, so a report must quote the comparison site rather than the Set-Cookie header. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the comparison is inside a hash function, a constant-time primitive, or is against a value the attacker cannot vary incrementally (for example a fixed HMAC of a request the attacker cannot modify), there is no timing oracle and the finding collapses to a hardening note.

*Disproof:* If the comparison is inside a hash function, a constant-time primitive, or is against a value the attacker cannot vary incrementally (for example a fixed HMAC of a request the attacker cannot modify), there is no timing oracle and the finding collapses to a hardening note.

## Exploitation

**The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post.**

nitiated (such as clicking on a Login button) 
 The browser client redirects to a /login route on the backend, or to the protected route depending on what the user did 
 The backend constructs a request to the authorization server’s /authorize endpoint and redirects the browser client there 
 The user is prompted to authenticate themselves using whatever method the authorization server presents 
 The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post. The backend is able to retrieve those tokens by parsing the body data. 
 
 At this point, the user is authenticated and the backend has the required tokens. A cookie can now be created to represent this state on the client. The client browser is then redirected to a route that serves the SPA and also receives the authentication cookie. 
 From now on, this cookie is traded between the client and b

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post.".

**The 302 occurs because, upon unsuccessful validation of the cookie, the server tries to redirect to the Authorization endpoint of the authorization server and sends this response to the client.**

ases where the authentication cookie is invalid or missing. The API call to the backend from the client happens in the background, so the client has to deal with any response from the server indicating the user should reauthenticate. 
 In the following sample application, this case is handled in a naive way by prompting the user to re-authenticate if the API call results in a 302 Redirect result. The 302 occurs because, upon unsuccessful validation of the cookie, the server tries to redirect to the Authorization endpoint of the authorization server and sends this response to the client. 
 ​ Example 
 The example application uses Node.js and Express to demonstrate the concepts covered above. 
 ​ Prerequisites 
 
 
 To follow along, make sure you have the  latest version of Node  installed. 
 
 
 Once Node is installed,  download or clone the source code  and open the project folder inside a terminal window. 
 # Clone the tutorial respository using SSH 
 git clone git@github.com:a

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The 302 occurs because, upon unsuccessful validation of the cookie, the server t”) does not occur under a test that isolates that control.

**For the application to work with authentication, express-openid-connect requires some environment variables to be present.**

etects any file changes. 
 ​ Explore the application 
 With the application open at  http://localhost:3000 , click the  Call API  button. You should see a message displayed on the screen. 
 
 Note that you were able to make the API call without being logged in. Let’s fix that by adding some middleware that requires the user to authenticate before the API call can be made. 
 ​ Set up environment 
 For the application to work with authentication, express-openid-connect requires some environment variables to be present. For this application, these variables can be specified in a .env file. Create a .env file in the root of the project directory and populate it with the following: 
 .env ISSUER_BASE_URL = " " 
 CLIENT_ID = " " 
 BASE_URL = "http://localhost:3000" 
 APP_SESSION_SECRET = " " 
 
 ​ Set up app in Auth0 
 
 
 Go to Dashboard > Applications > Applications and click Create Application . 
 
 
 Name your

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For the application to work with authentication, express-openid-connect requires some envi".

**The 302 occurs because, upon unsuccessful validation of the cookie, the server tries to redirect to the Authorization endpoint of the authorization server and sends this response to the client.**

ases where the authentication cookie is invalid or missing. The API call to the backend from the client happens in the background, so the client has to deal with any response from the server indicating the user should reauthenticate. 
 In the following sample application, this case is handled in a naive way by prompting the user to re-authenticate if the API call results in a 302 Redirect result. The 302 occurs because, upon unsuccessful validation of the cookie, the server tries to redirect to the Authorization endpoint of the authorization server and sends this response to the client. 
 ​ Example 
 The example application uses Node.js and Express to demonstrate the concepts covered above. 
 ​ Prerequisites 
 
 
 To follow along, make sure you have the  latest version of Node  installed. 
 
 
 Once Node is installed,  download or clone the source code  and open the project folder inside a terminal window. 
 # Clone the tutorial respository using SSH 
 git clone git@github.com:a

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The 302 occurs because, upon unsuccessful validation of the cookie, the server t”) does not occur under a test that isolates that control.

**For the application to work with authentication, express-openid-connect requires some environment variables to be present.**

etects any file changes. 
 ​ Explore the application 
 With the application open at  http://localhost:3000 , click the  Call API  button. You should see a message displayed on the screen. 
 
 Note that you were able to make the API call without being logged in. Let’s fix that by adding some middleware that requires the user to authenticate before the API call can be made. 
 ​ Set up environment 
 For the application to work with authentication, express-openid-connect requires some environment variables to be present. For this application, these variables can be specified in a .env file. Create a .env file in the root of the project directory and populate it with the following: 
 .env ISSUER_BASE_URL = " " 
 CLIENT_ID = " " 
 BASE_URL = "http://localhost:3000" 
 APP_SESSION_SECRET = " " 
 
 ​ Set up app in Auth0 
 
 
 Go to Dashboard > Applications > Applications and click Create Application . 
 
 
 Name your

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For the application to work with authentication, express-openid-connect requires some envi".

**The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post.**

nitiated (such as clicking on a Login button) 
 The browser client redirects to a /login route on the backend, or to the protected route depending on what the user did 
 The backend constructs a request to the authorization server’s /authorize endpoint and redirects the browser client there 
 The user is prompted to authenticate themselves using whatever method the authorization server presents 
 The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post. The backend is able to retrieve those tokens by parsing the body data. 
 
 At this point, the user is authenticated and the backend has the required tokens. A cookie can now be created to represent this state on the client. The client browser is then redirected to a route that serves the SPA and also receives the authentication cookie. 
 From now on, this cookie is traded between the client and b

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post.".

**Session termination is only proven by replaying the pre-logout session value against a protected endpoint after logout and observing that it no longer authenticates; a redirect to a login page in the UI is not evidence that the server-side record was destroyed.**

Two-phase test. Phase one: sign in, copy the exact Cookie header, and confirm it authenticates by replaying it and recording a 200. Phase two: sign out through the UI in the same browser, capture the new cookie value the server set, then replay the OLD pre-logout Cookie value in a request carrying no other credential. Interpret the result strictly: a 200 with authenticated content means logout cleared the browser jar but left the server-side session alive, so any captured or stolen value still works. Auth0's cookie flow makes the failure mode concrete because the cookie is the sole credential traded on each API call, so nothing else in the request can have saved the deployment.

*Disproof:* The test is invalid if the replayed request was sent from a browser whose own cookie jar the server could read implicitly, if a CDN served a cached authenticated body, or if logout in this deployment is by design client-side only with a short session lifetime you have not accounted for.

## Variations

**The defence against session-token guessing is the unpredictability of the token rather than any lockout on the identifier, so the bypass question is whether the token space is large enough that online guessing is infeasible, and the way to defeat it is to find a generator that produces guessable or low-entropy identifiers.**

Mechanism: The defence against session-token guessing is the unpredictability of the token rather than any lockout on the identifier, so the bypass question is whether the token space is large enough that online guessing is infeasible, and the way to defeat it is to find a generator that produces guessable or low-entropy identifiers. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the identifier is derived from a cryptographically strong generator with at least 128 bits of entropy, guessing is computationally infeasible regardless of lockout absence; if the identifier is a monotonically increasing counter, a visible timestamp, or a hash of user-controlled public data, the entropy claim fails and the class is exploitable.

*Disproof:* If the identifier is derived from a cryptographically strong generator with at least 128 bits of entropy, guessing is computationally infeasible regardless of lockout absence; if the identifier is a monotonically increasing counter, a visible timestamp, or a hash of user-controlled public data, the entropy claim fails and the class is exploitable.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.session.auto.01` — session: observe, exercise, confirm (goal: `Establish, exercise and confirm a session condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A session handler that silently adopts an arbitrary client-supplied session identifier is only vulnerable to fixation if that adopted identifier is still honoured after the victim authenticates; a handler in strict mode instead mints a fresh identifier for an unrecognised value and is not vulnerable regardless of what the attacker seeds.**

Mechanism: A session handler that silently adopts an arbitrary client-supplied session identifier is only vulnerable to fixation if that adopted identifier is still honoured after the victim authenticates; a handler in strict mode instead mints a fresh identifier for an unrecognised value and is not vulnerable regardless of what the attacker seeds. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS fixation when the adopted pre-auth identifier is replayed post-auth and returns a 200 on an authenticated-only page; it is NOT vulnerable when strict mode is on and the server issues a new ID for an uninitialized incoming ID, because the attacker's value never becomes the authenticated session.

*Disproof:* It IS fixation when the adopted pre-auth identifier is replayed post-auth and returns a 200 on an authenticated-only page; it is NOT vulnerable when strict mode is on and the server issues a new ID for an uninitialized incoming ID, because the attacker's value never becomes the authenticated session.

**A session cookie missing Secure, HttpOnly or SameSite is not itself an exploitable session defect; the finding only survives when a test demonstrates an attacker-reachable path that actually uses the weakness, such as script on the same origin reading the value or a cross-site request that still attaches it.**

Before reporting, run three separate checks and record each result. One: read the cookie back with document.cookie on the origin; a null result means HttpOnly is genuinely enforced and the exfiltration chain does not exist. Two: issue a cross-site form POST or fetch from an attacker page and inspect the Cookie header the browser attached; a withheld cookie means SameSite is doing its job for that request type. Three: request the same path over plain http:// and see whether the cookie is sent at all. Okta's reference configuration sets HttpOnly and a Secure policy explicitly and documents what each attribute buys, which is the baseline to compare against, not a finding in itself.

*Disproof:* It becomes exploitable when document.cookie on a same-origin XSS returns the session value and that value replays into an authenticated request, when the app serves any HTTP endpoint that receives the cookie, or when a SameSite=None cookie without Secure is accepted so a cross-site request still carries it. If none of those hold, downgrade the report to hardening.

**A session identifier appearing in a URL or response on a non-login, unauthenticated page is not session fixation or session hijack: fixation requires the identifier to survive privilege elevation and remain usable for an authenticated resource, otherwise it is at most anonymous session tracking.**

ZAP's session-fixation guidance states the two cases explicitly, and only one of them is a vulnerability: on a login URL the attacker can hand the victim a fixed session id and later assume their identity, while on a non-login page the same URL and fixed id let the attacker track an unauthenticated user's actions. Take the identifier from the flag, drive it through a real login, and then fetch a resource that requires authentication. CAPEC-61 frames the precondition the same way: the attack works because the target either relies on client-generated session identifiers or keeps the same identifier after privilege elevation. If the identifier is rejected at the login boundary, or the page never authenticates anyone, the hunt ends there.

*Disproof:* It IS fixation if the identifier still authenticates after login (issue it pre-auth, complete a real login with it, then fetch a page that requires authentication and show 200), or if it is set on a login page and accepted unchanged at privilege elevation. The test is reuse-after-login, not presence in the URL.

**Seeing a session identifier in server logs, a referrer, or an unauthenticated page does not constitute session hijack; the finding only exists once the identifier is shown to still authenticate a request for a protected resource when replayed.**

Mechanism: Seeing a session identifier in server logs, a referrer, or an unauthenticated page does not constitute session hijack; the finding only exists once the identifier is shown to still authenticate a request for a protected resource when replayed. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It becomes hijack when the leaked identifier is replayed in a Cookie header and returns 200 on an authenticated page; it is not hijack when the identifier has already expired server-side, was rotated at login, or the leaked page was never behind authentication, in which case the exposure is at most an information-disclosure or logging-hygiene issue.

*Disproof:* It becomes hijack when the leaked identifier is replayed in a Cookie header and returns 200 on an authenticated page; it is not hijack when the identifier has already expired server-side, was rotated at login, or the leaked page was never behind authentication, in which case the exposure is at most an information-disclosure or logging-hygiene issue.

## Validation

**Replay of an identity token is only defeated when the client compares the token's nonce claim against the value it persisted for the request it initiated and rejects the response when they differ; identical nonce values across two distinct authentication requests prove the check is absent.**

Drive two separate authentication requests (two fresh login attempts, or two authorize round-trips) and record the nonce parameter sent on each. Decode the returned ID tokens and compare each token's nonce claim to what you sent. The negative control matters: capture one token from request A and submit it in place of request B's response. Auth0's procedure is explicit that the nonce claim must contain the exact value sent and that a mismatch means authentication should be rejected, so a server that accepts the substituted token has no replay defence. Record both nonce values and the token that was accepted to prove the substitution.

*Disproof:* The claim fails if the server rejects the substituted token, if the token carries no nonce claim because the flow never used one (the defence is then absent but a one-time authorization code or PKCE may protect the flow), or if the two observed nonces were genuinely distinct and each token matched its own request.

**Fixation is proved by a two-step pair: capture an unauthenticated session identifier, complete a real login carrying that identifier, then replay that exact same identifier against an authenticated-only endpoint and record a 200 rather than a redirect to login.**

Mechanism: Fixation is proved by a two-step pair: capture an unauthenticated session identifier, complete a real login carrying that identifier, then replay that exact same identifier against an authenticated-only endpoint and record a 200 rather than a redirect to login. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the post-login replay returns 302 to the login page or a 401, the identifier was rotated at privilege elevation and no fixation exists; if the identifier could not be planted at all (the server issued it server-side and never echoed a chosen value), there is nothing to replay and the technique does not apply.

*Disproof:* If the post-login replay returns 302 to the login page or a 401, the identifier was rotated at privilege elevation and no fixation exists; if the identifier could not be planted at all (the server issued it server-side and never echoed a chosen value), there is nothing to replay and the technique does not apply.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from session.fp_rule.accepting_a_client_supplied_unknown_id_is_not_fixation_until_it_survives_login, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (session.fp_rule.accepting_a_client_supplied_unknown_id_is_not_fixation_until_it_survives_login) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from session.validation.prove_fixation_by_replaying_the_preauth_id_after_login, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (session.validation.prove_fixation_by_replaying_the_preauth_id_after_login) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from session.fp_rule.session_id_visible_in_logs_or_a_nonauth_page_is_never_by_itself_a_takeover, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (session.fp_rule.session_id_visible_in_logs_or_a_nonauth_page_is_never_by_itself_a_takeover) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from session.bypass.random_token_entropy_is_the_control_and_guessing_is_the_bypass, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (session.bypass.random_token_entropy_is_the_control_and_guessing_is_the_bypass) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **auth0.com** (blog)
  - <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/>
  - <https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post/mitigate-replay-attacks-when-using-the-implicit-flow>
  - <https://auth0.com/docs/manage-users/cookies/samesite-cookie-attribute-changes>
  - <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies>
- **capec.mitre.org** (standard)
  - <https://capec.mitre.org/data/definitions/61.html>
- **developer.okta.com** (blog)
  - <https://developer.okta.com/blog/2021/06/16/session-mgmt-react>
  - <https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens>
  - <https://developer.okta.com/blog/2022/07/19/angular-security-csrf>
  - <https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/>
- **docs.python.org** (writeup)
  - <https://docs.python.org/3/library/hmac.html>
  - <https://docs.python.org/3/library/http.server.html>
  - <https://docs.python.org/3/library/secrets.html>
- **php.net** (writeup)
  - <https://www.php.net/manual/en/function.hash-equals.php>
  - <https://www.php.net/manual/en/session.configuration.php>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/40013-4/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
