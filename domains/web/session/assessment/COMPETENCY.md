# Methodology — Session Management Flaws

> Derived from 12 verified items. Regenerate with `python -m wks.methodgen --class session --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Session identity, lifetime or binding is weaker than the operation's risk requires.

**References.** CWE-384 · A07:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A session cookie must be revalidated server-side on every request that relies on it, so any endpoint that acts on the cookie without a lookup or signature check sits outside the session boundary and is a session-trust defect on its own.**

Take the captured session cookie and hit one authenticated endpoint twice: once with the cookie, once with the cookie header removed entirely, and compare status codes and bodies byte-for-byte. A correct deployment returns 200 then a 401 or a 302 to login, because validation happens per request and a failed cookie sends the client back to the authorization endpoint. Okta's own session guidance states the server should validate the cookie before processing any request on it, and Auth0's cookie flow shows the 302 raised specifically on unsuccessful cookie validation, which is the observable to look for. Record the exact status code and Location header in both cases.

- *Disproof:* The claim fails if a cached or CDN-fronted response returns the same 200 body with no cookie because it was served from cache rather than a session lookup, or if the endpoint is deliberately public and returns identical bytes to an authenticated user. Both are artefacts of the test, not a missing validation.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies); [developer.okta.com](https://developer.okta.com/blog/2021/06/16/session-mgmt-react)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A session identifier that is a self-contained JWT keeps serving the claims captured at issuance, so a role or entitlement revoked server-side is still honoured in the session until the token expires; staleness shows up as a user retaining access they were demonstrably stripped of.**

Sign in as a test user and capture the session or access token, then decode the payload and note every authorization claim (roles, groups, plan, tenant). Have an administrator revoke the user's role or disable the account, confirm the revocation landed in the admin or IdP view, then replay the exact original request with the original token untouched. If it still returns 200 with the revoked privilege reflected in the response body, the session is carrying stale authorization. Okta's guidance that the information inside a JWT is a snapshot in time, and that a JWT cannot be revoked, is the mechanism you are testing for rather than assuming.

- *Disproof:* The finding collapses if the replayed request was rejected, if the server re-derives authorization from live server-side session state rather than from the token claims, or if the revocation never actually took effect and the account is still enabled server-side, leaving no staleness to observe.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/); [developer.okta.com](https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Session termination is only proven by replaying the pre-logout session value against a protected endpoint after logout and observing that it no longer authenticates; a redirect to a login page in the UI is not evidence that the server-side record was destroyed.**

Two-phase test. Phase one: sign in, copy the exact Cookie header, and confirm it authenticates by replaying it and recording a 200. Phase two: sign out through the UI in the same browser, capture the new cookie value the server set, then replay the OLD pre-logout Cookie value in a request carrying no other credential. Interpret the result strictly: a 200 with authenticated content means logout cleared the browser jar but left the server-side session alive, so any captured or stolen value still works. Auth0's cookie flow makes the failure mode concrete because the cookie is the sole credential traded on each API call, so nothing else in the request can have saved the deployment.

- *Disproof:* The test is invalid if the replayed request was sent from a browser whose own cookie jar the server could read implicitly, if a CDN served a cached authenticated body, or if logout in this deployment is by design client-side only with a short session lifetime you have not accounted for.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies); [developer.okta.com](https://developer.okta.com/blog/2021/06/16/session-mgmt-react)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Replay of an identity token is only defeated when the client compares the token's nonce claim against the value it persisted for the request it initiated and rejects the response when they differ; identical nonce values across two distinct authentication requests prove the check is absent.**

Drive two separate authentication requests (two fresh login attempts, or two authorize round-trips) and record the nonce parameter sent on each. Decode the returned ID tokens and compare each token's nonce claim to what you sent. The negative control matters: capture one token from request A and submit it in place of request B's response. Auth0's procedure is explicit that the nonce claim must contain the exact value sent and that a mismatch means authentication should be rejected, so a server that accepts the substituted token has no replay defence. Record both nonce values and the token that was accepted to prove the substitution.

- *Disproof:* The claim fails if the server rejects the substituted token, if the token carries no nonce claim because the flow never used one (the defence is then absent but a one-time authorization code or PKCE may protect the flow), or if the two observed nonces were genuinely distinct and each token matched its own request.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post/mitigate-replay-attacks-when-using-the-implicit-flow); [developer.okta.com](https://developer.okta.com/blog/2022/07/19/angular-security-csrf)

**Fixation is proved by a two-step pair: capture an unauthenticated session identifier, complete a real login carrying that identifier, then replay that exact same identifier against an authenticated-only endpoint and record a 200 rather than a redirect to login.**

Mechanism: Fixation is proved by a two-step pair: capture an unauthenticated session identifier, complete a real login carrying that identifier, then replay that exact same identifier against an authenticated-only endpoint and record a 200 rather than a redirect to login. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the post-login replay returns 302 to the login page or a 401, the identifier was rotated at privilege elevation and no fixation exists; if the identifier could not be planted at all (the server issued it server-side and never echoed a chosen value), there is nothing to replay and the technique does not apply.

- *Disproof:* If the post-login replay returns 302 to the login page or a 401, the identifier was rotated at privilege elevation and no fixation exists; if the identifier could not be planted at all (the server issued it server-side and never echoed a chosen value), there is nothing to replay and the technique does not apply.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/secrets.html); [php.net](https://www.php.net/manual/en/session.configuration.php)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A session cookie missing Secure, HttpOnly or SameSite is not itself an exploitable session defect; the finding only survives when a test demonstrates an attacker-reachable path that actually uses the weakness, such as script on the same origin reading the value or a cross-site request that still attaches it.**

Before reporting, run three separate checks and record each result. One: read the cookie back with document.cookie on the origin; a null result means HttpOnly is genuinely enforced and the exfiltration chain does not exist. Two: issue a cross-site form POST or fetch from an attacker page and inspect the Cookie header the browser attached; a withheld cookie means SameSite is doing its job for that request type. Three: request the same path over plain http:// and see whether the cookie is sent at all. Okta's reference configuration sets HttpOnly and a Secure policy explicitly and documents what each attribute buys, which is the baseline to compare against, not a finding in itself.

- *Disproof:* It becomes exploitable when document.cookie on a same-origin XSS returns the session value and that value replays into an authenticated request, when the app serves any HTTP endpoint that receives the cookie, or when a SameSite=None cookie without Secure is accepted so a cross-site request still carries it. If none of those hold, downgrade the report to hardening.
- *Evidence:* high_confidence — [auth0.com](https://auth0.com/docs/manage-users/cookies/samesite-cookie-attribute-changes); [developer.okta.com](https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens)

**Seeing a session identifier in server logs, a referrer, or an unauthenticated page does not constitute session hijack; the finding only exists once the identifier is shown to still authenticate a request for a protected resource when replayed.**

Mechanism: Seeing a session identifier in server logs, a referrer, or an unauthenticated page does not constitute session hijack; the finding only exists once the identifier is shown to still authenticate a request for a protected resource when replayed. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It becomes hijack when the leaked identifier is replayed in a Cookie header and returns 200 on an authenticated page; it is not hijack when the identifier has already expired server-side, was rotated at login, or the leaked page was never behind authentication, in which case the exposure is at most an information-disclosure or logging-hygiene issue.

- *Disproof:* It becomes hijack when the leaked identifier is replayed in a Cookie header and returns 200 on an authenticated page; it is not hijack when the identifier has already expired server-side, was rotated at login, or the leaked page was never behind authentication, in which case the exposure is at most an information-disclosure or logging-hygiene issue.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/http.server.html); [php.net](https://www.php.net/manual/en/session.configuration.php)

**A session handler that silently adopts an arbitrary client-supplied session identifier is only vulnerable to fixation if that adopted identifier is still honoured after the victim authenticates; a handler in strict mode instead mints a fresh identifier for an unrecognised value and is not vulnerable regardless of what the attacker seeds.**

Mechanism: A session handler that silently adopts an arbitrary client-supplied session identifier is only vulnerable to fixation if that adopted identifier is still honoured after the victim authenticates; a handler in strict mode instead mints a fresh identifier for an unrecognised value and is not vulnerable regardless of what the attacker seeds. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS fixation when the adopted pre-auth identifier is replayed post-auth and returns a 200 on an authenticated-only page; it is NOT vulnerable when strict mode is on and the server issues a new ID for an uninitialized incoming ID, because the attacker's value never becomes the authenticated session.

- *Disproof:* It IS fixation when the adopted pre-auth identifier is replayed post-auth and returns a 200 on an authenticated-only page; it is NOT vulnerable when strict mode is on and the server issues a new ID for an uninitialized incoming ID, because the attacker's value never becomes the authenticated session.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/secrets.html); [php.net](https://www.php.net/manual/en/session.configuration.php)

**A session identifier appearing in a URL or response on a non-login, unauthenticated page is not session fixation or session hijack: fixation requires the identifier to survive privilege elevation and remain usable for an authenticated resource, otherwise it is at most anonymous session tracking.**

ZAP's session-fixation guidance states the two cases explicitly, and only one of them is a vulnerability: on a login URL the attacker can hand the victim a fixed session id and later assume their identity, while on a non-login page the same URL and fixed id let the attacker track an unauthenticated user's actions. Take the identifier from the flag, drive it through a real login, and then fetch a resource that requires authentication. CAPEC-61 frames the precondition the same way: the attack works because the target either relies on client-generated session identifiers or keeps the same identifier after privilege elevation. If the identifier is rejected at the login boundary, or the page never authenticates anyone, the hunt ends there.

- *Disproof:* It IS fixation if the identifier still authenticates after login (issue it pre-auth, complete a real login with it, then fetch a page that requires authentication and show 200), or if it is set on a login page and accepted unchanged at privilege elevation. The test is reuse-after-login, not presence in the URL.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/61.html); [zaproxy.org](https://www.zaproxy.org/docs/alerts/40013-4/)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**The defence against session-token guessing is the unpredictability of the token rather than any lockout on the identifier, so the bypass question is whether the token space is large enough that online guessing is infeasible, and the way to defeat it is to find a generator that produces guessable or low-entropy identifiers.**

Mechanism: The defence against session-token guessing is the unpredictability of the token rather than any lockout on the identifier, so the bypass question is whether the token space is large enough that online guessing is infeasible, and the way to defeat it is to find a generator that produces guessable or low-entropy identifiers. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the identifier is derived from a cryptographically strong generator with at least 128 bits of entropy, guessing is computationally infeasible regardless of lockout absence; if the identifier is a monotonically increasing counter, a visible timestamp, or a hash of user-controlled public data, the entropy claim fails and the class is exploitable.

- *Disproof:* If the identifier is derived from a cryptographically strong generator with at least 128 bits of entropy, guessing is computationally infeasible regardless of lockout absence; if the identifier is a monotonically increasing counter, a visible timestamp, or a hash of user-controlled public data, the entropy claim fails and the class is exploitable.
- *Evidence:* high_confidence — [docs.python.org](https://docs.python.org/3/library/secrets.html); [php.net](https://www.php.net/manual/en/session.configuration.php)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
