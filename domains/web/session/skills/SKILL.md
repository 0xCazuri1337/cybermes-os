---
name: session-hunting
description: Use when hunting Session Management Flaws in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Session Management Flaws — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE 384 · OWASP A07:2021
> evidence: 15 items, 11 supported, 4 FP rules, 1 chains
> maturity: **mature**

Session identity, lifetime or binding is weaker than the operation's risk requires.

**Also called:** session fixation, session management, cookie flags, session hijacking


## Prerequisites (do not start without these)

- A session cookie must be revalidated server-side on every request that relies on it, so any endpoint that acts on the cookie without a lookup or signature check sits outside the session boundary and is a session-trust defect on its own.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim fails if a cached or CDN-fronted response returns the same 200 body with no cookie because it was served from cache rather than a session lookup, or if the endpoint is deliberately public and returns identical bytes to an authenticated user. Both are artefacts of the test, not a missing validation.
  - Sources: <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies> · <https://developer.okta.com/blog/2021/06/16/session-mgmt-react>

## Recon signals (where to look)

- A session identifier that is a self-contained JWT keeps serving the claims captured at issuance, so a role or entitlement revoked server-side is still honoured in the session until the token expires; staleness shows up as a user retaining access they were demonstrably stripped of.  _(merged 1 duplicate row(s))_
  - **Disproof:** The finding collapses if the replayed request was rejected, if the server re-derives authorization from live server-side session state rather than from the token claims, or if the revocation never actually took effect and the account is still enabled server-side, leaving no staleness to observe.
  - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens>

## Techniques (what to change)

- For the application to work with authentication, express-openid-connect requires some environment variables to be present.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For the application to work with authentication, express-openid-connect requires some envi".
  - Sources: <https://capec.mitre.org/data/definitions/61.html> · <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies>
- Session termination is only proven by replaying the pre-logout session value against a protected endpoint after logout and observing that it no longer authenticates; a redirect to a login page in the UI is not evidence that the server-side record was destroyed.  _(merged 1 duplicate row(s))_
  - **Disproof:** The test is invalid if the replayed request was sent from a browser whose own cookie jar the server could read implicitly, if a CDN served a cached authenticated body, or if logout in this deployment is by design client-side only with a short session lifetime you have not accounted for.
  - Sources: <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies> · <https://developer.okta.com/blog/2021/06/16/session-mgmt-react>
- The 302 occurs because, upon unsuccessful validation of the cookie, the server tries to redirect to the Authorization endpoint of the authorization server and sends this response to the client.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The 302 occurs because, upon unsuccessful validation of the cookie, the server t”) does not occur under a test that isolates that control.
  - Sources: <https://capec.mitre.org/data/definitions/61.html> · <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies>
- The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The authorization server POSTs the tokens to the redirect URI as a URL-encoded form post.".
  - Sources: <https://capec.mitre.org/data/definitions/61.html> · <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies>

## Tests

- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (session.validation.prove_fixation_by_replaying_the_preauth_id_after_login) states the full boundary.
  - Sources: <https://docs.python.org/3/library/secrets.html> · <https://www.php.net/manual/en/session.configuration.php>

## Validation bar (how to prove it)

- Fixation is proved by a two-step pair: capture an unauthenticated session identifier, complete a real login carrying that identifier, then replay that exact same identifier against an authenticated-only endpoint and record a 200 rather than a redirect to login.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the post-login replay returns 302 to the login page or a 401, the identifier was rotated at privilege elevation and no fixation exists; if the identifier could not be planted at all (the server issued it server-side and never echoed a chosen value), there is nothing to replay and the technique does not apply.
  - Sources: <https://docs.python.org/3/library/secrets.html> · <https://www.php.net/manual/en/session.configuration.php>
- Replay of an identity token is only defeated when the client compares the token's nonce claim against the value it persisted for the request it initiated and rejects the response when they differ; identical nonce values across two distinct authentication requests prove the check is absent.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim fails if the server rejects the substituted token, if the token carries no nonce claim because the flow never used one (the defence is then absent but a one-time authorization code or PKCE may protect the flow), or if the two observed nonces were genuinely distinct and each token matched its own request.
  - Sources: <https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post/mitigate-replay-attacks-when-using-the-implicit-flow> · <https://developer.okta.com/blog/2022/07/19/angular-security-csrf>

## False-positive rules (when to reject it)

- A session cookie missing Secure, HttpOnly or SameSite is not itself an exploitable session defect; the finding only survives when a test demonstrates an attacker-reachable path that actually uses the weakness, such as script on the same origin reading the value or a cross-site request that still attaches it.  _(merged 1 duplicate row(s))_
  - **Disproof:** It becomes exploitable when document.cookie on a same-origin XSS returns the session value and that value replays into an authenticated request, when the app serves any HTTP endpoint that receives the cookie, or when a SameSite=None cookie without Secure is accepted so a cross-site request still carries it. If none of those hold, downgrade the report to hardening.
  - Sources: <https://auth0.com/docs/manage-users/cookies/samesite-cookie-attribute-changes> · <https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/> · <https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens>
- A session handler that silently adopts an arbitrary client-supplied session identifier is only vulnerable to fixation if that adopted identifier is still honoured after the victim authenticates; a handler in strict mode instead mints a fresh identifier for an unrecognised value and is not vulnerable regardless of what the attacker seeds.  _(merged 1 duplicate row(s))_
  - **Disproof:** It IS fixation when the adopted pre-auth identifier is replayed post-auth and returns a 200 on an authenticated-only page; it is NOT vulnerable when strict mode is on and the server issues a new ID for an uninitialized incoming ID, because the attacker's value never becomes the authenticated session.
  - Sources: <https://docs.python.org/3/library/secrets.html> · <https://www.php.net/manual/en/session.configuration.php>
- A session identifier appearing in a URL or response on a non-login, unauthenticated page is not session fixation or session hijack: fixation requires the identifier to survive privilege elevation and remain usable for an authenticated resource, otherwise it is at most anonymous session tracking.  _(merged 1 duplicate row(s))_
  - **Disproof:** It IS fixation if the identifier still authenticates after login (issue it pre-auth, complete a real login with it, then fetch a page that requires authentication and show 200), or if it is set on a login page and accepted unchanged at privilege elevation. The test is reuse-after-login, not presence in the URL.
  - Sources: <https://capec.mitre.org/data/definitions/61.html> · <https://www.zaproxy.org/docs/alerts/40013-4/>
- Seeing a session identifier in server logs, a referrer, or an unauthenticated page does not constitute session hijack; the finding only exists once the identifier is shown to still authenticate a request for a protected resource when replayed.  _(merged 1 duplicate row(s))_
  - **Disproof:** It becomes hijack when the leaked identifier is replayed in a Cookie header and returns 200 on an authenticated page; it is not hijack when the identifier has already expired server-side, was rotated at login, or the leaked page was never behind authentication, in which case the exposure is at most an information-disclosure or logging-hygiene issue.
  - Sources: <https://docs.python.org/3/library/http.server.html> · <https://www.php.net/manual/en/session.configuration.php>

## Evidence requirements

- Comparing a session token or secret with a plain string equality operator is a distinct defect from a missing cookie attribute, because it is a server-side timing oracle over attacker-chosen bytes, so a report must quote the comparison site rather than the Set-Cookie header.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the comparison is inside a hash function, a constant-time primitive, or is against a value the attacker cannot vary incrementally (for example a fixed HMAC of a request the attacker cannot modify), there is no timing oracle and the finding collapses to a hardening note.
  - Sources: <https://docs.python.org/3/library/hmac.html> · <https://www.php.net/manual/en/function.hash-equals.php>

## Defence bypasses

- The defence against session-token guessing is the unpredictability of the token rather than any lockout on the identifier, so the bypass question is whether the token space is large enough that online guessing is infeasible, and the way to defeat it is to find a generator that produces guessable or low-entropy identifiers.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the identifier is derived from a cryptographically strong generator with at least 128 bits of entropy, guessing is computationally infeasible regardless of lockout absence; if the identifier is a monotonically increasing counter, a visible timestamp, or a hash of user-controlled public data, the entropy claim fails and the class is exploitable.
  - Sources: <https://docs.python.org/3/library/secrets.html> · <https://www.php.net/manual/en/session.configuration.php>


## Hunt procedure

1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
4. Record raw request and response pairs verbatim, including headers, before you interpret anything.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/session/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id session`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
