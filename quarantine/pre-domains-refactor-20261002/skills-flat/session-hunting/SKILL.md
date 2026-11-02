---
name: session-hunting
description: Use when hunting Session Management Flaws in a identity target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Session Management Flaws — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `identity` · CWE 384 · OWASP A07:2021
> evidence: 6 items, 6 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

Session identity, lifetime or binding is weaker than the operation's risk requires.

**Also called:** session fixation, session management, cookie flags, session hijacking


## Prerequisites (do not start without these)

- A session cookie must be revalidated server-side on every request that relies on it, so any endpoint that acts on the cookie without a lookup or signature check sits outside the session boundary and is a session-trust defect on its own.
  - **Disproof:** The claim fails if a cached or CDN-fronted response returns the same 200 body with no cookie because it was served from cache rather than a session lookup, or if the endpoint is deliberately public and returns identical bytes to an authenticated user. Both are artefacts of the test, not a missing validation.
  - Sources: <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies> · <https://developer.okta.com/blog/2021/06/16/session-mgmt-react>

## Recon signals (where to look)

- A session identifier that is a self-contained JWT keeps serving the claims captured at issuance, so a role or entitlement revoked server-side is still honoured in the session until the token expires; staleness shows up as a user retaining access they were demonstrably stripped of.
  - **Disproof:** The finding collapses if the replayed request was rejected, if the server re-derives authorization from live server-side session state rather than from the token claims, or if the revocation never actually took effect and the account is still enabled server-side, leaving no staleness to observe.
  - Sources: <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens>

## Techniques (what to change)

- Session termination is only proven by replaying the pre-logout session value against a protected endpoint after logout and observing that it no longer authenticates; a redirect to a login page in the UI is not evidence that the server-side record was destroyed.
  - **Disproof:** The test is invalid if the replayed request was sent from a browser whose own cookie jar the server could read implicitly, if a CDN served a cached authenticated body, or if logout in this deployment is by design client-side only with a short session lifetime you have not accounted for.
  - Sources: <https://auth0.com/docs/manage-users/cookies/spa-authenticate-with-cookies> · <https://developer.okta.com/blog/2021/06/16/session-mgmt-react>

## Validation bar (how to prove it)

- Replay of an identity token is only defeated when the client compares the token's nonce claim against the value it persisted for the request it initiated and rejects the response when they differ; identical nonce values across two distinct authentication requests prove the check is absent.
  - **Disproof:** The claim fails if the server rejects the substituted token, if the token carries no nonce claim because the flow never used one (the defence is then absent but a one-time authorization code or PKCE may protect the flow), or if the two observed nonces were genuinely distinct and each token matched its own request.
  - Sources: <https://auth0.com/docs/get-started/authentication-and-authorization-flow/implicit-flow-with-form-post/mitigate-replay-attacks-when-using-the-implicit-flow> · <https://developer.okta.com/blog/2022/07/19/angular-security-csrf>

## False-positive rules (when to reject it)

- A session cookie missing Secure, HttpOnly or SameSite is not itself an exploitable session defect; the finding only survives when a test demonstrates an attacker-reachable path that actually uses the weakness, such as script on the same origin reading the value or a cross-site request that still attaches it.
  - **Disproof:** It becomes exploitable when document.cookie on a same-origin XSS returns the session value and that value replays into an authenticated request, when the app serves any HTTP endpoint that receives the cookie, or when a SameSite=None cookie without Secure is accepted so a cross-site request still carries it. If none of those hold, downgrade the report to hardening.
  - Sources: <https://auth0.com/docs/manage-users/cookies/samesite-cookie-attribute-changes> · <https://developer.okta.com/docs/guides/sign-into-web-app-redirect/main/> · <https://developer.okta.com/blog/2022/02/08/cookies-vs-tokens>
- A session identifier appearing in a URL or response on a non-login, unauthenticated page is not session fixation or session hijack: fixation requires the identifier to survive privilege elevation and remain usable for an authenticated resource, otherwise it is at most anonymous session tracking.
  - **Disproof:** It IS fixation if the identifier still authenticates after login (issue it pre-auth, complete a real login with it, then fetch a page that requires authentication and show 200), or if it is set on a login page and accepted unchanged at privilege elevation. The test is reuse-after-login, not presence in the URL.
  - Sources: <https://capec.mitre.org/data/definitions/61.html> · <https://www.zaproxy.org/docs/alerts/40013-4/>

---
Full class document: `skills/Web/session/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id session`
