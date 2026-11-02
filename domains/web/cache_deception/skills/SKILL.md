---
name: cache_deception-hunting
description: Use when hunting Web Cache Deception in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Web Cache Deception — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 444 · OWASP A04:2021
> evidence: 18 items, 10 supported, 2 FP rules, 1 chains
> maturity: **mature**

A cache stores a personalised response under a key that other users can request.

**Also called:** cache deception, web cache deception


## Prerequisites (do not start without these)

- Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is wrong, and no shared cache is in front of the path, if: every response to the authenticated request carries a restrictive Set-Cookie directive and no Age or cache-hit header on any fetch; a second, unrelated user session receives their own distinct personalised body rather than the first user's; or the origin is reached directly with no intermediary hop visible in response headers, timing, or server configuration, so nothing outside the browser holds a copy. Any of those removes the shared-store precondition the whole class rests on.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>

## Techniques (what to change)

- A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.
  - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>

## Tests

- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
- To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>

## Validation bar (how to prove it)

- An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
- Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.
  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>

## False-positive rules (when to reject it)

- A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
- Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>

## Evidence requirements

- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's...  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- A convincing observation for this class is: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
- The observation that distinguishes cache deception from ordinary caching is a cache HIT served for a URL that the origin never had as a static file, since a normal cache entry is only ever created for a resource the origin actually produced.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the origin does have a matching static file and the deception succeeded on a different URL form, or when the edge reports the HIT for a request whose cache lookup was actually a revalidation rather than a stored object; the X-Cache/AGE header values and the file inventory must both be captured before treating the HIT as evidence.
  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>

## Defence bypasses

- An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>

## Chaining opportunities

- When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key weakness into cross-user session compromise rather than a self-inflicted reflection.  _(merged 1 duplicate row(s))_
  - **Disproof:** The chain is refuted if any link fails: the deployment has no shared cache in front of the personalised path, so the stored copy never reaches a second user; the response carries Cache-Control: private or Set-Cookie with no-store, which stops the shared tier storing it; Vary correctly names the unkeyed input and the cache honours it, splitting the stored responses by that header; or the personalised page carries no session-dependent content, so the second visitor receives an identical body and nothing is disclosed. Demonstrate the cross-identity read before asserting takeover.
  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>


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
Full class document: `domains/web/cache_deception/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_deception`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
