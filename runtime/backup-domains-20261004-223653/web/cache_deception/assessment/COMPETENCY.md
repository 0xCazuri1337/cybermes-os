# Methodology — Web Cache Deception

> Derived from 14 verified items. Regenerate with `python -m wks.methodgen --class cache_deception --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A cache stores a personalised response under a key that other users can request.

**References.** CWE-444 · A04:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.**

Before hunting cache deception, establish that the response actually traverses a shared cache rather than a per-user one. Two facts decide it. First, the cache must be positioned between client and web server and must store resources locally after retrieving them from the origin, then serve the same resource from local storage on subsequent requests. Second, a shared cache is by definition a cache that stores responses for reuse by more than one user, and shared caches are usually deployed as a part of an intermediary, whereas a private cache is dedicated to a single user and is often deployed inside the user agent. Practical probe: send the same request twice from two different authenticated sessions with no cache-busting header and diff the response headers. An Age header or an X-Cache/Hit indicator, or a server-timing entry naming a cache hop, proves a shared tier is answering. If every response carries Set-Cookie with no-store, or the origin returns Cache-Control: private, the shared tier is not storing it and the class does not apply to that path. Record the cache key inputs before anything else, because a deception finding that cannot name the key is not yet a finding.

- *Disproof:* The claim is wrong, and no shared cache is in front of the path, if: every response to the authenticated request carries a restrictive Set-Cookie directive and no Age or cache-hit header on any fetch; a second, unrelated user session receives their own distinct personalised body rather than the first user's; or the origin is reached directly with no intermediary hop visible in response headers, timing, or server configuration, so nothing outside the browser holds a copy. Any of those removes the shared-store precondition the whole class rests on.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [httpwg.org](https://httpwg.org/specs/rfc9111.html)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.**

The mechanism has two halves and both must be present. Cache half: the cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; caches differentiate content-negotiated responses by incorporating some of the original request's header fields into the cache key using the Vary response header field, so a response with no Vary, or a Vary that omits the header actually being reflected, keys on URI alone. Application half: web cache poisoning is often the result of discrepancies between web caches and the web application, and the discrepancies that matter are unkeyed inputs the origin honours but the key ignores. Procedure: pick an authenticated page, enumerate candidate unkeyed inputs one at a time (a header the origin reflects, a query parameter ignored in the key, a path suffix such as /x.css or /anything.js appended after a dynamic segment), poison each with a unique canary, then fetch the clean URI as a different session and look for the canary. The canary appearing in another user's response is the finding.

- *Disproof:* The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [portswigger.net](https://portswigger.net/web-security/host-header/exploiting)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.**

Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. The claim is proven when the unauthenticated probe returns the baseline body while the origin would have answered 401 for that same path without the suffix, because the cache key is the request method and target URI and many shared caches use only the URI, so a suffix maps to a different stored entry. A missing or cache-bypassing Age header, or an origin that returns 401 for the suffixed path directly, means the probe proved nothing about the cache.

- *Disproof:* If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9111.html); [w3.org](https://www.w3.org/TR/fetch-metadata/)

**Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.**

Mechanism: Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.

- *Disproof:* The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.
- *Evidence:* high_confidence — [developers.cloudflare.com](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/); [firebase.google.com](https://firebase.google.com/docs/hosting/full-config)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key...

Adjacent behaviour that produces the same observable result: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [httpwg.org](https://httpwg.org/specs/rfc9111.html)

**A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.**

The rejection test is identity, not the presence of a cache. A cache stores cacheable responses to reduce the response time and network bandwidth consumption on future equivalent requests, and a shared cache stores responses for reuse by more than one user; that is the entire designed purpose. What makes deception a finding is that a response generated for one identity is served to a different one. So: diff the body served to the authenticated session against the body served with no session. If they are byte-identical, or the anonymous request is refused outright, there is nothing to steal and the cache hit is a non-finding. Reject on any of: the URL is a static asset under /static, /assets, /cdn-cgi, or a hashed fingerprint; the response carries a long max-age or immutable; the asset is not user-specific in any tested dimension; or the only differing header is Age, X-Cache, or the edge POP name, which are cache metadata rather than leaked content. This is the single largest source of cache-deception noise, because every CDN-fronted property generates thousands of legitimate cache hits.

- *Disproof:* The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [httpwg.org](https://httpwg.org/specs/rfc9111.html)

**Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.**

Mechanism: Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.

- *Disproof:* The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.
- *Evidence:* high_confidence — [developers.cloudflare.com](https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/); [httpwg.org](https://httpwg.org/specs/rfc9111.html)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL.**

Mechanism: An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.

- *Disproof:* The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.
- *Evidence:* high_confidence — [developers.cloudflare.com](https://developers.cloudflare.com/cache/how-to/cache-rules/settings/); [httpwg.org](https://httpwg.org/specs/rfc9111.html)

## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key weakness into cross-user session compromise rather than a self-inflicted reflection.**

Three published facts compose into the chain. First, the shared-store precondition: a cache sits between the client and the web server and serves the same resource from local storage on subsequent requests, and a shared cache stores responses for reuse by more than one user. Second, the key weakness: the cache key is composed from, at a minimum, the request method and target URI, and caches differentiate responses by incorporating request header fields named in Vary, so an input the origin honours but the key ignores is invisible to the cache. Third, the amplification: web cache poisoning can lead to otherwise unexploitable vulnerabilities being weaponized to target a massive number of potential victims, and a reflected weakness becomes a dangerous stored one by persuading the cache to serve a poisoned response to other users. Composed: the attacker requests a URI under a personalised path with an unkeyed suffix, the cache stores the attacker's rendered body, and the next unrelated visitor to that URI receives the attacker's session context or a script running as the attacker. The attacker is not stealing a cookie by guessing; the cache is handing out the wrong principal's response on demand.

- *Disproof:* The chain is refuted if any link fails: the deployment has no shared cache in front of the personalised path, so the stored copy never reaches a second user; the response carries Cache-Control: private or Set-Cookie with no-store, which stops the shared tier storing it; Vary correctly names the unkeyed input and the cache honours it, splitting the stored responses by that header; or the personalised page carries no session-dependent content, so the second visitor receives an identical body and nothing is disclosed. Demonstrate the cross-identity read before asserting takeover.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [httpwg.org](https://httpwg.org/specs/rfc9111.html); [portswigger.net](https://portswigger.net/web-security/host-header/exploiting)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
