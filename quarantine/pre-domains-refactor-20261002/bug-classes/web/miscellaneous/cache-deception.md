# Web Cache Deception

## Definition

A cache stores a personalised response under a key that other users can request.

- **CWE:** 444
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["cache deception", "web cache deception"]

Canonical home for `cache_deception`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.**

Before hunting cache deception, establish that the response actually traverses a shared cache rather than a per-user one. Two facts decide it. First, the cache must be positioned between client and web server and must store resources locally after retrieving them from the origin, then serve the same resource from local storage on subsequent requests. Second, a shared cache is by definition a cache that stores responses for reuse by more than one user, and shared caches are usually deployed as a part of an intermediary, whereas a private cache is dedicated to a single user and is often deployed inside the user agent. Practical probe: send the same request twice from two different authenticated sessions with no cache-busting header and diff the response headers. An Age header or an X-Cache/Hit indicator, or a server-timing entry naming a cache hop, proves a shared tier is answering. If every response carries Set-Cookie with no-store, or the origin returns Cache-Control: private, the shared tier is not storing it and the class does not apply to that path. Record the cache key inputs before anything else, because a deception finding that cannot name the key is not yet a finding.

*Disproof:* The claim is wrong, and no shared cache is in front of the path, if: every response to the authenticated request carries a restrictive Set-Cookie directive and no Age or cache-hit header on any fetch; a second, unrelated user session receives their own distinct personalised body rather than the first user's; or the origin is reached directly with no intermediary hop visible in response headers, timing, or server configuration, so nothing outside the browser holds a copy. Any of those removes the shared-store precondition the whole class rests on.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors.**

The detector's signal is not the attacker request but the cache hit that request creates, so a hunter should compare cached response bodies against what the origin dynamically returns for the same path and probe the reflection points that reach the cache. This matters because edge networks cache origin responses automatically unless Cache-Control overrides it, which is why a single pre-auth request has effects beyond its own session. The claim is falsified by an edge configured so responses are never automatically cached and per-request cache keys are used.

*Disproof:* A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.

**When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.**

The mechanism has two halves and both must be present. Cache half: the cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; caches differentiate content-negotiated responses by incorporating some of the original request's header fields into the cache key using the Vary response header field, so a response with no Vary, or a Vary that omits the header actually being reflected, keys on URI alone. Application half: web cache poisoning is often the result of discrepancies between web caches and the web application, and the discrepancies that matter are unkeyed inputs the origin honours but the key ignores. Procedure: pick an authenticated page, enumerate candidate unkeyed inputs one at a time (a header the origin reflects, a query parameter ignored in the key, a path suffix such as /x.css or /anything.js appended after a dynamic segment), poison each with a unique canary, then fetch the clean URI as a different session and look for the canary. The canary appearing in another user's response is the finding.

*Disproof:* The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.**

The rejection test is identity, not the presence of a cache. A cache stores cacheable responses to reduce the response time and network bandwidth consumption on future equivalent requests, and a shared cache stores responses for reuse by more than one user; that is the entire designed purpose. What makes deception a finding is that a response generated for one identity is served to a different one. So: diff the body served to the authenticated session against the body served with no session. If they are byte-identical, or the anonymous request is refused outright, there is nothing to steal and the cache hit is a non-finding. Reject on any of: the URL is a static asset under /static, /assets, /cdn-cgi, or a hashed fingerprint; the response carries a long max-age or immutable; the asset is not user-specific in any tested dimension; or the only differing header is Age, X-Cache, or the edge POP name, which are cache metadata rather than leaked content. This is the single largest source of cache-deception noise, because every CDN-fronted property generates thousands of legitimate cache hits.

*Disproof:* The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.

## Validation

**An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.**

Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. The claim is proven when the unauthenticated probe returns the baseline body while the origin would have answered 401 for that same path without the suffix, because the cache key is the request method and target URI and many shared caches use only the URI, so a suffix maps to a different stored entry. A missing or cache-bypassing Age header, or an origin that returns 401 for the suffixed path directly, means the probe proved nothing about the cache.

*Disproof:* If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **fastly.com** (writeup)
  - <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9111.html>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/>
- **portswigger.net** (docs)
  - <https://portswigger.net/web-security/host-header/exploiting>
- **w3.org** (standard)
  - <https://www.w3.org/TR/fetch-metadata/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
