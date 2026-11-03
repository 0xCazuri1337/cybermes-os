<!-- GENERATED from db/wks.db — do not edit -->
# Web Cache Deception

## Definition

A cache stores a personalised response under a key that other users can request.

- **CWE:** 444
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["cache deception", "web cache deception"]

Canonical home for `cache_deception`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

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

**A convincing observation for this class is: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.**

Derived from cache_deception.validation.uri_keyed_cache_serves_another_identity, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's...**

Derived from cache_deception.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.fp_rule.auto.derived) states the full boundary.

**The observation that distinguishes cache deception from ordinary caching is a cache HIT served for a URL that the origin never had as a static file, since a normal cache entry is only ever created for a resource the origin actually produced.**

Mechanism: The observation that distinguishes cache deception from ordinary caching is a cache HIT served for a URL that the origin never had as a static file, since a normal cache entry is only ever created for a resource the origin actually produced. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the origin does have a matching static file and the deception succeeded on a different URL form, or when the edge reports the HIT for a request whose cache lookup was actually a revalidation rather than a stored object; the X-Cache/AGE header values and the file inventory must both be captured before treating the HIT as evidence.

*Disproof:* The claim is false when the origin does have a matching static file and the deception succeeded on a different URL form, or when the edge reports the HIT for a request whose cache lookup was actually a revalidation rather than a stored object; the X-Cache/AGE header values and the file inventory must both be captured before treating the HIT as evidence.

## Exploitation

**HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.**

solves that with the simplicity of our new HTTP Cache APIs, a set of SDK APIs, usable from within Compute code. How does it work? By default, when HTTP requests pass through Fastly’s edge, origin responses are automatically cached (unless explicitly overridden via Cache-Control). Subsequent requests for that same resource can then be delivered from cache without having to connect to the backend.  HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. Now, you can inject customizations into this default flow, opening the doors to new use cases and possibilities for Compute customers. What you need to know HTTP Cache API: The TL;DR Provides first-class HTTP support in your preferred language  Enables fine-grained, programmatic access to Fastly’s cache Supports customizing dynamic content delivered by Fastly Compute Allows developers to customiz

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“HTTP Cache APIs allow developers to do something they have never been able to do”) does not occur under a test that isolates that control.

**It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.**

eferred language  Enables fine-grained, programmatic access to Fastly’s cache Supports customizing dynamic content delivered by Fastly Compute Allows developers to customize caching behavior with ease The HTTP cache interface builds on the foundation established by the Simple Cache and Core Cache interfaces and is optimized for caching requests/responses within the flow of the HTTP specification. It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. Use cases our customers love Here is a simple JavaScript example of modifying the Fastly TTL while setting a Surrogate-Control for downstream caches, and a Cache-Control header for managing browser caches: Copied! 
 if (!customElements.get("copy-button")) {
 class CopyButton extends HTMLElement {
 connectedCallback() {
 this.addEventListener("click", async () => {
 const code = this.dataset.code

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“It is a fully integrated API that gives developers capabilities such as the abil”) does not occur under a test that isolates that control.

**Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.**

amic content can have shorter TTLs. This results in improved website speed, reduced origin load, and a better user experience, all while maintaining content freshness appropriate to each asset type. Modify the response headers or body before storing it in the cache. For example, developers can cache the locally generated HTML version of a response, rather than the raw JSON returned by the origin. Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. By caching the HTML version instead of raw JSON, subsequent requests can be served faster, as the transformation step is eliminated. This not only improves performance but also reduces computational load on both the origin server and the edge, leading to cost savings and a more responsive application overall. Determining whether to cache at all, based on the origin content. This is great for situ

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Benefit: This capability enables developers to store optimized versions of conte”) does not occur under a test that isolates that control.

**It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.**

eferred language  Enables fine-grained, programmatic access to Fastly’s cache Supports customizing dynamic content delivered by Fastly Compute Allows developers to customize caching behavior with ease The HTTP cache interface builds on the foundation established by the Simple Cache and Core Cache interfaces and is optimized for caching requests/responses within the flow of the HTTP specification. It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. Use cases our customers love Here is a simple JavaScript example of modifying the Fastly TTL while setting a Surrogate-Control for downstream caches, and a Cache-Control header for managing browser caches: Copied! 
 if (!customElements.get("copy-button")) {
 class CopyButton extends HTMLElement {
 connectedCallback() {
 this.addEventListener("click", async () => {
 const code = this.dataset.code

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“It is a fully integrated API that gives developers capabilities such as the abil”) does not occur under a test that isolates that control.

**Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.**

amic content can have shorter TTLs. This results in improved website speed, reduced origin load, and a better user experience, all while maintaining content freshness appropriate to each asset type. Modify the response headers or body before storing it in the cache. For example, developers can cache the locally generated HTML version of a response, rather than the raw JSON returned by the origin. Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. By caching the HTML version instead of raw JSON, subsequent requests can be served faster, as the transformation step is eliminated. This not only improves performance but also reduces computational load on both the origin server and the edge, leading to cost savings and a more responsive application overall. Determining whether to cache at all, based on the origin content. This is great for situ

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Benefit: This capability enables developers to store optimized versions of conte”) does not occur under a test that isolates that control.

**HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.**

solves that with the simplicity of our new HTTP Cache APIs, a set of SDK APIs, usable from within Compute code. How does it work? By default, when HTTP requests pass through Fastly’s edge, origin responses are automatically cached (unless explicitly overridden via Cache-Control). Subsequent requests for that same resource can then be delivered from cache without having to connect to the backend.  HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. Now, you can inject customizations into this default flow, opening the doors to new use cases and possibilities for Compute customers. What you need to know HTTP Cache API: The TL;DR Provides first-class HTTP support in your preferred language  Enables fine-grained, programmatic access to Fastly’s cache Supports customizing dynamic content delivered by Fastly Compute Allows developers to customiz

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“HTTP Cache APIs allow developers to do something they have never been able to do”) does not occur under a test that isolates that control.

**A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors.**

The detector's signal is not the attacker request but the cache hit that request creates, so a hunter should compare cached response bodies against what the origin dynamically returns for the same path and probe the reflection points that reach the cache. This matters because edge networks cache origin responses automatically unless Cache-Control overrides it, which is why a single pre-auth request has effects beyond its own session. The claim is falsified by an edge configured so responses are never automatically cached and per-request cache keys are used.

*Disproof:* A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.

**When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.**

The mechanism has two halves and both must be present. Cache half: the cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; caches differentiate content-negotiated responses by incorporating some of the original request's header fields into the cache key using the Vary response header field, so a response with no Vary, or a Vary that omits the header actually being reflected, keys on URI alone. Application half: web cache poisoning is often the result of discrepancies between web caches and the web application, and the discrepancies that matter are unkeyed inputs the origin honours but the key ignores. Procedure: pick an authenticated page, enumerate candidate unkeyed inputs one at a time (a header the origin reflects, a query parameter ignored in the key, a path suffix such as /x.css or /anything.js appended after a dynamic segment), poison each with a unique canary, then fetch the clean URI as a different session and look for the canary. The canary appearing in another user's response is the finding.

*Disproof:* The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.

## Variations

**An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL.**

Mechanism: An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.

*Disproof:* The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.cache_deception.auto.01` — cache_deception: observe, exercise, confirm (goal: `Establish, exercise and confirm a cache_deception condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data.**

Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the origin's own 404 handler renders user-specific content — a signed-in shell, an internal error detail, a per-user tenant name — or when the edge caches a 404 for a path that was genuinely private, in which case the cached object does carry data and the deception holds despite the status code.

*Disproof:* The rule is wrong when the origin's own 404 handler renders user-specific content — a signed-in shell, an internal error detail, a per-user tenant name — or when the edge caches a 404 for a path that was genuinely private, in which case the cached object does carry data and the deception holds despite the status code.

**Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.**

Mechanism: Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.

*Disproof:* The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.

**Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key...

Adjacent behaviour that produces the same observable result: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.**

The rejection test is identity, not the presence of a cache. A cache stores cacheable responses to reduce the response time and network bandwidth consumption on future equivalent requests, and a shared cache stores responses for reuse by more than one user; that is the entire designed purpose. What makes deception a finding is that a response generated for one identity is served to a different one. So: diff the body served to the authenticated session against the body served with no session. If they are byte-identical, or the anonymous request is refused outright, there is nothing to steal and the cache hit is a non-finding. Reject on any of: the URL is a static asset under /static, /assets, /cdn-cgi, or a hashed fingerprint; the response carries a long max-age or immutable; the asset is not user-specific in any tested dimension; or the only differing header is Age, X-Cache, or the edge POP name, which are cache metadata rather than leaked content. This is the single largest source of cache-deception noise, because every CDN-fronted property generates thousands of legitimate cache hits.

*Disproof:* The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.

## Validation

**Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.**

Mechanism: Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.

*Disproof:* The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.

**An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.**

Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. The claim is proven when the unauthenticated probe returns the baseline body while the origin would have answered 401 for that same path without the suffix, because the cache key is the request method and target URI and many shared caches use only the URI, so a suffix maps to a different stored entry. A missing or cache-bypassing Age header, or an origin that returns 401 for the suffixed path directly, means the probe proved nothing about the cache.

*Disproof:* If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.

**To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data.**

Derived from cache_deception.fp_rule.a_404_response_cached_for_three_minutes_does_not_leak_anything, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_404_response_cached_for_three_minutes_does_not_leak_anything) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.

**To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.**

Derived from cache_deception.validation.uri_keyed_cache_serves_another_identity, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/444.html>
- **developers.cloudflare.com** (writeup)
  - <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
  - <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
- **fastly.com** (writeup)
  - <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **firebase.google.com** (writeup)
  - <https://firebase.google.com/docs/hosting/full-config>
- **github.com** (practitioner)
  - <https://github.com/dmbs335/the-map/blob/main/08-infrastructure/web-cache-poisoning-and-deception.md>
  - <https://github.com/harshdhamaniya/web-application-security/blob/main/22-caching-attacks/README.md>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9111.html>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/>
- **masaaki.tech** (practitioner)
  - <https://masaaki.tech/blog/cybersec/ethical-hacking/web-cache-attacks/>
- **portswigger.net** (web)
  - <https://portswigger.net/kb/issues/00200650_web-cache-deception>
  - <https://portswigger.net/web-security/host-header/exploiting>
  - <https://portswigger.net/web-security/web-cache-deception>
- **raw.githubusercontent.com** (primary)
  - <https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en/A04_2021-Insecure_Design.md>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc9111.html>
- **usenix.org** (web)
  - <https://www.usenix.org/system/files/sec22summer_mirheidari.pdf>
- **w3.org** (standard)
  - <https://www.w3.org/TR/fetch-metadata/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
