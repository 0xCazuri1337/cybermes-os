# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
--- cache_deception@current
+++ cache_deception@new
@@ -73,4 +73,4 @@
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
 ---
-Full class document: `domains/web/cache_deception/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_deception`
+Full class document: `domains/web/cache_deception/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_deception`
```

## 2026-10-02 19:37 — 103 diff lines
- items: 23 (supported 11), FP rules 3, chains 1, state mature

```diff
--- cache_deception@current
+++ cache_deception@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 13 items, 13 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 11 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 A cache stores a personalised response under a key that other users can request.
@@ -26,45 +26,84 @@
 
 ## Techniques (what to change)
 
-- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.
+- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.
+- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.
+- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.
+- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.
+- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.
+- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors.
+- A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors. _(unverified)_
   - **Disproof:** A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.
   - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
 - When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.
   - **Disproof:** The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
+## Tests
+
+- To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. How to apply it in the field: treat this as the fp_rule it is — a hunter must _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_404_response_cached_for_three_minutes_does_not_leak_anything) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. The claim is proven when the unauthenticated probe returns the base _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignor _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the de _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
+
 ## Validation bar (how to prove it)
 
+- Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.
+  - **Disproof:** The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
 - An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.
   - **Disproof:** If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
 
 ## False-positive rules (when to reject it)
 
+- A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. _(unverified)_
+  - **Disproof:** The rule is wrong when the origin's own 404 handler renders user-specific content — a signed-in shell, an internal error detail, a per-user tenant name — or when the edge caches a 404 for a path that was genuinely private, in which case the cached object does carry data and the deception holds despite the status code.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
+- Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.
+  - **Disproof:** The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
 - Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
 - A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.
   - **Disproof:** The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
+
+## Evidence requirements
+
+- The observation that distinguishes cache deception from ordinary caching is a cache HIT served for a URL that the origin never had as a static file, since a normal cache entry is only ever created for a resource the origin actually produced.
+  - **Disproof:** The claim is false when the origin does have a matching static file and the deception succeeded on a different URL form, or when the edge reports the HIT for a request whose cache lookup was actually a revalidation rather than a stored object; the X-Cache/AGE header values and the file inventory must both be captured before treating the HIT as evidence.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
+
+## Defence bypasses
+
+- An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL.
+  - **Disproof:** The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
 
 ## Chaining opportunities
 
```

## 2026-10-03 01:46 — 100 diff lines
- items: 25 (supported 14), FP rules 3, chains 1, state mature

```diff
--- cache_deception@current
+++ cache_deception@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 23 items, 11 supported, 3 FP rules, 1 chains
+> evidence: 25 items, 14 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 A cache stores a personalised response under a key that other users can request.
@@ -28,13 +28,13 @@
 
 - HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
 - It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
 - Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
 - It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
@@ -43,7 +43,7 @@
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
 - HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
 - A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors. _(unverified)_
   - **Disproof:** A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.
   - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
@@ -53,19 +53,19 @@
 
 ## Tests
 
-- To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. How to apply it in the field: treat this as the fp_rule it is — a hunter must _(unverified)_
+- To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_404_response_cached_for_three_minutes_does_not_leak_anything) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. The claim is proven when the unauthenticated probe returns the base _(unverified)_
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
+- To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignor _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the de _(unverified)_
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client) states the full boundary.
   - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
 
@@ -82,10 +82,10 @@
 
 - A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. _(unverified)_
   - **Disproof:** The rule is wrong when the origin's own 404 handler renders user-specific content — a signed-in shell, an internal error detail, a per-user tenant name — or when the edge caches a 404 for a path that was genuinely private, in which case the cached object does carry data and the deception holds despite the status code.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
 - Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.
   - **Disproof:** The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
 - Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
@@ -95,6 +95,12 @@
 
 ## Evidence requirements
 
+- A convincing observation for this class is: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. _(unverified)_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's...
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
 - The observation that distinguishes cache deception from ordinary caching is a cache HIT served for a URL that the origin never had as a static file, since a normal cache entry is only ever created for a resource the origin actually produced.
   - **Disproof:** The claim is false when the origin does have a matching static file and the deception succeeded on a different URL form, or when the edge reports the HIT for a request whose cache lookup was actually a revalidation rather than a stored object; the X-Cache/AGE header values and the file inventory must both be captured before treating the HIT as evidence.
   - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
@@ -103,7 +109,7 @@
 
 - An origin-side rule that refuses to serve responses for paths ending in a static extension closes the naive deception payload but not the same attack through a catch-all route, because a rewrite that maps every unmatched path to the application handler still returns the user's page under a cacheable URL.
   - **Disproof:** The rule is false when the application genuinely has no catch-all and returns its own 404 for unknown static-looking paths, or when the cache key itself includes the path in a way that cannot be reused — then the naive payload and its variants both fail and the allowlist holds.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
 
 ## Chaining opportunities
 
```

## 2026-10-04 00:43 — 159 diff lines
- items: 25 (supported 14), FP rules 3, chains 1, state mature

```diff
--- cache_deception@current
+++ cache_deception@new
@@ -20,102 +20,108 @@
 
 ## Prerequisites (do not start without these)
 
-- Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.
+- Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and no shared cache is in front of the path, if: every response to the authenticated request carries a restrictive Set-Cookie directive and no Age or cache-hit header on any fetch; a second, unrelated user session receives their own distinct personalised body rather than the first user's; or the origin is reached directly with no intermediary hop visible in response headers, timing, or server configuration, so nothing outside the browser holds a copy. Any of those removes the shared-store precondition the whole class rests on.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
 
 ## Techniques (what to change)
 
-- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. _(unverified)_
+- A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.
+  - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
+- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
+- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
   - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. _(unverified)_
+- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- HTTP Cache APIs allow developers to do something they have never been able to do before with Compute. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors. _(unverified)_
-  - **Disproof:** A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.
-  - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
-- When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.
+  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
+- When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
 ## Tests
 
-- To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client) states the full boundary.
+  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
+- To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_404_response_cached_for_three_minutes_does_not_leak_anything) states the full boundary.
   - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
-- To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. _(unverified)_
+- To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it) states the full boundary.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
 
 ## Validation bar (how to prove it)
 
-- Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.
+- An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
+- Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.
   - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
-- An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.
-  - **Disproof:** If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
 
 ## False-positive rules (when to reject it)
 
-- A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data. _(unverified)_
+- A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The rule is wrong when the origin's own 404 handler renders user-specific content — a signed-in shell, an internal error detail, a per-user tenant name — or when the edge caches a 404 for a path that was genuinely private, in which case the cached object does carry data and the deception holds despite the status code.
   - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
-- Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.
+- A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
+- Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.  _(merged 1 duplicate row(s))_
   - **Disproof:** The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
-- Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
-- A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.
-  - **Disproof:** The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both. _(unverified)_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's...  _(merged 1 duplicate row(s))_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
+- A convincing observation for this class is: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
... (truncated)
```

## 2026-10-04 13:20 — 22 diff lines
- items: 25 (supported 14), FP rules 3, chains 1, state mature

```diff
--- cache_deception@current
+++ cache_deception@new
@@ -46,16 +46,16 @@
 
 - To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.bypass.a_static_extension_allowlist_defeats_the_naive_payload_but_not_the_catch_all_route) states the full boundary.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/>
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
 - To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_cached_response_for_a_fake_static_path_is_only_a_leak_when_the_origin_serves_user_data_for_it) states the full boundary.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
 - To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.proof_is_the_same_cached_object_returned_to_a_second_unauthenticated_client) states the full boundary.
   - Sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>
 - To decide this case, observe: Mechanism: A cached 404 is not an information leak: the default edge TTL applied to 404 and 410 responses is minutes long and the cached object is the origin's error page, so caching it produces at most a stale missing page and no disclosure of the requester's data.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.fp_rule.a_404_response_cached_for_three_minutes_does_not_leak_anything) states the full boundary.
-  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>
+  - Sources: <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>
 - To decide this case, observe: Step: with a valid session cookie, request the private endpoint and capture the response body as a baseline, then replay the same request with the cookie removed and a path suffix such as /x.css appended, comparing the two responses and the Age or X-Cache headers on both.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_deception.validation.uri_keyed_cache_serves_another_identity) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>
```
