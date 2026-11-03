# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -73,4 +73,4 @@
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 
 ---
-Full class document: `domains/web/cache_poisoning/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
+Full class document: `domains/web/cache_poisoning/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
```

## 2026-10-02 19:37 — 67 diff lines
- items: 16 (supported 6), FP rules 2, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
+> evidence: 16 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
@@ -26,36 +26,45 @@
 
 ## Techniques (what to change)
 
-- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).
+- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).
+- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.
+- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.
+- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.
+- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.
+- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.
+- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).
+- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.
+- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).
+- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
+
+## Tests
+
+- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize. It is a
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
+  - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
+- To decide this case, observe: in sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached. Re-run after the window closes to show the effect ends for the right reason.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 74 diff lines
- items: 22 (supported 12), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 16 items, 6 supported, 2 FP rules, 1 chains
+> evidence: 22 items, 12 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
@@ -22,7 +22,7 @@
 
 - A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.
   - **Disproof:** If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>
 
 ## Techniques (what to change)
 
@@ -59,21 +59,33 @@
 
 ## Tests
 
-- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize. It is a
+- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
-- To decide this case, observe: in sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached. Re-run after the window closes to show the effect ends for the right reason.
+- To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
+- A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.
+  - **Disproof:** If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
 
 ## Validation bar (how to prove it)
 
+- Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.
+  - **Disproof:** If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
 - Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.
   - **Disproof:** If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
 
 ## False-positive rules (when to reject it)
 
+- A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.
+  - **Disproof:** It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
+- Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.
+  - **Disproof:** It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
 - A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.
   - **Disproof:** It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
   - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
@@ -81,5 +93,17 @@
   - **Disproof:** A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
+  - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
+
+## Defence bypasses
+
+- When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.
+  - **Disproof:** It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+
 ---
 Full class document: `domains/web/cache_poisoning/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
```

## 2026-10-04 00:43 — 132 diff lines
- items: 22 (supported 12), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -20,90 +20,90 @@
 
 ## Recon signals (where to look)
 
-- A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.
+- A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>
 
 ## Techniques (what to change)
 
-- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). _(unverified)_
+- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
+- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent. _(unverified)_
+- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request. _(unverified)_
+- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
-  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). _(unverified)_
+- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
 
 ## Tests
 
-- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.
+- A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
-- To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.
+- To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
-- A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.
-  - **Disproof:** If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
 
 ## Validation bar (how to prove it)
 
-- Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.
+- Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
-- Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.
+- Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
 
 ## False-positive rules (when to reject it)
 
-- A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.
+- A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
-- Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.
+- A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
+  - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
+- A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
+  - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
+- Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
-- A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.
-  - **Disproof:** It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
-  - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
-- A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.
-  - **Disproof:** A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
-  - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.
+- A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 
 ## Defence bypasses
 
-- When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.
+- When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
... (truncated)
```

## 2026-10-04 19:46 — 9 diff lines
- items: 22 (supported 12), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -107,6 +107,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/cache_poisoning/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 42 diff lines
- items: 22 (supported 22), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 22 items, 12 supported, 4 FP rules, 1 chains
+> evidence: 22 items, 22 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
@@ -26,20 +26,20 @@
 
 ## Techniques (what to change)
 
-- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
+- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A cache considers a stored response "fresh", as defined in Section 4.2 , if it c”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
+- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
+- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a cache receives a delta-seconds value greater than the greatest integer it c”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
+- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The cache key is the information a cache uses to choose a response and is compos”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
+- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When a cached response is not fresh, it might still be reusable if validation ca”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
 
 ## Tests
```

## 2026-10-28 14:45 — 36 diff lines
- items: 17 (supported 17), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 22 items, 22 supported, 4 FP rules, 1 chains
+> evidence: 17 items, 17 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
@@ -26,19 +26,19 @@
 
 ## Techniques (what to change)
 
-- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).  _(merged 2 duplicate row(s))_
+- A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A cache considers a stored response "fresh", as defined in Section 4.2 , if it c”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.  _(merged 2 duplicate row(s))_
+- Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.  _(merged 2 duplicate row(s))_
+- If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a cache receives a delta-seconds value greater than the greatest integer it c”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 2 duplicate row(s))_
+- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The cache key is the information a cache uses to choose a response and is compos”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 2 duplicate row(s))_
+- When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When a cached response is not fresh, it might still be reusable if validation ca”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
 
```

## 2026-10-28 21:00 — 59 diff lines
- items: 24 (supported 24), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 17 items, 17 supported, 4 FP rules, 1 chains
+> evidence: 24 items, 24 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
@@ -29,6 +29,12 @@
 - A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A cache considers a stored response "fresh", as defined in Section 4.2 , if it c”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
+- A request header that changes the response but is absent from the cache key is unkeyed input: the origin's response is stored under a key that does not include that header, so every later request whose key matches - regardless of the header value - is served the attacker's response.  _(merged 1 duplicate row(s))_
+  - **Disproof:** No poisoning when the response is not cacheable (no-store, or private without s-maxage/proxy-revalidate), when the Authorization request triggers a shared-cache prohibition, when the header is part of the cache key (Vary or the configured key), or when the origin rejects the header.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws>
+- A response with no explicit freshness directives (no Cache-Control max-age/s-maxage or Expires) is still a caching candidate: a shared cache may apply a heuristic expiration from other field values, so a poisoned entry without explicit directives can persist long after a naive 'not fresh' assessment and keep serving victims until the heuristic TTL expires.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the response carries explicit Cache-Control (no-store, no-cache, private without s-maxage) or the cache is configured to ignore heuristic freshness, or the entry predates the probe, the claim does not hold.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
 - Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
@@ -41,6 +47,9 @@
 - When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When a cached response is not fresh, it might still be reusable if validation ca”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
+- When a shared cache keys only on the request method and URI, or omits the Authorization header and Cookie from the key, an authenticated or personalized response can be stored under a shared key. A route that is cacheable for an authenticated request can then carry unkeyed attacker input, so the poisoned entry propagates to every user who hits the key, bypassing per-user boundaries.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the cache key includes Authorization/Cookie (Vary or a structured key), if the route is not cacheable for authenticated requests, or if the internal and external tiers key identically, the entry is separated and the claim does not hold.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 
 ## Tests
 
@@ -86,9 +95,24 @@
 
 ## Defence bypasses
 
+- A 'fat GET' request - a GET carrying a message body - is not exempt from caching, and many caches key the entry on the URI plus query string only; the body is therefore outside the cache key and a body parameter can change the response while remaining unkeyed.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the cache strips the body before lookup (Varnish builtin.vcl), if proxy_cache_methods excludes GET with a body, if the response is not cacheable, or if the body parameter is part of the key, the primitive does not hold.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
+- Parameter cloaking hides a payload from the cache key: caches derive their key from URL parsing (regexes, semicolon and duplicate-parameter handling), so an attacker can feed a parameter that the cache treats as a single keyed parameter while the origin parses it differently and exposes a second, attacker-controlled parameter.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the cache and the origin parse the input identically, if the payload stays inside the key, or if the response is not cacheable, the entry is keyed and no poisoning occurs.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
 - When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+- nginx proxy_cache_convert_head (default on) converts HEAD requests to GET for caching, so a HEAD request's headers are processed by the origin and can change the stored response while the entry is filed under a key derived from GET semantics: the request method never enters the key.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the key includes the request method (conversion off), if the origin rejects HEAD, if the route is not cacheable, or if the poisoning header is part of the key, the attack does not hold.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+
+## Chaining opportunities
+
+- A cache poisoning chain links an unkeyed input at one tier to a second tier that keys differently: an attacker poisons the origin's cache through an unkeyed header, and the front-end CDN serves the poisoned entry to victims because its key omits the same input - one request by the attacker poisons a whole tier, and the payload (script, redirect, HSTS header or custom response header) is delivered to every visitor until the TTL expires.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the tiers agree on the key (one tier unkeys something the other keys, or both unkey the same input), or if the front-end never serves the poisoned entry (it revalidates, or the origin entry is separate), the chain does not hold.
+  - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf> · <https://portswigger.net/research/practical-web-cache-poisoning>
 
 
 ## Hunt procedure
```

## 2026-10-28 21:26 — 20 diff lines
- items: 24 (supported 24), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -76,7 +76,7 @@
 
 - A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9111.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 - A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
   - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
@@ -85,7 +85,7 @@
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 - Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9111.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 
 ## Evidence requirements
 
```

## 2026-10-28 21:43 — 33 diff lines
- items: 24 (supported 24), FP rules 4, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -55,7 +55,7 @@
 
 - A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 - To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
@@ -67,7 +67,7 @@
 
 - Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 - Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
@@ -103,10 +103,10 @@
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
 - When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.  _(merged 1 duplicate row(s))_
   - **Disproof:** It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 - nginx proxy_cache_convert_head (default on) converts HEAD requests to GET for caching, so a HEAD request's headers are processed by the origin and can change the stored response while the entry is filed under a key derived from GET semantics: the request method never enters the key.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the key includes the request method (conversion off), if the origin rejects HEAD, if the route is not cacheable, or if the poisoning header is part of the key, the attack does not hold.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
 
 ## Chaining opportunities
 
```

## 2026-10-31 06:41 — 78 diff lines
- items: 24 (supported 16), FP rules 3, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 444 · OWASP A04:2021
-> evidence: 24 items, 24 supported, 4 FP rules, 1 chains
+> evidence: 24 items, 16 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
@@ -41,7 +41,7 @@
 - If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a cache receives a delta-seconds value greater than the greatest integer it c”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
-- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 1 duplicate row(s))_
+- The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The cache key is the information a cache uses to choose a response and is compos”) does not occur under a test that isolates that control.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
 - When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).  _(merged 1 duplicate row(s))_
@@ -56,10 +56,10 @@
 - A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
-- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
-- To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
 
@@ -68,7 +68,7 @@
 - Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
-- Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.  _(merged 1 duplicate row(s))_
+- Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
 
@@ -80,7 +80,7 @@
 - A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
   - Sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
-- A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.  _(merged 1 duplicate row(s))_
+- A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 - Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.  _(merged 1 duplicate row(s))_
@@ -89,7 +89,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 
@@ -98,7 +98,7 @@
 - A 'fat GET' request - a GET carrying a message body - is not exempt from caching, and many caches key the entry on the URI plus query string only; the body is therefore outside the cache key and a body parameter can change the response while remaining unkeyed.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the cache strips the body before lookup (Varnish builtin.vcl), if proxy_cache_methods excludes GET with a body, if the response is not cacheable, or if the body parameter is part of the key, the primitive does not hold.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
-- Parameter cloaking hides a payload from the cache key: caches derive their key from URL parsing (regexes, semicolon and duplicate-parameter handling), so an attacker can feed a parameter that the cache treats as a single keyed parameter while the origin parses it differently and exposes a second, attacker-controlled parameter.  _(merged 1 duplicate row(s))_
+- Parameter cloaking hides a payload from the cache key: caches derive their key from URL parsing (regexes, semicolon and duplicate-parameter handling), so an attacker can feed a parameter that the cache treats as a single keyed parameter while the origin parses it differently and exposes a second, attacker-controlled parameter.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the cache and the origin parse the input identically, if the payload stays inside the key, or if the response is not cacheable, the entry is keyed and no poisoning occurs.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
 - When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.  _(merged 1 duplicate row(s))_
@@ -110,7 +110,7 @@
 
 ## Chaining opportunities
 
-- A cache poisoning chain links an unkeyed input at one tier to a second tier that keys differently: an attacker poisons the origin's cache through an unkeyed header, and the front-end CDN serves the poisoned entry to victims because its key omits the same input - one request by the attacker poisons a whole tier, and the payload (script, redirect, HSTS header or custom response header) is delivered to every visitor until the TTL expires.  _(merged 1 duplicate row(s))_
+- A cache poisoning chain links an unkeyed input at one tier to a second tier that keys differently: an attacker poisons the origin's cache through an unkeyed header, and the front-end CDN serves the poisoned entry to victims because its key omits the same input - one request by the attacker poisons a whole tier, and the payload (script, redirect, HSTS header or custom response header) is delivered to every visitor until the TTL expires.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the tiers agree on the key (one tier unkeys something the other keys, or both unkey the same input), or if the front-end never serves the poisoned entry (it revalidates, or the origin entry is separate), the chain does not hold.
   - Sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf> · <https://portswigger.net/research/practical-web-cache-poisoning>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 24 (supported 16), FP rules 3, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -130,7 +130,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/web/cache_poisoning/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
+Full class document: `skills/web/cache_poisoning/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 24 (supported 16), FP rules 3, chains 1, state mature

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -5,7 +5,8 @@
 
 # Web Cache Poisoning — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
