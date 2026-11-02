# Web Cache Poisoning

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **mature** — 22 items, 12 supported, 4 FP rules, 1 chains

Unkeyed attacker input is reflected into a response the cache stores and serves to others.

**Aliases:** cache poisoning, web cache poisoning

## Signal

- **A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**  
  `high_confidence` · score 0.929 · disproved by: If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>

## Technique

- **The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**  
  `under_review` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**  
  `under_review` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**  
  `under_review` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**  
  `under_review` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>

## Test

- **To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.**  
  `high_confidence` · score 0.948 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.**  
  `high_confidence` · score 0.918 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
- **A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.**  
  `high_confidence` · score 0.8655 · disproved by: If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>

## Validation

- **Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.**  
  `high_confidence` · score 0.984 · disproved by: If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.**  
  `high_confidence` · score 0.893 · disproved by: If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>

## Fp Rule

- **A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.**  
  `high_confidence` · score 0.954 · disproved by: A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
- **A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.**  
  `high_confidence` · score 0.8905 · disproved by: It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
  sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
- **A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.**  
  `high_confidence` · score 0.838 · disproved by: It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>
- **Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.**  
  `high_confidence` · score 0.838 · disproved by: It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://www.rfc-editor.org/rfc/rfc9111.html>

## Evidence

- **A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.**  
  `high_confidence` · score 0.918 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>

## Bypass

- **When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.**  
  `high_confidence` · score 0.893 · disproved by: It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
