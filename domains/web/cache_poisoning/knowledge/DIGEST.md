# Web Cache Poisoning

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **mature** — 24 items, 16 supported, 3 FP rules, 1 chains

Unkeyed attacker input is reflected into a response the cache stores and serves to others.

**Aliases:** cache poisoning, web cache poisoning

## Signal

- **A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**  
  `high_confidence` · score 0.929 · disproved by: If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>

## Technique

- **A request header that changes the response but is absent from the cache key is unkeyed input: the origin's response is stored under a key that does not include that header, so every later request whose key matches - regardless of the header value - is served the attacker's response.**  
  `high_confidence` · score 0.948 · disproved by: No poisoning when the response is not cacheable (no-store, or private without s-maxage/proxy-revalidate), when the Authorization request triggers a shared-cache prohibition, when the header is part of the cache key (Vary or the configured key), or when the origin rejects the header.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws>
- **When a shared cache keys only on the request method and URI, or omits the Authorization header and Cookie from the key, an authenticated or personalized response can be stored under a shared key. A route that is cacheable for an authenticated request can then carry unkeyed attacker input, so the poisoned entry propagates to every user who hits the key, bypassing per-user boundaries.**  
  `high_confidence` · score 0.9365 · disproved by: If the cache key includes Authorization/Cookie (Vary or a structured key), if the route is not cacheable for authenticated requests, or if the internal and external tiers key identically, the entry is separated and the claim does not hold.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
- **A response with no explicit freshness directives (no Cache-Control max-age/s-maxage or Expires) is still a caching candidate: a shared cache may apply a heuristic expiration from other field values, so a poisoned entry without explicit directives can persist long after a naive 'not fresh' assessment and keep serving victims until the heuristic TTL expires.**  
  `high_confidence` · score 0.908 · disproved by: If the response carries explicit Cache-Control (no-store, no-cache, private without s-maxage) or the cache is configured to ignore heuristic freshness, or the entry predates the probe, the claim does not hold.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
- **The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**  
  `under_review` · score 0.8845 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The cache key is the information a cache uses to choose a response and is compos”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**  
  `high_confidence` · score 0.857 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A cache considers a stored response "fresh", as defined in Section 4.2 , if it c”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**  
  `high_confidence` · score 0.857 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When a cached response is not fresh, it might still be reusable if validation ca”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**  
  `high_confidence` · score 0.857 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**  
  `high_confidence` · score 0.802 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a cache receives a delta-seconds value greater than the greatest integer it c”) does not occur under a test that isolates that control.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>

## Test

- **To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.**  
  `under_review` · score 0.948 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.**  
  `under_review` · score 0.918 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
- **A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.**  
  `high_confidence` · score 0.8905 · disproved by: If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.
  sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>

## Validation

- **Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.**  
  `under_review` · score 0.984 · disproved by: If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.**  
  `high_confidence` · score 0.918 · disproved by: If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
  sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>

## Fp Rule

- **A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.**  
  `under_review` · score 0.954 · disproved by: A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
- **A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.**  
  `high_confidence` · score 0.893 · disproved by: It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.
  sources: <https://www.rfc-editor.org/rfc/rfc9111.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
- **Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.**  
  `high_confidence` · score 0.893 · disproved by: It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.
  sources: <https://www.rfc-editor.org/rfc/rfc9111.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
- **A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.**  
  `high_confidence` · score 0.8905 · disproved by: It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
  sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>

## Evidence

- **A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.**  
  `under_review` · score 0.918 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>

## Bypass

- **A 'fat GET' request - a GET carrying a message body - is not exempt from caching, and many caches key the entry on the URI plus query string only; the body is therefore outside the cache key and a body parameter can change the response while remaining unkeyed.**  
  `high_confidence` · score 0.948 · disproved by: If the cache strips the body before lookup (Varnish builtin.vcl), if proxy_cache_methods excludes GET with a body, if the response is not cacheable, or if the body parameter is part of the key, the primitive does not hold.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
- **Parameter cloaking hides a payload from the cache key: caches derive their key from URL parsing (regexes, semicolon and duplicate-parameter handling), so an attacker can feed a parameter that the cache treats as a single keyed parameter while the origin parses it differently and exposes a second, attacker-controlled parameter.**  
  `under_review` · score 0.948 · disproved by: If the cache and the origin parse the input identically, if the payload stays inside the key, or if the response is not cacheable, the entry is keyed and no poisoning occurs.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
- **When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.**  
  `high_confidence` · score 0.918 · disproved by: It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
  sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
- **nginx proxy_cache_convert_head (default on) converts HEAD requests to GET for caching, so a HEAD request's headers are processed by the origin and can change the stored response while the entry is filed under a key derived from GET semantics: the request method never enters the key.**  
  `high_confidence` · score 0.918 · disproved by: If the key includes the request method (conversion off), if the origin rejects HEAD, if the route is not cacheable, or if the poisoning header is part of the key, the attack does not hold.
  sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>

## Chain Link

- **A cache poisoning chain links an unkeyed input at one tier to a second tier that keys differently: an attacker poisons the origin's cache through an unkeyed header, and the front-end CDN serves the poisoned entry to victims because its key omits the same input - one request by the attacker poisons a whole tier, and the payload (script, redirect, HSTS header or custom response header) is delivered to every visitor until the TTL expires.**  
  `under_review` · score 1.0 · disproved by: If the tiers agree on the key (one tier unkeys something the other keys, or both unkey the same input), or if the front-end never serves the poisoned entry (it revalidates, or the origin entry is separate), the chain does not hold.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf> · <https://portswigger.net/research/practical-web-cache-poisoning>
