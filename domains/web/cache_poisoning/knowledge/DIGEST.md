# Web Cache Poisoning

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

Unkeyed attacker input is reflected into a response the cache stores and serves to others.

**Aliases:** cache poisoning, web cache poisoning

## Signal

- **A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**  
  `high_confidence` · score 0.984 · disproved by: If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>

## Technique

- **The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The cache key is the information a cache uses to choose a response and is composed from, a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reus".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When a cached response is not fresh, it might still be reusable if validation can freshen ".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a cache receives a delta-seconds value greater than the greatest integer it can represe".
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>

## Validation

- **Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.**  
  `high_confidence` · score 0.984 · disproved by: If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>

## Fp Rule

- **A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.**  
  `high_confidence` · score 0.954 · disproved by: A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
  sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
- **A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.**  
  `high_confidence` · score 0.8905 · disproved by: It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
  sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.zaproxy.org/docs/alerts/40039/>
