# Web Cache Poisoning

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **researching** — 4 items, 4 supported, 2 FP rules, 0 chains

Unkeyed attacker input is reflected into a response the cache stores and serves to others.

**Aliases:** cache poisoning, web cache poisoning

## Signal

- **A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**  
  `high_confidence` · score 0.984 · disproved by: If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>

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

## Known gaps

Not yet satisfied: `items`, `chain`
