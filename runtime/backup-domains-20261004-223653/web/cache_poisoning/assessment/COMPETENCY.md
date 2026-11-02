# Methodology — Web Cache Poisoning

> Derived from 12 verified items. Regenerate with `python -m wks.methodgen --class cache_poisoning --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Unkeyed attacker input is reflected into a response the cache stores and serves to others.

**References.** CWE-444 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**

Diff pairs of requests that differ only in a header or an unusual parameter and compare the bodies; if the response changes while the cache slot does not, that input is unkeyed. Common unkeyed channels are the forwarded-host and forwarded-for headers, cookies, and parameters the origin reads from the request body rather than the query string. Then confirm the entry is actually stored and served to a different client by replaying a clean request from a separate session with no attacker headers. Cache keys may also be deliberately widened with extra material such as referrer identity, which shrinks the attack surface rather than enlarging it.

- *Disproof:* If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html); [snyk.io](https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/)

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.**

Send the poisoning request, then request the same URL from a separate session with no attacker headers and no attacker cookies; if the injected content comes back, the cache stored it. Record how long the poisoned entry survives so the report states real blast radius rather than a theoretical one: the window is the response's freshness lifetime, which is explicit when the origin sets an expiry and heuristic when it does not. Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached. Re-run after the window closes to show the effect ends for the right reason.

- *Disproof:* If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9111.html); [snyk.io](https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/)

**Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.**

The OWASP definition is precise about what has to happen: an attacker-controlled input changes a response, that input is excluded from the cache key, and the harmful response is then served to other users. A payload that comes back only on requests that still carry the poisoning header proves nothing about the cache at all - it proves the origin reflects the header. The field test that isolates the cache is a two-step sequence: send the poisoning request once, then send an entirely fresh request with a different session, no special headers and no marker, ideally from a second connection, and look for the marker in the body or in a generated link. If it appears, the entry was stored under a key that did not include the poisoning input.

- *Disproof:* If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html); [nginx.org](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.**

The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize. It is a precondition, not the finding. Reflection only proves the origin application passed the value through; the cache is a separate component with its own key, and poisoning is the observable consequence of the key omitting that value. Note also that a header-trust finding on its own can be misfiled in either direction: spoofing an IP address via a simple request header manipulation is a genuine bypass of a control that trusts the field, while a header that is merely present and ignored changes nothing. The distinguishing test is a differential replay: send the priming request with the injected header or parameter, then send a second request from a different client with a different cache key (different cookie jar, different query, no injected header at all) and look for the injected value in the response body. If the second, clean request returns the injected value, the cache is poisoned. If it returns the origin's own output, the correct classification is unkeyed reflection with no cache impact, and the fix is still the same but the severity is a hardening item rather than a cross-user compromise.

- *Disproof:* A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/); [proofpoint.com](https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365)

**A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.**

Reflection is the precondition, not the finding. watchTowr's Sitecore research shows the two extra steps that turn reflection into poisoning on a real product: the response must actually be cached (caching there is opt-in per item, and the researchers had to work out how the cache key is generated before they could overwrite a legitimate entry), and the overwritten entry must then be served to someone who never sent the attacker's header. So reject on cacheability and on key collision: no-store/private, or a key derived from the reflecting header, means the attacker only ever poisons themselves. ZAP's guidance points at the same class of mistake from the other side, warning against deciding cache behaviour from the URL and file extension alone. Hunting value: this separates real poisoning from mere reflection, filtering static and per-user responses, private/no-store pages and anything varying on the reflecting header, which together are the bulk of Host and header reflection alerts.

- *Disproof:* It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.
- *Evidence:* high_confidence — [labs.watchtowr.com](https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/); [zaproxy.org](https://www.zaproxy.org/docs/alerts/40039/)

**A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.**

Cache poisoning requires an attacker's input to have altered the response that got stored; cache deception and cross-tenant leakage require only that a personalised response landed under a cacheable key. OWASP separates these: sensitive response exposure is a shared cache storing a personalised or authenticated response and returning it to another user, whereas web cache poisoning requires an attacker-controlled request input to change the response. A hunter who logs in as user A, then reads the same URL as user B and sees A's data, has established the key omission but not poisoning - the honest framing is that the cache is storing a personalised response, and the remediation differs, because fixing the key does not help when no attacker input exists to add to it.

- *Disproof:* It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9111.html)

**Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.**

Hunters routinely see Set-Cookie on a login or personalised page and conclude that no shared cache could have kept it, then stop testing. OWASP's cache cheat sheet names this explicitly: a Set-Cookie header alone does not prevent caching, and the response directives are what govern storage and reuse. The field consequence is that a route can emit Set-Cookie on every response and still sit behind a shared cache that stores it, so an attacker's poisoned entry is delivered to every later visitor including anonymous ones. The practical check is to read the Cache-Control value, and if it is absent to look for a default cacheability in the CDN or reverse-proxy configuration rather than inferring one from the cookie.

- *Disproof:* It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9111.html)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.**

nginx documents proxy_cache_convert_head as on by default and states the consequence directly: when the conversion is disabled the cache key should be configured to include the request method. That is the whole attack surface in one line. With conversion on, a HEAD request is served as if it were a GET for caching purposes, so any header that influences the origin's response generation - a Host override, a forwarded-prefix, an accept-language - is processed for a request whose method would otherwise not have populated the cache. A hunter testing only GET payloads can miss this entirely. Testing HEAD with the same unkeyed headers as the GET probe, then replaying a clean GET, covers it.

- *Disproof:* It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html); [nginx.org](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Test sequence, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
