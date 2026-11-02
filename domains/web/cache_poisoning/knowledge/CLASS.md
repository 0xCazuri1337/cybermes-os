# Web Cache Poisoning

## Definition

Unkeyed attacker input is reflected into a response the cache stores and serves to others.

- **CWE:** 444
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["cache poisoning", "web cache poisoning"]

Canonical home for `cache_poisoning`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**

Diff pairs of requests that differ only in a header or an unusual parameter and compare the bodies; if the response changes while the cache slot does not, that input is unkeyed. Common unkeyed channels are the forwarded-host and forwarded-for headers, cookies, and parameters the origin reads from the request body rather than the query string. Then confirm the entry is actually stored and served to a different client by replaying a clean request from a separate session with no attacker headers. Cache keys may also be deliberately widened with extra material such as referrer identity, which shrinks the attack surface rather than enlarging it.

*Disproof:* If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.

**A convincing observation for this class is: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.**

Derived from cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.

## Exploitation

**A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**

he is a cache that stores responses for reuse by more than one user; shared caches are usually (but not always) deployed as a part of an intermediary. A private cache , in contrast, is dedicated to a single user; often, they are deployed as a component of a user agent. The goal of HTTP caching is significantly improving performance by reusing a prior response message to satisfy a current request. A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). A fresh response can therefore reduce both latency and network overhead each time the cache reuses it. When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). This document obsoletes RFC 7234 , with the changes being summarized in Appendix B . 1.1.   Requirements Notation The key words " MUST "

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A cache considers a stored response "fresh", as defined in Section 4.2 , if it c”) does not occur under a test that isolates that control.

**When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**

mproving performance by reusing a prior response message to satisfy a current request. A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). A fresh response can therefore reduce both latency and network overhead each time the cache reuses it. When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). This document obsoletes RFC 7234 , with the changes being summarized in Appendix B . 1.1.   Requirements Notation The key words " MUST ", " MUST NOT ", " REQUIRED ", " SHALL ", " SHALL NOT ", " SHOULD ", " SHOULD NOT ", " RECOMMENDED ", " NOT RECOMMENDED ", " MAY ", and " OPTIONAL " in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When a cached response is not fresh, it might still be reusable if validation ca”) does not occur under a test that isolates that control.

**If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**

me = [HTTP] , Section 5.1 >
 quoted-string = [HTTP] , Section 5.6.4 >
 token = [HTTP] , Section 5.6.2 >
 1.2.2.   Delta Seconds The delta-seconds rule specifies a non-negative integer, representing time in seconds. delta-seconds = 1* DIGIT 
 A recipient parsing a delta-seconds value and converting it to binary form ought to use an arithmetic type of at least 31 bits of non-negative integer range. If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent. Note: The value 2147483648 is here for historical reasons, represents infinity (over 68 years), and does not need to be stored in binary form; an implementation could produce it as a string if any overflow occurs, even if the calculations are performed with an arithmetic type incapable of directly representing that number. What matters here is that an overflow be detected and not treated as a neg

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a cache receives a delta-seconds value greater than the greatest integer it c”) does not occur under a test that isolates that control.

**Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**

e of directly representing that number. What matters here is that an overflow be detected and not treated as a negative value in later calculations. 2.   Overview of Cache Operation Proper cache operation preserves the semantics of HTTP transfers while reducing the transmission of information already held in the cache. See Section 3 of [HTTP] for the general terminology and core concepts of HTTP. Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. Therefore, HTTP cache requirements are focused on preventing a cache from either storing a non-reusable response or reusing a stored response inappropriately, rather than mandating that caches always store and reuse particular responses. The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the sto

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that”) does not occur under a test that isolates that control.

**The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**

it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. Therefore, HTTP cache requirements are focused on preventing a cache from either storing a non-reusable response or reusing a stored response inappropriately, rather than mandating that caches always store and reuse particular responses. The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request. However, many HTTP caches in common use today only cache GET responses and therefore only use the URI as the cache key. A cache might store multiple responses for a request target that is subject to content negotiation. Caches differentiate these responses by incorporating some of the original request's header fields into the cache key as well, using information in the Vary response header field,

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The cache key is the information a cache uses to choose a response and is compos”) does not occur under a test that isolates that control.

**If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent.**

me = [HTTP] , Section 5.1 >
 quoted-string = [HTTP] , Section 5.6.4 >
 token = [HTTP] , Section 5.6.2 >
 1.2.2.   Delta Seconds The delta-seconds rule specifies a non-negative integer, representing time in seconds. delta-seconds = 1* DIGIT 
 A recipient parsing a delta-seconds value and converting it to binary form ought to use an arithmetic type of at least 31 bits of non-negative integer range. If a cache receives a delta-seconds value greater than the greatest integer it can represent, or if any of its subsequent calculations overflows, the cache MUST consider the value to be 2147483648 (2 31 ) or the greatest positive integer it can conveniently represent. Note: The value 2147483648 is here for historical reasons, represents infinity (over 68 years), and does not need to be stored in binary form; an implementation could produce it as a string if any overflow occurs, even if the calculations are performed with an arithmetic type incapable of directly representing that number. What matters here is that an overflow be detected and not treated as a neg

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a cache receives a delta-seconds value greater than the greatest integer it c”) does not occur under a test that isolates that control.

**The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request.**

it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. Therefore, HTTP cache requirements are focused on preventing a cache from either storing a non-reusable response or reusing a stored response inappropriately, rather than mandating that caches always store and reuse particular responses. The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the stored response; the method determines under which circumstances that response can be used to satisfy a subsequent request. However, many HTTP caches in common use today only cache GET responses and therefore only use the URI as the cache key. A cache might store multiple responses for a request target that is subject to content negotiation. Caches differentiate these responses by incorporating some of the original request's header fields into the cache key as well, using information in the Vary response header field,

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The cache key is the information a cache uses to choose a response and is compos”) does not occur under a test that isolates that control.

**A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request).**

he is a cache that stores responses for reuse by more than one user; shared caches are usually (but not always) deployed as a part of an intermediary. A private cache , in contrast, is dedicated to a single user; often, they are deployed as a component of a user agent. The goal of HTTP caching is significantly improving performance by reusing a prior response message to satisfy a current request. A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). A fresh response can therefore reduce both latency and network overhead each time the cache reuses it. When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). This document obsoletes RFC 7234 , with the changes being summarized in Appendix B . 1.1.   Requirements Notation The key words " MUST "

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A cache considers a stored response "fresh", as defined in Section 4.2 , if it c”) does not occur under a test that isolates that control.

**Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it.**

e of directly representing that number. What matters here is that an overflow be detected and not treated as a negative value in later calculations. 2.   Overview of Cache Operation Proper cache operation preserves the semantics of HTTP transfers while reducing the transmission of information already held in the cache. See Section 3 of [HTTP] for the general terminology and core concepts of HTTP. Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that reusing a cached response is desirable and that such reuse is the default behavior when no requirement or local configuration prevents it. Therefore, HTTP cache requirements are focused on preventing a cache from either storing a non-reusable response or reusing a stored response inappropriately, rather than mandating that caches always store and reuse particular responses. The cache key is the information a cache uses to choose a response and is composed from, at a minimum, the request method and target URI used to retrieve the sto

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although caching is an entirely OPTIONAL feature of HTTP, it can be assumed that”) does not occur under a test that isolates that control.

**When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ).**

mproving performance by reusing a prior response message to satisfy a current request. A cache considers a stored response "fresh", as defined in Section 4.2 , if it can be reused without "validation" (checking with the origin server to see if the cached response remains valid for this request). A fresh response can therefore reduce both latency and network overhead each time the cache reuses it. When a cached response is not fresh, it might still be reusable if validation can freshen it ( Section 4.3 ) or if the origin is unavailable ( Section 4.2.4 ). This document obsoletes RFC 7234 , with the changes being summarized in Appendix B . 1.1.   Requirements Notation The key words " MUST ", " MUST NOT ", " REQUIRED ", " SHALL ", " SHALL NOT ", " SHOULD ", " SHOULD NOT ", " RECOMMENDED ", " NOT RECOMMENDED ", " MAY ", and " OPTIONAL " in this document are to be interpreted as described in BCP 14 [RFC2119] [RFC8174] when, and only when, they appear

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When a cached response is not fresh, it might still be reusable if validation ca”) does not occur under a test that isolates that control.

**When a shared cache keys only on the request method and URI, or omits the Authorization header and Cookie from the key, an authenticated or personalized response can be stored under a shared key. A route that is cacheable for an authenticated request can then carry unkeyed attacker input, so the poisoned entry propagates to every user who hits the key, bypassing per-user boundaries.**

PortSwigger's internal-cache-poisoning lab shows the effect exactly: the internal cache keys on the URI only while the external cache keys on host plus URI; the attacker's X-Forwarded-Host poisons the internal fragment, and the externally cached response still reflects the attacker's server because the internal cache's key omits the header. The same family of flaws covers a route that is not cacheable for anonymous users but is cacheable once the request carries a session cookie, after which the entry is shared. Practical checks: cache every candidate route through the production path, request them with and without authentication, and diff the keys; include the authentication context in the key test. Sources: PortSwigger internal cache poisoning lab, RFC 9111 (Vary), plus OWASP cheat sheet.

*Disproof:* If the cache key includes Authorization/Cookie (Vary or a structured key), if the route is not cacheable for authenticated requests, or if the internal and external tiers key identically, the entry is separated and the claim does not hold.

**A response with no explicit freshness directives (no Cache-Control max-age/s-maxage or Expires) is still a caching candidate: a shared cache may apply a heuristic expiration from other field values, so a poisoned entry without explicit directives can persist long after a naive 'not fresh' assessment and keep serving victims until the heuristic TTL expires.**

RFC 9111 section 4.2.2 states that, since origin servers do not always provide explicit expiration times, a cache MAY assign a heuristic expiration time using other field values (such as the Last-Modified time), subject to worst-case constraints, and MUST NOT apply heuristics when explicit freshness is present. Status codes defined as heuristically cacheable (RFC 9110: 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501) can be reused with heuristic expiration unless otherwise indicated. Age and Cache-Control headers on the response reveal the entry's real age and remaining lifetime. Practical checks: send the poisoned request with a probe header, then replay after the apparent expiry; if the marker persists, the cache used heuristics or the entry came from another tier. Sources: RFC 9111 (heuristics) plus RFC 9110 (heuristically cacheable status codes).

*Disproof:* If the response carries explicit Cache-Control (no-store, no-cache, private without s-maxage) or the cache is configured to ignore heuristic freshness, or the entry predates the probe, the claim does not hold.

**A request header that changes the response but is absent from the cache key is unkeyed input: the origin's response is stored under a key that does not include that header, so every later request whose key matches - regardless of the header value - is served the attacker's response.**

When an application uses an unkeyed header (for example X-Forwarded-Host, X-Forwarded-Proto or X-Host) to build an absolute URL inside the response - a script import, an Open Graph tag, a redirect Location - and the route is cacheable, one poisoned request stores the attacker's value under a shared key. Caching headers (Age, max-age) then define how long the malicious value survives, and X-Cache: hit demonstrates that the entry was served from the cache. Validation is a clean replay: send the poisoned request, then send a fresh request carrying the same URI and host but no injected header, and observe the marker in the response. PortSwigger's design-flaw lab uses X-Forwarded-Host to make the origin generate an import URL, the same primitive applying whenever the header influences the response and the key does not.

*Disproof:* No poisoning when the response is not cacheable (no-store, or private without s-maxage/proxy-revalidate), when the Authorization request triggers a shared-cache prohibition, when the header is part of the cache key (Vary or the configured key), or when the origin rejects the header.

## Variations

**A 'fat GET' request - a GET carrying a message body - is not exempt from caching, and many caches key the entry on the URI plus query string only; the body is therefore outside the cache key and a body parameter can change the response while remaining unkeyed.**

Varnish's builtin.vcl strips the body for GET requests because GET with a body is questionable, but some applications and frameworks genuinely accept a body on GET. An attacker sends GET /js/geolocate.js?callback=setCountryCookie with a Content-Length body of callback=arbitraryFunction; the cache key is derived from the query-string callback only, and the stored response contains the body-controlled function name, served to every user who later requests the URI. Practical checks: confirm proxy_cache_methods includes GET and HEAD, observe the stored response with and without the body, then replay a clean request and confirm the marker. Sources: PortSwigger Web Cache Entanglement plus RFC 9111.

*Disproof:* If the cache strips the body before lookup (Varnish builtin.vcl), if proxy_cache_methods excludes GET with a body, if the response is not cacheable, or if the body parameter is part of the key, the primitive does not hold.

**When a reverse proxy converts HEAD to GET for caching purposes, an attacker can seed a cache entry with a HEAD request whose headers are unkeyed, because the stored entry is filed under a key derived from GET semantics.**

nginx documents proxy_cache_convert_head as on by default and states the consequence directly: when the conversion is disabled the cache key should be configured to include the request method. That is the whole attack surface in one line. With conversion on, a HEAD request is served as if it were a GET for caching purposes, so any header that influences the origin's response generation - a Host override, a forwarded-prefix, an accept-language - is processed for a request whose method would otherwise not have populated the cache. A hunter testing only GET payloads can miss this entirely. Testing HEAD with the same unkeyed headers as the GET probe, then replaying a clean GET, covers it.

*Disproof:* It is not exploitable this way if the key already includes the request method, as nginx requires once conversion is off, or if the configuration appends $request_method to the key. It also fails as an attack if the origin rejects HEAD outright, or if the route is not cacheable, or if the poisoning header is actually part of the key. Confirm the key composition and the method handling before reporting.

**nginx proxy_cache_convert_head (default on) converts HEAD requests to GET for caching, so a HEAD request's headers are processed by the origin and can change the stored response while the entry is filed under a key derived from GET semantics: the request method never enters the key.**

With conversion on, a HEAD probe carrying an unkeyed header (X-Forwarded-Host, X-Forwarded-Scheme) lands in the cache as if it were a GET, and a clean GET from another user then retrieves the poisoned entry. Verification: disable conversion and include $request_method in the key, or the attack fails. Practical checks: send HEAD with the poisoning header, observe X-Cache: hit on the HEAD, then replay a clean GET and confirm the marker; compare against a HEAD probe with the header removed. Sources: nginx proxy module docs plus OWASP cheat sheet.

*Disproof:* If the key includes the request method (conversion off), if the origin rejects HEAD, if the route is not cacheable, or if the poisoning header is part of the key, the attack does not hold.

**Parameter cloaking hides a payload from the cache key: caches derive their key from URL parsing (regexes, semicolon and duplicate-parameter handling), so an attacker can feed a parameter that the cache treats as a single keyed parameter while the origin parses it differently and exposes a second, attacker-controlled parameter.**

Example (Varnish-style hash): a regex removes "?_=[^&]+&" from the hash URL, so the key does not contain the payload parameter but the origin still parses and reflects it. Semicolon trick: utm_content=foo;callback=arbitraryFunction - the cache keys only callback=setCountryCookie while the origin uses the last callback, overwriting the function on every imported script. Practical checks: compare the X-Cache-Key with the request and replay a clean request with the same key, then confirm the marker in the response. Sources: PortSwigger Web Cache Entanglement plus RFC 9111.

*Disproof:* If the cache and the origin parse the input identically, if the payload stays inside the key, or if the response is not cacheable, the entry is keyed and no poisoning occurs.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.cache_poisoning.auto.01` — cache_poisoning: observe, exercise, confirm (goal: `Establish, exercise and confirm a cache_poisoning condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A cached response that contains one user's data and is served to a different user proves the cache key omits the identity context, but reporting it as web cache poisoning is a category error when the attacker contributed no input of their own to the stored response.**

Cache poisoning requires an attacker's input to have altered the response that got stored; cache deception and cross-tenant leakage require only that a personalised response landed under a cacheable key. OWASP separates these: sensitive response exposure is a shared cache storing a personalised or authenticated response and returning it to another user, whereas web cache poisoning requires an attacker-controlled request input to change the response. A hunter who logs in as user A, then reads the same URL as user B and sees A's data, has established the key omission but not poisoning - the honest framing is that the cache is storing a personalised response, and the remediation differs, because fixing the key does not help when no attacker input exists to add to it.

*Disproof:* It IS poisoning if the attacker's own request contributed something to the stored response - a header value, a query parameter, or a body field that the origin reflected or used - and that contribution was excluded from the key while the entry was then replayed to other users. Show the attacker's marker in the stored body or in a generated URL and the poisoning classification is restored.

**Treating a Set-Cookie header on a response as proof that the response was not stored in a shared cache is a false negative, because cacheability is decided by the Cache-Control response directives and not by the presence of a cookie in the response.**

Hunters routinely see Set-Cookie on a login or personalised page and conclude that no shared cache could have kept it, then stop testing. OWASP's cache cheat sheet names this explicitly: a Set-Cookie header alone does not prevent caching, and the response directives are what govern storage and reuse. The field consequence is that a route can emit Set-Cookie on every response and still sit behind a shared cache that stores it, so an attacker's poisoned entry is delivered to every later visitor including anonymous ones. The practical check is to read the Cache-Control value, and if it is absent to look for a default cacheability in the CDN or reverse-proxy configuration rather than inferring one from the cookie.

*Disproof:* It IS a genuine non-cacheable response if Cache-Control carries no-store, or carries private with no s-maxage or proxy-revalidate override, or the request that stored it carried an Authorization header and no directive permitting shared storage. In that case the response cannot be replayed from a shared cache and a poisoning attempt against it will not persist. Demonstrate the directive, not the Set-Cookie header, and the reasoning holds.

**A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a different, uncorrupted victim request.**

Reflection is the precondition, not the finding. watchTowr's Sitecore research shows the two extra steps that turn reflection into poisoning on a real product: the response must actually be cached (caching there is opt-in per item, and the researchers had to work out how the cache key is generated before they could overwrite a legitimate entry), and the overwritten entry must then be served to someone who never sent the attacker's header. So reject on cacheability and on key collision: no-store/private, or a key derived from the reflecting header, means the attacker only ever poisons themselves. ZAP's guidance points at the same class of mistake from the other side, warning against deciding cache behaviour from the URL and file extension alone. Hunting value: this separates real poisoning from mere reflection, filtering static and per-user responses, private/no-store pages and anything varying on the reflecting header, which together are the bulk of Host and header reflection alerts.

*Disproof:* It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.

**A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.**

The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize. It is a precondition, not the finding. Reflection only proves the origin application passed the value through; the cache is a separate component with its own key, and poisoning is the observable consequence of the key omitting that value. Note also that a header-trust finding on its own can be misfiled in either direction: spoofing an IP address via a simple request header manipulation is a genuine bypass of a control that trusts the field, while a header that is merely present and ignored changes nothing. The distinguishing test is a differential replay: send the priming request with the injected header or parameter, then send a second request from a different client with a different cache key (different cookie jar, different query, no injected header at all) and look for the injected value in the response body. If the second, clean request returns the injected value, the cache is poisoned. If it returns the origin's own output, the correct classification is unkeyed reflection with no cache impact, and the fix is still the same but the severity is a hardening item rather than a cross-user compromise.

*Disproof:* A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.

## Validation

**Cache poisoning is proven only by replaying a clean request that carries none of the attacker's markers and observing the poisoned payload in the response, because the defining property is that the harmful response reaches a request the attacker did not craft.**

The OWASP definition is precise about what has to happen: an attacker-controlled input changes a response, that input is excluded from the cache key, and the harmful response is then served to other users. A payload that comes back only on requests that still carry the poisoning header proves nothing about the cache at all - it proves the origin reflects the header. The field test that isolates the cache is a two-step sequence: send the poisoning request once, then send an entirely fresh request with a different session, no special headers and no marker, ideally from a second connection, and look for the marker in the body or in a generated link. If it appears, the entry was stored under a key that did not include the poisoning input.

*Disproof:* If the marker appears only on requests carrying the original header, or only for the same session, or the replay returns a fresh origin response with an Age or X-Cache MISS indicator, then nothing was stored and there is no poisoning to report. Equally, if a purge or a Cache-Control: no-store change between the two steps removed the entry, the replay proves nothing about the original design.

**Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.**

Send the poisoning request, then request the same URL from a separate session with no attacker headers and no attacker cookies; if the injected content comes back, the cache stored it. Record how long the poisoned entry survives so the report states real blast radius rather than a theoretical one: the window is the response's freshness lifetime, which is explicit when the origin sets an expiry and heuristic when it does not. Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached. Re-run after the window closes to show the effect ends for the right reason.

*Disproof:* If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.

**To decide this case, observe: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header poisoning, unkeyed parameter poisoning, parameter cloaking, fat GET requests, and HTTP header oversize.**

Derived from cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning) states the full boundary.

**To decide this case, observe: Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached.**

Derived from cache_poisoning.validation.replay_and_ttl, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cache_poisoning.validation.replay_and_ttl) states the full boundary.

**A route that is later marked Cache-Control: no-store can still serve previously stored poisoned entries, so a re-test performed only after the fix will report clean and mask an ongoing exposure.**

OWASP calls out the operational trap: purging previously stored entries is required when changing a route to no-store, because the directive does not delete old entries. The consequence for a hunter's methodology is direct. If a team responds to a poisoning report by adding no-store and the reporter re-tests, the new requests are never stored but the entries written before the change are still in the CDN or reverse-proxy tier and are still being served to real users. The correct verification has two parts - confirm the header now appears on the response, and separately confirm that the previously poisoned URL no longer returns the marker. Only the second part demonstrates the exposure is actually closed.

*Disproof:* If the cache tier was purged as part of the fix, or the entries had already expired under their original freshness lifetime, or the marker is no longer reachable on the previously poisoned URL, then the response to the old poisoned request was itself affected and the re-test is meaningful. Note that a purge is exactly what a competent fix includes, so this item describes the verification requirement, not an assumption that the fix is incomplete.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (writeup)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Web_Cache_Security_Cheat_Sheet.html>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9111.html>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/>
- **nginx.org** (docs)
  - <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- **portswigger.net** (research)
  - <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
  - <https://portswigger.net/research/practical-web-cache-poisoning>
  - <https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws>
  - <https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-internal>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc9110.html>
  - <https://www.rfc-editor.org/rfc/rfc9111.html>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/>
  - <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/40039/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
