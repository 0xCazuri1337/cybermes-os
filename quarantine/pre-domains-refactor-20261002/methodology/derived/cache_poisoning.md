# Methodology — Web Cache Poisoning

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class cache_poisoning --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Unkeyed attacker input is reflected into a response the cache stores and serves to others.

**References.** CWE-444 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A request header or parameter that changes the response body but is absent from the cache key is the precondition for web cache poisoning.**

Diff pairs of requests that differ only in a header or an unusual parameter and compare the bodies; if the response changes while the cache slot does not, that input is unkeyed. Common unkeyed channels are the forwarded-host and forwarded-for headers, cookies, and parameters the origin reads from the request body rather than the query string. Then confirm the entry is actually stored and served to a different client by replaying a clean request from a separate session with no attacker headers. Cache keys may also be deliberately widened with extra material such as referrer identity, which shrinks the attack surface rather than enlarging it.

- *Disproof:* If the response is identical with and without the header, or the cache refuses to store the response (no freshness information, cache-control no-store), there is no poisoning primitive.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9111.html); [snyk.io](https://snyk.io/blog/cache-poisoning-in-popular-open-source-packages/)

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.**

Send the poisoning request, then request the same URL from a separate session with no attacker headers and no attacker cookies; if the injected content comes back, the cache stored it. Record how long the poisoned entry survives so the report states real blast radius rather than a theoretical one: the window is the response's freshness lifetime, which is explicit when the origin sets an expiry and heuristic when it does not. Where the origin sends no explicit caching directives, note that heuristic freshness may still apply, so absence of an Expires header is not evidence the entry is not cached. Re-run after the window closes to show the effect ends for the right reason.

- *Disproof:* If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9111.html); [snyk.io](https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/)

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

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Test sequence, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
