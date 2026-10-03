# Web Cache Deception

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **mature** — 13 items, 13 supported, 2 FP rules, 1 chains

A cache stores a personalised response under a key that other users can request.

**Aliases:** cache deception, web cache deception

## Prerequisite

- **Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.**  
  `high_confidence` · score 0.96 · disproved by: The claim is wrong, and no shared cache is in front of the path, if: every response to the authenticated request carries a restrictive Set-Cookie directive and no Age or cache-hit header on any fetch; a second, unrelated user session receives their own distinct personalised body rather than the first user's; or the origin is reached directly with no intermediary hop visible in response headers, timing, or server configuration, so nothing outside the browser holds a copy. Any of those removes the shared-store precondition the whole class rests on.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>

## Technique

- **When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body under a key other users will request.**  
  `high_confidence` · score 0.93 · disproved by: The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
- **A pre-authentication HTML cache poisoning vulnerability that reflects attacker-controlled input into a cached response lets a single unauthenticated request contaminate a shared cache and serve attacker content to later, unrelated visitors.**  
  `high_confidence` · score 0.918 · disproved by: A cache layer configured with per-request cache keys and no reflected header or body reaching a stored response would refute the claim.
  sources: <https://labs.watchtowr.com/cache-me-if-you-can-sitecore-experience-platform-cache-poisoning-to-rce/> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **It is a fully integrated API that gives developers capabilities such as the ability to make changes to the cache properties of an object, adjust headers like Cache-Control, and more, all within the context of an HTTP flow.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It is a fully integrated API that gives developers capabilities such as the ability to mak".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **Benefit: This capability enables developers to store optimized versions of content in the cache, reducing processing time and improving delivery speed.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Benefit: This capability enables developers to store optimized versions of content in the ".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>
- **HTTP Cache APIs allow developers to do something they have never been able to do before with Compute.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP Cache APIs allow developers to do something they have never been able to do before wi".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.fastly.com/blog/cache-me-if-you-can-http-cache-api-edition>

## Validation

- **An unauthenticated probe whose path differs from a user's request only by a decoy suffix, yet returns that user's response body from a shared cache, proves cache deception.**  
  `high_confidence` · score 0.944 · disproved by: If the suffixed unauthenticated probe returns 401, an empty body, or a response with no Age header from a shared cache, then no cache deception is present and the difference was ordinary authorization.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://www.w3.org/TR/fetch-metadata/>

## Fp Rule

- **Reject a cache_deception finding until it is distinguished from the adjacent behaviour this class also covers. "When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key..." and "When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8965 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "When a cache keys only on method and target URI while the origin varie" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.**  
  `high_confidence` · score 0.8965 · disproved by: The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>

## Chain Link

- **When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key weakness into cross-user session compromise rather than a self-inflicted reflection.**  
  `high_confidence` · score 0.9485 · disproved by: The chain is refuted if any link fails: the deployment has no shared cache in front of the personalised path, so the stored copy never reaches a second user; the response carries Cache-Control: private or Set-Cookie with no-store, which stops the shared tier storing it; Vary correctly names the unkeyed input and the cache honours it, splitting the stored responses by that header; or the personalised page carries no session-dependent content, so the second visitor receives an identical body and nothing is disclosed. Demonstrate the cross-identity read before asserting takeover.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
