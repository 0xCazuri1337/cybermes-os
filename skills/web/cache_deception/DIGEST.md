<!-- GENERATED from db/wks.db — do not edit -->
# Web Cache Deception

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **mature** — 18 items, 10 supported, 2 FP rules, 1 chains

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

## Validation

- **Web cache deception is proved by a second request for the same URL, made with a different or absent session, returning the first client's data — the shared cached object is the evidence, not the fact that the URL contains an extension.**  
  `high_confidence` · score 0.8655 · disproved by: The claim is false when the cache varies on a header or cookie and the second client sends a different one, in which case a different object is legitimately served and the deception has not occurred; the test must hold the cache-key components constant while changing only the identity.
  sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://firebase.google.com/docs/hosting/full-config>

## Fp Rule

- **A repeat request for a public, unauthenticated, immutable asset returning an Age header and a CDN edge name is the caching layer working as designed, not cache deception: nothing in the response is personalised to the requester.**  
  `high_confidence` · score 0.8965 · disproved by: The rule is wrong, and it IS deception, if: an authenticated response to the same URL returns content the anonymous request does not receive, and that content is then served to the anonymous or to a second authenticated identity; a Set-Cookie, session identifier, personal name, account balance, or internal hostname from the first identity appears in the cached copy served to another; or the response is stored despite Cache-Control: private or Set-Cookie with a no-store attribute, which is a caching-policy failure rather than intended behaviour. The discriminator is always cross-identity content, never the cache header itself.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **Appending a fake static extension to a path and getting a 200 is not web cache deception on its own; the finding requires the cached body to contain the requesting user's data, because a static-file miss that returns the application's normal 404 page caches only public content.**  
  `high_confidence` · score 0.893 · disproved by: The rule is wrong when the origin serves the same dynamic content for any path that merely looks static — a single-page app shell, a catch-all rewrite, or a server that ignores unknown extensions — in which case the cached object is the authenticated user's page and the deception is real even though nothing about the path was ever a static file.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/>

## Evidence

- **The observation that distinguishes cache deception from ordinary caching is a cache HIT served for a URL that the origin never had as a static file, since a normal cache entry is only ever created for a resource the origin actually produced.**  
  `high_confidence` · score 0.8815 · disproved by: The claim is false when the origin does have a matching static file and the deception succeeded on a different URL form, or when the edge reports the HIT for a request whose cache lookup was actually a revalidation rather than a stored object; the X-Cache/AGE header values and the file inventory must both be captured before treating the HIT as evidence.
  sources: <https://developers.cloudflare.com/cache/how-to/cache-rules/settings/> · <https://developers.cloudflare.com/cache/how-to/configure-cache-status-code/> · <https://firebase.google.com/docs/hosting/full-config>

## Chain Link

- **When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key weakness into cross-user session compromise rather than a self-inflicted reflection.**  
  `high_confidence` · score 0.9485 · disproved by: The chain is refuted if any link fails: the deployment has no shared cache in front of the personalised path, so the stored copy never reaches a second user; the response carries Cache-Control: private or Set-Cookie with no-store, which stops the shared tier storing it; Vary correctly names the unkeyed input and the cache honours it, splitting the stored responses by that header; or the personalised page carries no session-dependent content, so the second visitor receives an identical body and nothing is disclosed. Demonstrate the cross-identity read before asserting takeover.
  sources: <https://httpwg.org/specs/rfc9111.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>

## Vulnerability

- **Web cache deception forces a shared cache (CDN, reverse proxy, or other intermediate HTTP agent) to store a victim's personalized response under a URL the attacker controls, because the cache and the origin disagree about what a URL means: the cache keys requests on URL shape while the origin maps the same URL to a private, per-user resource.**  
  `high_confidence` · score 0.964 · disproved by: The attack does not exist when the cache and the origin apply identical URL normalization and path mapping, when every authenticated or otherwise sensitive response carries Cache-Control: no-store or private, when cache rules cannot override Cache-Control directives, and when no sensitive response is reachable under a URL the cache would classify as a static asset.
  sources: <https://cwe.mitre.org/data/definitions/444.html> · <https://www.rfc-editor.org/rfc/rfc9111.html> · <https://portswigger.net/web-security/web-cache-deception>
- **Attackers bypass cache deception defenses using path-confusion, normalization, delimiter, and unkeyed-header discrepancies, and the impact ranges from authenticated profile and email theft to full account takeover when the cached private response contains tokens, session IDs, CSRF tokens, or API keys.**  
  `high_confidence` · score 0.905 · disproved by: The attack does not exist when the cache and the origin agree on path normalization and delimiter handling, when no sensitive response is stored under a long-lived cache entry, when responses vary correctly on every unkeyed input through the Vary header (including when the CDN implements Vary as configured), and when Cache-Control: no-store is honored by the cache rather than overridden by extension- or directory-based cache rules.
  sources: <https://github.com/dmbs335/the-map/blob/main/08-infrastructure/web-cache-poisoning-and-deception.md> · <https://github.com/harshdhamaniya/web-application-security/blob/main/22-caching-attacks/README.md> · <https://masaaki.tech/blog/cybersec/ethical-hacking/web-cache-attacks/> · <https://raw.githubusercontent.com/OWASP/Top10/master/2021/docs/en/A04_2021-Insecure_Design.md>
- **Web cache deception tricks a shared cache (reverse proxy/CDN) into storing a sensitive, authenticated dynamic response against a static-looking URL, letting an attacker retrieve another user's private content by re-requesting that URL.**  
  `high_confidence` · score 0.89 · disproved by: A cache that normalizes or ignores the request path before caching, or an application that returns Cache-Control: private / no-store on authenticated responses, neutralizes the attack. If re-requesting the deceptive URL yields a cache miss or a response without sensitive content, the deception is disproven.
  sources: <https://portswigger.net/kb/issues/00200650_web-cache-deception> · <https://portswigger.net/web-security/web-cache-deception> · <https://www.usenix.org/system/files/sec22summer_mirheidari.pdf>
