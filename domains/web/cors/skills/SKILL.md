---
name: cors-hunting
description: Use when hunting CORS Misconfiguration in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# CORS Misconfiguration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 942 · OWASP A05:2021
> evidence: 30 items, 14 supported, 7 FP rules, 1 chains
> maturity: **mature**

The cross-origin policy grants a foreign origin more access than intended.

**Also called:** cors, cross origin resource sharing, cors misconfiguration


## Prerequisites (do not start without these)

- A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.
  - **Disproof:** If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
  - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Recon signals (where to look)

- An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.
  - **Disproof:** If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
  - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Techniques (what to change)

- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
- Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This CORS configuration permits any origin to interact with your application, opening the ".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Anothe".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) . _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- This approach allows the client to cache the server’s CORS policy information for a specified time. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.
  - **Disproof:** The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.
  - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing. _(unverified)_
  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
  - Sources: <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.
  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>

## Tests

- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.wildcard_allow_origin_plus_allow_credentials_is_blocked_by_the_browser) states the full boundary.
  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.missing_allow_origin_header_is_a_block_not_a_misconfiguration) states the full boundary.
  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>

## Validation bar (how to prove it)

- Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it.
  - **Disproof:** The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.
  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>

## False-positive rules (when to reject it)

- Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.
  - **Disproof:** The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.
  - Sources: <https://www.zaproxy.org/docs/alerts/40040-3/> · <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
- An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.
  - **Disproof:** A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
- An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body.
  - **Disproof:** The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.
  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
- A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails.
  - **Disproof:** The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.
  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>

## Evidence requirements

- A single hand-sent OPTIONS probe is not valid evidence of what a browser will do, because the browser caches the preflight decision for the number of seconds given by `Access-Control-Max-Age` (5 by default) and will answer the real request from that cache without re-probing the server.
  - **Disproof:** The claim is false if the evidence set includes two independent observations: the raw OPTIONS exchange itself plus a browser-side trace (DevTools network panel or HAR) showing the subsequent cross-origin request either issuing a fresh preflight or reusing a cached one, which establishes what the user agent actually did rather than what the server would have answered.
  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>

## Defence bypasses

- When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO.
  - **Disproof:** The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.
  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>

## Rejected before you report

- **A CORS endpoint reflects an arbitrary attacker Origin with Access-Control-Allow-Credentials:true, therefore an attacker's page can steal the victim's data**
  - Killed by: The cited paths returned a byte-identical application shell rather than JSON and appear nowhere in the bundle; the application keys every data call on an Authorization or caller-supplied token, so the browser never attaches a credential cross-origin; zero Set-Cookie on any path, so there is nothing for the attacker's page to read; and the client never uses credentials:'include'
  - Rule: Reflection plus ACAC:true is only credential theft when a secret is keyed on something the browser attaches automatically. Prove a cookie-keyed or ambient-credential read exists on the SAME path: a Set-Cookie, a cookie-backed data call, or credentials:'include' actually used in the client. If the data is Authorization-keyed, there is no cross-origin read to perform
- **CORS reflection on one host and session cookies on another host means the account family is vulnerable to cross-origin credential theft**
  - Killed by: No host in the family had all three. Reflect-only hosts issued no cookie and their canonical data paths 404'd; cookie-only hosts emitted no CORS headers at all; one host pinned ACAO to a fixed developer origin with no reflection
  - Rule: The exploitable condition is CONJUNCTIVE and lives on a single path: arbitrary-Origin reflection AND ACAC:true AND a cookie on that same path. Reflection on host A with cookies on host B is two harmless facts, not a finding - probe for the combination before reporting it
- **A hardcoded Access-Control-Allow-Origin value in the response plus Access-Control-Allow-Credentials:true is an exploitable CORS misconfiguration**
  - Killed by: The ACAO value was byte-identical regardless of the Origin sent - the server pinned it rather than reflecting. A pinned ACAO cannot be matched by an attacker origin, so the browser blocks the credentialed read
  - Rule: CORS reflection requires the ACAO value to CHANGE with the Origin header. Send an attacker Origin and a second arbitrary Origin and compare: identical values are a pinned allowlist, and pinned-plus-ACAC is not exploitable. Word the finding as 'reflects' only after you have observed it vary

---
Full class document: `domains/web/cors/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
