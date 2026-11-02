# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 21 (supported 21), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 21 (supported 21), FP rules 2, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -94,4 +94,4 @@
   - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
 
 ---
-Full class document: `domains/web/cors/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
+Full class document: `domains/web/cors/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
```

## 2026-10-02 19:37 — 129 diff lines
- items: 30 (supported 14), FP rules 4, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 21 items, 21 supported, 2 FP rules, 1 chains
+> evidence: 30 items, 14 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -32,49 +32,49 @@
 
 ## Techniques (what to change)
 
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).
+- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
-- Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.
+- Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.
+- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This CORS configuration permits any origin to interact with your application, opening the ".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.
+- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.
+- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Anothe".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.
+- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .
+- Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) . _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.
+- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.
+- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.
+- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- This approach allows the client to cache the server’s CORS policy information for a specified time.
+- This approach allows the client to cache the server’s CORS policy information for a specified time. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.
+- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.
+- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).
+- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
-- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.
+- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 - An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.
@@ -84,6 +84,27 @@
   - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
   - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
 
+## Tests
+
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly sp _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.wildcard_allow_origin_plus_allow_credentials_is_blocked_by_the_browser) states the full boundary.
+  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: htt
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.missing_allow_origin_header_is_a_block_not_a_misconfiguration) states the full boundary.
+  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
+- To decide this case, observe: Mechanism: Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposi
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.validation.origin_reflection_is_only_provable_by_an_actual_credentialed_read) states the full boundary.
+  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
+- To decide this case, observe: the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request an
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.bypass.the_preflight_is_the_control_that_actually_blocks_side_effecting_cross_origin_requests) states the full boundary.
+  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
+
+## Validation bar (how to prove it)
+
+- Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it.
+  - **Disproof:** The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.
+  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
+
 ## False-positive rules (when to reject it)
 
 - Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.
@@ -92,6 +113,24 @@
 - An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.
   - **Disproof:** A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
   - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
+- An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body.
+  - **Disproof:** The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.
+  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
+- A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails.
+  - **Disproof:** The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.
+  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
+
+## Evidence requirements
+
+- A single hand-sent OPTIONS probe is not valid evidence of what a browser will do, because the browser caches the preflight decision for the number of seconds given by `Access-Control-Max-Age` (5 by default) and will answer the real request from that cache without re-probing the server.
+  - **Disproof:** The claim is false if the evidence set includes two independent observations: the raw OPTIONS exchange itself plus a browser-side trace (DevTools network panel or HAR) showing the subsequent cross-origin request either issuing a fresh preflight or reusing a cached one, which establishes what the user agent actually did rather than what the server would have answered.
+  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
... (truncated)
```

## 2026-10-03 01:46 — 61 diff lines
- items: 30 (supported 14), FP rules 4, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -34,7 +34,7 @@
 
 - CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
 - Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
@@ -73,7 +73,7 @@
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 - CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
 - However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
@@ -82,22 +82,22 @@
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 - Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.
   - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
-  - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
+- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing. _(unverified)_
+  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
+  - Sources: <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
+- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.
+  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
 
 ## Tests
 
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly sp _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.wildcard_allow_origin_plus_allow_credentials_is_blocked_by_the_browser) states the full boundary.
   - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: htt
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.missing_allow_origin_header_is_a_block_not_a_misconfiguration) states the full boundary.
   - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
-- To decide this case, observe: Mechanism: Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposi
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.validation.origin_reflection_is_only_provable_by_an_actual_credentialed_read) states the full boundary.
-  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
-- To decide this case, observe: the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request an
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.bypass.the_preflight_is_the_control_that_actually_blocks_side_effecting_cross_origin_requests) states the full boundary.
-  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
 
 ## Validation bar (how to prove it)
 
@@ -112,7 +112,7 @@
   - Sources: <https://www.zaproxy.org/docs/alerts/40040-3/> · <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
 - An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.
   - **Disproof:** A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
-  - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
 - An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body.
   - **Disproof:** The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.
   - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
```

## 2026-10-03 05:00 — 29 diff lines
- items: 30 (supported 14), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 30 items, 14 supported, 4 FP rules, 1 chains
+> evidence: 30 items, 14 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -132,5 +132,17 @@
   - **Disproof:** The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.
   - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
 
+## Rejected before you report
+
+- **A CORS endpoint reflects an arbitrary attacker Origin with Access-Control-Allow-Credentials:true, therefore an attacker's page can steal the victim's data**
+  - Killed by: The cited paths returned a byte-identical application shell rather than JSON and appear nowhere in the bundle; the application keys every data call on an Authorization or caller-supplied token, so the browser never attaches a credential cross-origin; zero Set-Cookie on any path, so there is nothing for the attacker's page to read; and the client never uses credentials:'include'
+  - Rule: Reflection plus ACAC:true is only credential theft when a secret is keyed on something the browser attaches automatically. Prove a cookie-keyed or ambient-credential read exists on the SAME path: a Set-Cookie, a cookie-backed data call, or credentials:'include' actually used in the client. If the data is Authorization-keyed, there is no cross-origin read to perform
+- **CORS reflection on one host and session cookies on another host means the account family is vulnerable to cross-origin credential theft**
+  - Killed by: No host in the family had all three. Reflect-only hosts issued no cookie and their canonical data paths 404'd; cookie-only hosts emitted no CORS headers at all; one host pinned ACAO to a fixed developer origin with no reflection
+  - Rule: The exploitable condition is CONJUNCTIVE and lives on a single path: arbitrary-Origin reflection AND ACAC:true AND a cookie on that same path. Reflection on host A with cookies on host B is two harmless facts, not a finding - probe for the combination before reporting it
+- **A hardcoded Access-Control-Allow-Origin value in the response plus Access-Control-Allow-Credentials:true is an exploitable CORS misconfiguration**
+  - Killed by: The ACAO value was byte-identical regardless of the Origin sent - the server pinned it rather than reflecting. A pinned ACAO cannot be matched by an attacker origin, so the browser blocks the credentialed read
+  - Rule: CORS reflection requires the ACAO value to CHANGE with the Origin header. Send an attacker Origin and a second arbitrary Origin and compare: identical values are a pinned allowlist, and pinned-plus-ACAC is not exploitable. Word the finding as 'reflects' only after you have observed it vary
+
 ---
 Full class document: `domains/web/cors/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
```

## 2026-10-04 00:43 — 195 diff lines
- items: 30 (supported 14), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -20,115 +20,106 @@
 
 ## Prerequisites (do not start without these)
 
-- A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.
+- A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
   - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 
 ## Recon signals (where to look)
 
-- An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.
+- An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.  _(merged 1 duplicate row(s))_
   - **Disproof:** If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
   - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 
 ## Techniques (what to change)
 
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
+- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
+- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
+- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
-- Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. _(unverified)_
+- Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
+  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
+- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability. _(unverified)_
+- Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This CORS configuration permits any origin to interact with your application, opening the ".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".
+- This approach allows the client to cache the server’s CORS policy information for a specified time.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option. _(unverified)_
+- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Anothe".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) . _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- This approach allows the client to cache the server’s CORS policy information for a specified time. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
-  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
-- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.
-  - **Disproof:** The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
-  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
-- Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.
-  - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
-  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
-- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing. _(unverified)_
-  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
-  - Sources: <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
-- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.
-  - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
-  - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
 
... (truncated)
```

## 2026-10-04 00:50 — 16 diff lines
- items: 30 (supported 14), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -138,10 +138,9 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Send Origin: https://your-collaborator-domain with Access-Control-Request-Method set, and read Access-Control-Allow-Origin and Access-Control-Allow-Credentials in the response.
+2. Only test with an authenticated session, and confirm the reflected origin is not a substring match or a regex like https://evil.*.
+3. Prove read impact by fetching a response only that session can see.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 30 (supported 14), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -151,6 +151,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/cors/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 92 diff lines
- items: 30 (supported 27), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 30 items, 14 supported, 7 FP rules, 1 chains
+> evidence: 30 items, 27 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -32,38 +32,38 @@
 
 ## Techniques (what to change)
 
-- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".
+- 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' ,”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 - An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
-- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".
+- As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“As helpful as CORS is, improper implementation can expose your Node.js applicati”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 - CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
-- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".
+- CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS lets web applications bypass SOP limitations, enabling communication betwee”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".
+- CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS security implications and best practices If we don't configure CORS correct”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
+- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of”) does not occur under a test that isolates that control.
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
 - Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
-- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".
+- Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Enable CORS for specific origins You can set the origin option in your CORS sett”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
+- However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, it requires some content security policy (CSP) configuration to enable ”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".
+- Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Misconfigurations may reveal sensitive data to unintended origins or allow malic”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 - Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
@@ -71,17 +71,17 @@
 - Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This CORS configuration permits any origin to interact with your application, opening the ".
+- This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This CORS configuration permits any origin to interact with your application, op”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- This approach allows the client to cache the server’s CORS policy information for a specified time.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".
+- This approach allows the client to cache the server’s CORS policy information for a specified time.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This approach allows the client to cache the server’s CORS policy information fo”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".
+- corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight reque”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Anothe".
+- corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed head”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
 
 ## Tests
```

## 2026-10-07 00:47 — 1 DoD-session rule (pre-gate, no skillgen run)
- items: unchanged; 1 FP-kill rule filed in `research/pending/fp/fp-dod-session-2026-10-03.json` (source: `/mnt/e/bugbounty/DOD/sessions/2026-10-03-kh/findings/triage-verdict.md`)

```diff
--- cors@current
+++ cors@pending
+- cors.fprule.wildcard_acao_acac_invalid: ACAO `*` + ACAC true is invalid per the Fetch spec (browser makes the body opaque to credentialed CORS). Compound kill: a cross-origin 401 with zero-byte body has no data to steal, and permissive CORS without demonstrated impact is class-excluded.
```

## 2026-10-28 14:45 — 42 diff lines
- items: 26 (supported 24), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 30 items, 27 supported, 7 FP rules, 1 chains
+> evidence: 26 items, 24 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -41,7 +41,7 @@
 - As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“As helpful as CORS is, improper implementation can expose your Node.js applicati”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.  _(merged 2 duplicate row(s))_ _(unverified)_
+- CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.  _(merged 1 duplicate row(s))_
   - **Disproof:** gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
 - CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.  _(merged 1 duplicate row(s))_
@@ -50,7 +50,7 @@
 - CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS security implications and best practices If we don't configure CORS correct”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 2 duplicate row(s))_
+- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of”) does not occur under a test that isolates that control.
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
 - Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.  _(merged 1 duplicate row(s))_
@@ -83,12 +83,6 @@
 - corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed head”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-
-## Tests
-
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.wildcard_allow_origin_plus_allow_credentials_is_blocked_by_the_browser) states the full boundary.
-  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-28 21:00 — 59 diff lines
- items: 32 (supported 30), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 26 items, 24 supported, 7 FP rules, 1 chains
+> evidence: 32 items, 30 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -23,6 +23,9 @@
 - A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
   - Sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- CORS-safelisted methods (GET, HEAD, POST) trigger no preflight, so a CORS misconfiguration is only reachable for those methods; any protection that depends on the preflight is defeated for them.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight; then the simple-request precondition does not hold and the misconfiguration is not exploitable for that method.
+  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
 
 ## Recon signals (where to look)
 
@@ -68,6 +71,9 @@
 - Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
+- Server-side origin reflection is detected when the ACAO response value equals the request Origin for an arbitrary foreign Origin, rather than a fixed allowlisted host.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when ACAO is constant across all three probes (no Origin, near-miss origin, trusted origin), or the near-miss origin is rejected while only the exact trusted origin passes; the header is then a fixed allowlist.
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 - Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
@@ -110,12 +116,27 @@
 - A single hand-sent OPTIONS probe is not valid evidence of what a browser will do, because the browser caches the preflight decision for the number of seconds given by `Access-Control-Max-Age` (5 by default) and will answer the real request from that cache without re-probing the server.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false if the evidence set includes two independent observations: the raw OPTIONS exchange itself plus a browser-side trace (DevTools network panel or HAR) showing the subsequent cross-origin request either issuing a fresh preflight or reusing a cached one, which establishes what the user agent actually did rather than what the server would have answered.
   - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
+- An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can issue requests in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when the response never carries ACAO with the null origin, when no attacker-controlled document can be made to run in a null origin (no upload-and-render path, PDF or HTML preview, or sandboxed viewer), or when the endpoint varies its response on something other than Origin so the null response is a generic error page.
+  - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://portswigger.net/web-security/cors/>
 
 ## Defence bypasses
 
+- An Access-Control-Allow-Origin header that echoes the raw request Origin instead of a fixed allowlisted host is a misconfiguration: any attacker-controlled origin is accepted and its cross-origin reads are permitted.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when ACAO is a constant that differs from the request Origin, or when the server validates the origin against an allowlist and only the exact trusted origin passes; then the header is a fixed allowlist, not reflection.
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
+- The combination Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is not always blocked: server frameworks that special-case the wildcard + credentials pair can emit the requesting origin, making credentialed cross-origin reads possible. The browser rejection is conditional on the server actually sending a literal *.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when the server sends a literal * and does not reflect the origin, because the browser short-circuits the credentialed check against * and fails; the bypass only fires when the server instead reflects the requester's origin for that origin.
+  - Sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
 - When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.
   - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
+
+## Chaining opportunities
+
+- A CORS misconfiguration is an effective chain link for XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the reach of the XSS beyond its own origin.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 
 ## Rejected before you report
 
```

## 2026-10-28 21:26 — 45 diff lines
- items: 38 (supported 36), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 32 items, 30 supported, 7 FP rules, 1 chains
+> evidence: 38 items, 36 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -120,8 +120,23 @@
   - **Disproof:** The claim is wrong when the response never carries ACAO with the null origin, when no attacker-controlled document can be made to run in a null origin (no upload-and-render path, PDF or HTML preview, or sandboxed viewer), or when the endpoint varies its response on something other than Origin so the null response is a generic error page.
   - Sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://portswigger.net/web-security/cors/>
 
+## Variants
+
+- A server that accepts Origin: null (sandboxed iframe origins) in its CORS policy and echoes or allows it grants trust to an origin that sandboxed contexts can obtain without any user interaction.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim does not apply when the API never receives a null Origin in practice (only browser-navigated requests and sandboxed iframes set Origin), or when null is explicitly rejected and not echoed into Access-Control-Allow-Origin.
+  - Sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>
+- Configuring Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is invalid and browser-blocked; but a standalone wildcard on authenticated APIs is still a serious data-exposure risk.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim does not hold if ACAC is false and the affected endpoint is genuinely public with no authentication, so no session data is at risk; and if the endpoint is unauthenticated, the wildcard only affects browsers rendering the response, which is the least-privileged scenario.
+  - Sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>
+- Failing to send Vary: Origin on a dynamically generated CORS response lets a shared cache serve a response allowed for one origin to a different, untrusted origin.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim does not hold if the caching layer explicitly includes the Origin request header in its cache key, or if the Access-Control-Allow-Origin value is a static, hardcoded allowlist stored outside the dynamic response path.
+  - Sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>
+
 ## Defence bypasses
 
+- Allowlists that use substring, suffix, prefix, or unescaped-regex matching (for example 'example.com' matching 'evil-example.com') let an attacker craft an allowed origin and read responses.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim does not hold when the allowlist uses exact string equality against a fixed list, and the response sets Vary: Origin so that CDNs and proxies do not cache a response across different origins.
+  - Sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>
 - An Access-Control-Allow-Origin header that echoes the raw request Origin instead of a fixed allowlisted host is a misconfiguration: any attacker-controlled origin is accepted and its cross-origin reads are permitted.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong when ACAO is a constant that differs from the request Origin, or when the server validates the origin against an allowlist and only the exact trusted origin passes; then the header is a fixed allowlist, not reflection.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
@@ -134,6 +149,9 @@
 
 ## Chaining opportunities
 
+- A CORS misconfiguration chains with XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the XSS reach beyond its own origin.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 - A CORS misconfiguration is an effective chain link for XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the reach of the XSS beyond its own origin.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
```

## 2026-10-28 21:46 — 11 diff lines
- items: 39 (supported 37), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 38 items, 36 supported, 7 FP rules, 1 chains
+> evidence: 39 items, 37 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
```

## 2026-10-31 06:41 — 42 diff lines
- items: 39 (supported 33), FP rules 7, chains 1, state mature

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 39 items, 37 supported, 7 FP rules, 1 chains
+> evidence: 39 items, 33 supported, 7 FP rules, 1 chains
 > maturity: **mature**
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -53,7 +53,7 @@
 - CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS security implications and best practices If we don't configure CORS correct”) does not occur under a test that isolates that control.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 1 duplicate row(s))_
+- CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of”) does not occur under a test that isolates that control.
   - Sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
 - Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.  _(merged 1 duplicate row(s))_
@@ -71,7 +71,7 @@
 - Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
   - Sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
-- Server-side origin reflection is detected when the ACAO response value equals the request Origin for an arbitrary foreign Origin, rather than a fixed allowlisted host.  _(merged 1 duplicate row(s))_
+- Server-side origin reflection is detected when the ACAO response value equals the request Origin for an arbitrary foreign Origin, rather than a fixed allowlisted host.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is wrong when ACAO is constant across all three probes (no Origin, near-miss origin, trusted origin), or the near-miss origin is rejected while only the exact trusted origin passes; the header is then a fixed allowlist.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 - Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -149,10 +149,10 @@
 
 ## Chaining opportunities
 
-- A CORS misconfiguration chains with XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the XSS reach beyond its own origin.  _(merged 1 duplicate row(s))_
+- A CORS misconfiguration chains with XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the XSS reach beyond its own origin.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
-- A CORS misconfiguration is an effective chain link for XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the reach of the XSS beyond its own origin.  _(merged 1 duplicate row(s))_
+- A CORS misconfiguration is an effective chain link for XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the reach of the XSS beyond its own origin.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
   - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 
```
