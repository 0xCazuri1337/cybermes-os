# CORS Misconfiguration

> surface: `web` · CWE: 942 · OWASP: A05:2021
> maturity: **mature** — 39 items, 33 supported, 7 FP rules, 1 chains

The cross-origin policy grants a foreign origin more access than intended.

**Aliases:** cors, cross origin resource sharing, cors misconfiguration

## Prerequisite

- **A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.**  
  `high_confidence` · score 0.9265 · disproved by: If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
  sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS-safelisted methods (GET, HEAD, POST) trigger no preflight, so a CORS misconfiguration is only reachable for those methods; any protection that depends on the preflight is defeated for them.**  
  `high_confidence` · score 0.8545 · disproved by: The claim is wrong when the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight; then the simple-request precondition does not hold and the misconfiguration is not exploitable for that method.
  sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>

## Signal

- **An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.**  
  `high_confidence` · score 0.8715 · disproved by: If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
  sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Technique

- **Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.**  
  `high_confidence` · score 0.899 · disproved by: If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
  sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
- **Server-side origin reflection is detected when the ACAO response value equals the request Origin for an arbitrary foreign Origin, rather than a fixed allowlisted host.**  
  `under_review` · score 0.894 · disproved by: The claim is wrong when ACAO is constant across all three probes (no Origin, near-miss origin, trusted origin), or the near-miss origin is rejected while only the exact trusted origin passes; the header is then a fixed allowlist.
  sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- **An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**  
  `high_confidence` · score 0.8665 · disproved by: The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
  sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- **corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.**  
  `high_confidence` · score 0.8545 · disproved by: Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight reque”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **This approach allows the client to cache the server’s CORS policy information for a specified time.**  
  `high_confidence` · score 0.8545 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This approach allows the client to cache the server’s CORS policy information fo”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.**  
  `high_confidence` · score 0.8515 · disproved by: gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
  sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/> · <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
- **Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.**  
  `under_review` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.**  
  `high_confidence` · score 0.827 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' ,”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).**  
  `under_review` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of”) does not occur under a test that isolates that control.
  sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://portswigger.net/web-security/cors/>
- **This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This CORS configuration permits any origin to interact with your application, op”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed head”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS lets web applications bypass SOP limitations, enabling communication betwee”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Enable CORS for specific origins You can set the origin option in your CORS sett”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, it requires some content security policy (CSP) configuration to enable ”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“As helpful as CORS is, improper implementation can expose your Node.js applicati”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS security implications and best practices If we don't configure CORS correct”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Misconfigurations may reveal sensitive data to unintended origins or allow malic”) does not occur under a test that isolates that control.
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Validation

- **Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it.**  
  `high_confidence` · score 0.918 · disproved by: The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.
  sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>

## Fp Rule

- **Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.**  
  `high_confidence` · score 0.918 · disproved by: The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.
  sources: <https://www.zaproxy.org/docs/alerts/40040-3/> · <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
- **An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body.**  
  `high_confidence` · score 0.918 · disproved by: The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.
  sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
- **An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.**  
  `high_confidence` · score 0.899 · disproved by: A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
  sources: <https://bishopfox.com/blog/is-cors-obsolete> · <https://www.w3.org/TR/cors/>
- **A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails.**  
  `high_confidence` · score 0.8905 · disproved by: The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.
  sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>

## Evidence

- **A single hand-sent OPTIONS probe is not valid evidence of what a browser will do, because the browser caches the preflight decision for the number of seconds given by `Access-Control-Max-Age` (5 by default) and will answer the real request from that cache without re-probing the server.**  
  `high_confidence` · score 0.8905 · disproved by: The claim is false if the evidence set includes two independent observations: the raw OPTIONS exchange itself plus a browser-side trace (DevTools network panel or HAR) showing the subsequent cross-origin request either issuing a fresh preflight or reusing a cached one, which establishes what the user agent actually did rather than what the server would have answered.
  sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
- **An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can issue requests in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**  
  `high_confidence` · score 0.8665 · disproved by: The claim is wrong when the response never carries ACAO with the null origin, when no attacker-controlled document can be made to run in a null origin (no upload-and-render path, PDF or HTML preview, or sandboxed viewer), or when the endpoint varies its response on something other than Origin so the null response is a generic error page.
  sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://portswigger.net/web-security/cors/>

## Variant

- **Failing to send Vary: Origin on a dynamically generated CORS response lets a shared cache serve a response allowed for one origin to a different, untrusted origin.**  
  `high_confidence` · score 0.8295 · disproved by: The claim does not hold if the caching layer explicitly includes the Origin request header in its cache key, or if the Access-Control-Allow-Origin value is a static, hardcoded allowlist stored outside the dynamic response path.
  sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>
- **Configuring Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true is invalid and browser-blocked; but a standalone wildcard on authenticated APIs is still a serious data-exposure risk.**  
  `high_confidence` · score 0.8295 · disproved by: The claim does not hold if ACAC is false and the affected endpoint is genuinely public with no authentication, so no session data is at risk; and if the endpoint is unauthenticated, the wildcard only affects browsers rendering the response, which is the least-privileged scenario.
  sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>
- **A server that accepts Origin: null (sandboxed iframe origins) in its CORS policy and echoes or allows it grants trust to an origin that sandboxed contexts can obtain without any user interaction.**  
  `high_confidence` · score 0.8105 · disproved by: The claim does not apply when the API never receives a null Origin in practice (only browser-navigated requests and sandboxed iframes set Origin), or when null is explicitly rejected and not echoed into Access-Control-Allow-Origin.
  sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>

## Bypass

- **An Access-Control-Allow-Origin header that echoes the raw request Origin instead of a fixed allowlisted host is a misconfiguration: any attacker-controlled origin is accepted and its cross-origin reads are permitted.**  
  `high_confidence` · score 0.894 · disproved by: The claim is wrong when ACAO is a constant that differs from the request Origin, or when the server validates the origin against an allowlist and only the exact trusted origin passes; then the header is a fixed allowlist, not reflection.
  sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- **When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO.**  
  `high_confidence` · score 0.8905 · disproved by: The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.
  sources: <https://developer.chrome.com/blog/private-network-access-preflight> · <https://fetch.spec.whatwg.org/>
- **The combination Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is not always blocked: server frameworks that special-case the wildcard + credentials pair can emit the requesting origin, making credentialed cross-origin reads possible. The browser rejection is conditional on the server actually sending a literal *.**  
  `high_confidence` · score 0.8355 · disproved by: The claim is wrong when the server sends a literal * and does not reflect the origin, because the browser short-circuits the credentialed check against * and fails; the bypass only fires when the server instead reflects the requester's origin for that origin.
  sources: <https://expressjs.com/en/resources/middleware/cors.html> · <https://fetch.spec.whatwg.org/>
- **Allowlists that use substring, suffix, prefix, or unescaped-regex matching (for example 'example.com' matching 'evil-example.com') let an attacker craft an allowed origin and read responses.**  
  `high_confidence` · score 0.8105 · disproved by: The claim does not hold when the allowlist uses exact string equality against a fixed list, and the response sets Vary: Origin so that CDNs and proxies do not cache a response across different origins.
  sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>

## Chain Link

- **A CORS misconfiguration chains with XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the XSS reach beyond its own origin.**  
  `under_review` · score 0.803 · disproved by: The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
  sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- **A CORS misconfiguration is an effective chain link for XSS: if an origin is allowed to read a target's responses, a stored or reflected XSS in that origin can exfiltrate data from any origin the target trusts, widening the reach of the XSS beyond its own origin.**  
  `under_review` · score 0.803 · disproved by: The claim is wrong when the targeted endpoint returns identical bodies for anonymous and credentialed callers, or the response is blocked by a cross-origin resource policy (CORP) the attacker page cannot satisfy, so no differing data reaches the attacker script.
  sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>

## Misconfiguration

- **Echoing the incoming Origin header verbatim into Access-Control-Allow-Origin, combined with Access-Control-Allow-Credentials: true, completely nullifies the Same-Origin Policy for any third-party origin.**  
  `high_confidence` · score 0.9015 · disproved by: The claim does not hold when the server validates the Origin against an exact, fixed allowlist before echoing it, or when the ACAC flag is absent on unauthenticated endpoints only. A verified exact-match allowlist means only the configured origins are echoed, so no arbitrary third-party is trusted.
  sources: <https://cwe.mitre.org/data/definitions/942.html> · <https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/>

## Vulnerability

- **A CORS misconfiguration (e.g., reflecting an arbitrary Origin or trusting a permissive cross-domain whitelist) disables the same-origin policy, letting a malicious site read authenticated responses from the victim's browser.**  
  `high_confidence` · score 0.8815 · disproved by: If Access-Control-Allow-Origin is absent or set to a fixed, allowlisted origin; if Access-Control-Allow-Credentials is absent or set to false; or if the server rejects the attacker-controlled Origin with a non-200 refusal, the misconfiguration is neutralized and cross-origin reads are blocked.
  sources: <https://blog.yunolay.com/cors-misconfiguration-and-exploitation/> · <https://cwe.mitre.org/data/definitions/942.html> · <https://portswigger.net/kb/issues/00200600_cross-origin-resource-sharing>

## False-positive rules

- **Hypothesis:** A CORS endpoint reflects an arbitrary attacker Origin with Access-Control-Allow-Credentials:true, therefore an attacker's page can steal the victim's data
  - **Invalidated by:** The cited paths returned a byte-identical application shell rather than JSON and appear nowhere in the bundle; the application keys every data call on an Authorization or caller-supplied token, so the browser never attaches a credential cross-origin; zero Set-Cookie on any path, so there is nothing for the attacker's page to read; and the client never uses credentials:'include'
  - **Rule:** Reflection plus ACAC:true is only credential theft when a secret is keyed on something the browser attaches automatically. Prove a cookie-keyed or ambient-credential read exists on the SAME path: a Set-Cookie, a cookie-backed data call, or credentials:'include' actually used in the client. If the data is Authorization-keyed, there is no cross-origin read to perform

- **Hypothesis:** CORS reflection on one host and session cookies on another host means the account family is vulnerable to cross-origin credential theft
  - **Invalidated by:** No host in the family had all three. Reflect-only hosts issued no cookie and their canonical data paths 404'd; cookie-only hosts emitted no CORS headers at all; one host pinned ACAO to a fixed developer origin with no reflection
  - **Rule:** The exploitable condition is CONJUNCTIVE and lives on a single path: arbitrary-Origin reflection AND ACAC:true AND a cookie on that same path. Reflection on host A with cookies on host B is two harmless facts, not a finding - probe for the combination before reporting it

- **Hypothesis:** A hardcoded Access-Control-Allow-Origin value in the response plus Access-Control-Allow-Credentials:true is an exploitable CORS misconfiguration
  - **Invalidated by:** The ACAO value was byte-identical regardless of the Origin sent - the server pinned it rather than reflecting. A pinned ACAO cannot be matched by an attacker origin, so the browser blocks the credentialed read
  - **Rule:** CORS reflection requires the ACAO value to CHANGE with the Origin header. Send an attacker Origin and a second arbitrary Origin and compare: identical values are a pinned allowlist, and pinned-plus-ACAC is not exploitable. Word the finding as 'reflects' only after you have observed it vary
