# Methodology — CORS Misconfiguration

> Derived from 33 verified items. Regenerate with `python -m wks.methodgen --class cors --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The cross-origin policy grants a foreign origin more access than intended.

**References.** CWE-942 · A05:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.**

Per the Fetch standard a preflight only happens when the method is not CORS-safelisted or an unsafe header is present. Hunt by sending GET or POST carrying only a safelisted Content-Type and no custom header; if the server answers without an OPTIONS round trip the simple-request path is live. Confirm on a state-bearing endpoint that a fetch from a foreign origin with credentials actually reads the body.

- *Disproof:* If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/); [w3.org](https://www.w3.org/TR/cors/)

**CORS-safelisted methods (GET, HEAD, POST) trigger no preflight, so a CORS misconfiguration is only reachable for those methods; any protection that depends on the preflight is defeated for them.**

Mechanism: for a CORS-safelisted method with safelisted headers and a safelisted content type, the browser skips the OPTIONS preflight and sends the real request directly. How to apply it in the field: to exploit a misconfigured endpoint, first confirm the method and headers are safelisted so no preflight fires. Boundary of the rule: if the method or custom header is non-safelisted, preflight fires and a permissive preflight (or its absence) becomes the control.

- *Disproof:* The claim is wrong when the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight; then the simple-request precondition does not hold and the misconfiguration is not exploitable for that method.
- *Evidence:* high_confidence — [developer.chrome.com](https://developer.chrome.com/blog/private-network-access-preflight); [fetch.spec.whatwg.org](https://fetch.spec.whatwg.org/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.**

Send the endpoint three times with Origin: https://a.invalid, https://b.invalid and no Origin at all, then diff the ACAO returned each time. Reflection is the signal: a fixed allowlist answers only the trusted value or nothing, a reflection answers the decoy verbatim. Add a near-miss origin, the trusted value with one character appended, to separate prefix matching from true reflection.

- *Disproof:* If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
- *Evidence:* high_confidence — [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/); [w3.org](https://www.w3.org/TR/cors/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.**

Host a page on a domain you control that issues fetch(target, {credentials:'include'}) and exfiltrates the decoded body to your own collector. Run it against the test account's own session, never a real user's. A readable account-scoped body is the finding; a visible ACAO header with no readable body is a configuration observation only.

- *Disproof:* If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/is-cors-obsolete); [w3.org](https://www.w3.org/TR/cors/)

**An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain; it generally allows a domain to issue requests to other domains, but not to access the responses. A null-origin allowlist entry widens that gate for a specific, attacker-reachable document class. Cross-origin resource calls from internal documents and sandboxed requests can specify the null origin, so a sandboxed iframe on an attacker page, or any user-uploaded HTML rendered in a sandbox, produces exactly the Origin: null the server has been told to trust. Procedure: send the request with an explicit Origin: null header and confirm the reflected ACAO; then prove reachability by loading the same resource from a sandboxed iframe with credentials and reading the body cross-origin. The credentialed half still matters: the response must also signal that it can be shared when the request's credentials mode is include, otherwise the browser will not attach the cookie and the read returns nothing the attacker lacks.

- *Disproof:* The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [w3.org](https://www.w3.org/TR/cors/)

**corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.**

in-height: 1em;
}

.shiki-code-block--line-numbers .shiki-code-block__line {
 display: grid;
 grid-template-columns: minmax(2.5rem, max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 corsOptions . allowedHeaders = [ 'Content-Type' , 'Authorization' ] ; 
 corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting. This approach allows the client to cache the server’s CORS policy information for a specified time. When clients make subsequent requests, they can use cached CORS policy data without fetching it again from the server. Setting an appropriate maxAge value reduces response time and network overhead, optimizing performance while ensuring that CORS policies remain current. The example below sets maxA

- *Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight reque”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**This approach allows the client to cache the server’s CORS policy information for a specified time.**

{
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 corsOptions . allowedHeaders = [ 'Content-Type' , 'Authorization' ] ; 
 corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting. This approach allows the client to cache the server’s CORS policy information for a specified time. When clients make subsequent requests, they can use cached CORS policy data without fetching it again from the server. Setting an appropriate maxAge value reduces response time and network overhead, optimizing performance while ensuring that CORS policies remain current. The example below sets maxAge to 86400 seconds (24 hours): 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (bel

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This approach allows the client to cache the server’s CORS policy information fo”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.**

CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.

HackTricks reference: cors (https://kathan19.gitbook.io/howtohunt/cors/cors.md)

- *Disproof:* gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/is-cors-obsolete); [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/cors/cors.md); [w3.org](https://www.w3.org/TR/cors/)

**5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.**

ck__line {
 display: grid;
 grid-template-columns: minmax(2.5rem, max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 1 corsOptions . credentials = true; 
 2 
 3 app . use ( passport . initialize ()); 
 4 passport . use ( new JwtStrategy ( /* ... */ )); 
 5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials. Limit exposed headers and HTTP methods To specify only essential headers, use the exposedHeaders option. Also, use the methods option in your configuration to restrict which methods enable CORS: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once co

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' ,”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.**

unwanted actions on the application. Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. For instance, you may be tempted to use the allow all wildcard, denoted by an asterisk ( * ), for the Access-Control-Allow-Origin HTTP header value. This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability. So, instead, opt for specific, restrictive configurations. For dynamic settings of allowed origins, consider leveraging environment variables as a safer alternative. Securely implementing CORS in a Node.js application In this section, we’ll walk through a secure implementation of CORS in a Node.js application. We’ll consider a simple Node.js application using Express.js as its web framework. It w

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This CORS configuration permits any origin to interact with your application, op”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.**

ine-offset: -0.1875rem;
}

.shiki-code-block__line {
 display: block;
 min-height: 1em;
}

.shiki-code-block--line-numbers .shiki-code-block__line {
 display: grid;
 grid-template-columns: minmax(2.5rem, max-content) minmax(0, 1fr);
 column-gap: 1rem;
}

.shiki-code-block__line-number {
 color: #505050;
 text-align: right;
 user-select: none;
}

.shiki-code-block__line-content {
 min-width: 0;
}
 corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option. This approach allows the application to properly handle sensitive data while maintaining flexible communication between client and server components. The example below only allows Content-Type and Authorization headers and only exposes X-Custom-Header : 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable a

- *Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed head”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.**

plications hosted at one origin from reading an application’s resources at a different source.  This mechanism prevents malicious sites from reading another site's data but can also restrict legitimate uses. What if you want to include weather data in your application? Or embed a YouTube video on a web page? These public resources should be available for everyone to read, but the SOP blocks them. CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests. Applications can use the OPTIONS HTTP method to send preflight requests to the other origin’s resource. Through these preflight requests, web browsers determine if the other origin’s server permits such requests. Based on that information, the browser either disregards or enforces the SOP. Typical use cases for CORS include loading resources from content delivery networks (CDNs), requesting APIs

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS lets web applications bypass SOP limitations, enabling communication betwee”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.**

e on the /books route doesn’t explicitly specify which origins can make a GET request. So, the setting enables all origins to make requests to the path. This approach isn’t a good idea for security reasons, but you can configure more restrictive rules for your production environment. Configure CORS Using four different configurations, you can more securely implement CORS with the cors middleware. Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins. This setting enhances security by restricting access to trusted sources and preventing unauthorized cross-origin requests. The example below only allows requests from ` https://example.com `: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once conte

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Enable CORS for specific origins You can set the origin option in your CORS sett”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.**

rmitted HTTP Methods 
 5 corsOptions . methods =[ 'GET' ] ; Implement security headers outside of CORS You can implement additional security headers outside of CORS to further secure your application. HTTP security headers are HTTP headers that indicate the security aspects of an HTTP communication between a client and a server. Helmet.js provides a set of security headers with sensible defaults. However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines. Follow the steps below to set it up. First, run the following command in your Node.js application directory’s command line to install Helmet: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once content overflows, leaving long lines flush
 against th

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“However, it requires some content security policy (CSP) configuration to enable ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.**

Ikechukwu September 13, 2023 0 mins read In modern web applications, cross-origin resource sharing (CORS) enables secure communication between applications hosted on different origins. Developers use CORS to access other applications’ services within their own. This approach eliminates the need to rewrite features from scratch, accelerating development time and improving the developer experience. As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. Understanding these vulnerabilities and adopting best practices to implement CORS securely helps mitigate these risks but also supports you in maintaining your application’s functionality. In this article, we’ll first cover what CORS is and some of its use

- *Disproof:* Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“As helpful as CORS is, improper implementation can expose your Node.js applicati”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.**

corsOptions ), ( req , res ) => { /* ... */ }); Although CORS helps secure the API, it is still a third-party dependency. We need to ensure it and any other dependencies we pull into the project are secure, without known vulnerabilities. Snyk Open Source , for example, helps check packages for security concerns during development or in continuous integration/continuous delivery (CI/CD) pipelines. CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier. Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) . To avoid such scenarios, always follow best practices when implementing CORS configurations. You can also take further security steps, like implementing heade

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CORS security implications and best practices If we don't configure CORS correct”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

**Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.**

origins. Developers use CORS to access other applications’ services within their own. This approach eliminates the need to rewrite features from scratch, accelerating development time and improving the developer experience. As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. Understanding these vulnerabilities and adopting best practices to implement CORS securely helps mitigate these risks but also supports you in maintaining your application’s functionality. In this article, we’ll first cover what CORS is and some of its use cases. Then, we’ll use a code sample to implement CORS in a Node.js application. After exploring the potential security concerns, we’ll review

- *Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Misconfigurations may reveal sensitive data to unintended origins or allow malic”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [snyk.io](https://snyk.io/blog/security-implications-cors-node-js/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it.**

Mechanism: Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.

- *Disproof:* The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.
- *Evidence:* high_confidence — [developer.chrome.com](https://developer.chrome.com/blog/private-network-access-preflight); [fetch.spec.whatwg.org](https://fetch.spec.whatwg.org/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.**

Probe: send the request twice, once with no Cookie and no Authorization, once with a valid session cookie, and diff the two response bodies. If the bodies are identical (or the unauthenticated one is a 401), there is nothing for a credentialed read to steal. Read the response header block for Access-Control-Allow-Credentials specifically, not for the presence of CORS headers in general. ZAP states the precondition for authenticated cross-origin reads directly: authenticated AJAX queries require Access-Control-Allow-Credentials: true alongside an ACAO that is null or the malicious page's domain. So the rejection test is: wildcard ACAO, no ACAC, and no per-user variation in the body. Sonar's origin-reflection writeup names the mirror-image real bug for contrast: a server that reflects whatever Origin it receives nullifies CSRF protection and permits authenticated requests from any domain - that is echoing, not wildcard, and this rule must not swallow it. Hunting value: this filters the single largest CORS false-positive class, killing every ACAO wildcard hit on public docs, marketing pages, JS bundles, static assets and anonymous catalogue endpoints, none of which a credentialed request can escalate.

- *Disproof:* The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.
- *Evidence:* high_confidence — [sonarsource.com](https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/); [zaproxy.org](https://www.zaproxy.org/docs/alerts/40040-3/)

**An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body.**

Mechanism: An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.

- *Disproof:* The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.
- *Evidence:* high_confidence — [expressjs.com](https://expressjs.com/en/resources/middleware/cors.html); [fetch.spec.whatwg.org](https://fetch.spec.whatwg.org/)

**An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.**

Before reporting, fetch the same path unauthenticated from a clean session. If the body is byte-identical to the authenticated response, the data was already public and CORS changed nothing about who could read it. Record the unauthenticated diff as the disproof artefact so the triage decision is auditable rather than assumed.

- *Disproof:* A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/is-cors-obsolete); [w3.org](https://www.w3.org/TR/cors/)

**A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails.**

Mechanism: A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.

- *Disproof:* The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.
- *Evidence:* high_confidence — [expressjs.com](https://expressjs.com/en/resources/middleware/cors.html); [fetch.spec.whatwg.org](https://fetch.spec.whatwg.org/)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**An Access-Control-Allow-Origin header that echoes the raw request Origin instead of a fixed allowlisted host is a misconfiguration: any attacker-controlled origin is accepted and its cross-origin reads are permitted.**

Mechanism: server-side origin reflection means the CORS policy is derived from the request, so an attacker page on evil.example receives the same ACAO it sent. How to apply it in the field: a hunter must send a probe with a foreign Origin, then read the ACAO response and compare it byte-for-byte with the request Origin. Boundary of the rule: the finding is only real if the reflected origin matches the attacker's Origin and the response carries no ACAO check failure for that origin.

- *Disproof:* The claim is wrong when ACAO is a constant that differs from the request Origin, or when the server validates the origin against an allowlist and only the exact trusted origin passes; then the header is a fixed allowlist, not reflection.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cors/); [w3.org](https://www.w3.org/TR/cors/)

**When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO.**

Mechanism: When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.

- *Disproof:* The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.
- *Evidence:* high_confidence — [developer.chrome.com](https://developer.chrome.com/blog/private-network-access-preflight); [fetch.spec.whatwg.org](https://fetch.spec.whatwg.org/)

**The combination Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true is not always blocked: server frameworks that special-case the wildcard + credentials pair can emit the requesting origin, making credentialed cross-origin reads possible. The browser rejection is conditional on the server actually sending a literal *.**

Mechanism: a naive server that special-cases the * + credentials combination emits the attacker's own origin, so the browser then performs a byte-level comparison of ACAO against the request Origin and succeeds. How to apply it in the field: intercept a credentialed cross-origin request and confirm the ACAO value equals the attacker's Origin and the body is returned. Boundary of the rule: refuted if the ACAO stays a literal * and no reflection occurs.

- *Disproof:* The claim is wrong when the server sends a literal * and does not reflect the origin, because the browser short-circuits the credentialed check against * and fails; the bypass only fires when the server instead reflects the requester's origin for that origin.
- *Evidence:* high_confidence — [expressjs.com](https://expressjs.com/en/resources/middleware/cors.html); [fetch.spec.whatwg.org](https://fetch.spec.whatwg.org/)

**Allowlists that use substring, suffix, prefix, or unescaped-regex matching (for example 'example.com' matching 'evil-example.com') let an attacker craft an allowed origin and read responses.**

A CORS allowlist compiled as an unescaped regular expression (for example https://good.example matches https://goodXexample) or checked with substring/suffix logic such as endswith('.example.com') is trivially bypassed by an attacker-controlled domain that shares a suffix with a trusted root. Subdomain wildcards are additionally dangerous because a parent-domain trust lets a third-party registrant of attacker-example.com read the API. This is a classic CWE-942 pattern and is routinely found where origin matching is implemented with loose string ad-hoc logic instead of strict equality against a fixed list.

- *Disproof:* The claim does not hold when the allowlist uses exact string equality against a fixed list, and the response sets Vary: Origin so that CDNs and proxies do not cache a response across different origins.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/942.html); [top10.owasp.org](https://top10.owasp.org/2021/A05_2021-Security_Misconfiguration/)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
