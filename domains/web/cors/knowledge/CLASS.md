# CORS Misconfiguration

## Definition

The cross-origin policy grants a foreign origin more access than intended.

- **CWE:** 942
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["cors", "cross origin resource sharing", "cors misconfiguration"]

Canonical home for `cors`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.**

Per the Fetch standard a preflight only happens when the method is not CORS-safelisted or an unsafe header is present. Hunt by sending GET or POST carrying only a safelisted Content-Type and no custom header; if the server answers without an OPTIONS round trip the simple-request path is live. Confirm on a state-bearing endpoint that a fetch from a foreign origin with credentials actually reads the body.

*Disproof:* If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.**

Send the endpoint three times with Origin: https://a.invalid, https://b.invalid and no Origin at all, then diff the ACAO returned each time. Reflection is the signal: a fixed allowlist answers only the trusted value or nothing, a reflection answers the decoy verbatim. Add a near-miss origin, the trusted value with one character appended, to separate prefix matching from true reflection.

*Disproof:* If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.

**A single hand-sent OPTIONS probe is not valid evidence of what a browser will do, because the browser caches the preflight decision for the number of seconds given by `Access-Control-Max-Age` (5 by default) and will answer the real request from that cache without re-probing the server.**

Mechanism: A single hand-sent OPTIONS probe is not valid evidence of what a browser will do, because the browser caches the preflight decision for the number of seconds given by `Access-Control-Max-Age` (5 by default) and will answer the real request from that cache without re-probing the server. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false if the evidence set includes two independent observations: the raw OPTIONS exchange itself plus a browser-side trace (DevTools network panel or HAR) showing the subsequent cross-origin request either issuing a fresh preflight or reusing a cached one, which establishes what the user agent actually did rather than what the server would have answered.

*Disproof:* The claim is false if the evidence set includes two independent observations: the raw OPTIONS exchange itself plus a browser-side trace (DevTools network panel or HAR) showing the subsequent cross-origin request either issuing a fresh preflight or reusing a cached one, which establishes what the user agent actually did rather than what the server would have answered.

## Exploitation

**CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).**

Lately, we have received a lot of questions from our clients about CORS becoming obsolete. They are rightfully concerned about this possibility because so much of Web 2.0 depends on the interoperability mechanisms that CORS provides. 
 In this write-up, we shed some light on whether this is a valid fear, and the actual reality of the situation. 
 What Is CORS? 
 CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). In general, this means that websites that support CORS will allow resources to be shared with other sites, with the CORS policy acting as the gatekeeper. 
 The high-level model for how CORS requests are handled is illustrated in the graph below: 
   
 
   
 Figure 1 - The browser’s decision graph for a allowing a CORS request 
   
 Is CORS Obsolete? 
 There are two answers to this question. 
 Fir

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".

**Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.**

OP. Typical use cases for CORS include loading resources from content delivery networks (CDNs), requesting APIs across multiple domains, and facilitating third-party integration. However, improperly implementing CORS in your application poses security risks. You may open your app to a cross-site request forgery (CSRF) attack, which tricks users into performing unwanted actions on the application. Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. For instance, you may be tempted to use the allow all wildcard, denoted by an asterisk ( * ), for the Access-Control-Allow-Origin HTTP header value. This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability. So, instead, opt for specific, restrictive configurations. For dynamic settings of allowed origins, consider leveraging environ

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".

**This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.**

unwanted actions on the application. Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit. For instance, you may be tempted to use the allow all wildcard, denoted by an asterisk ( * ), for the Access-Control-Allow-Origin HTTP header value. This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability. So, instead, opt for specific, restrictive configurations. For dynamic settings of allowed origins, consider leveraging environment variables as a safer alternative. Securely implementing CORS in a Node.js application In this section, we’ll walk through a secure implementation of CORS in a Node.js application. We’ll consider a simple Node.js application using Express.js as its web framework. It w

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This CORS configuration permits any origin to interact with your application, opening the ".

**As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.**

Ikechukwu September 13, 2023 0 mins read In modern web applications, cross-origin resource sharing (CORS) enables secure communication between applications hosted on different origins. Developers use CORS to access other applications’ services within their own. This approach eliminates the need to rewrite features from scratch, accelerating development time and improving the developer experience. As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. Understanding these vulnerabilities and adopting best practices to implement CORS securely helps mitigate these risks but also supports you in maintaining your application’s functionality. In this article, we’ll first cover what CORS is and some of its use

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Anothe".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".

**Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .**

other dependencies we pull into the project are secure, without known vulnerabilities. Snyk Open Source , for example, helps check packages for security concerns during development or in continuous integration/continuous delivery (CI/CD) pipelines. CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier. Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) . To avoid such scenarios, always follow best practices when implementing CORS configurations. You can also take further security steps, like implementing headers outside of CORS, which we'll cover later in this section. Best practices Best practices like restricting allowed origins, using secure cookies and tokens, and limiting exposed headers are essential to keep your applications and users secu

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".

**CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.**

plications hosted at one origin from reading an application’s resources at a different source.  This mechanism prevents malicious sites from reading another site's data but can also restrict legitimate uses. What if you want to include weather data in your application? Or embed a YouTube video on a web page? These public resources should be available for everyone to read, but the SOP blocks them. CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests. Applications can use the OPTIONS HTTP method to send preflight requests to the other origin’s resource. Through these preflight requests, web browsers determine if the other origin’s server permits such requests. Based on that information, the browser either disregards or enforces the SOP. Typical use cases for CORS include loading resources from content delivery networks (CDNs), requesting APIs

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".

**CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.**

corsOptions ), ( req , res ) => { /* ... */ }); Although CORS helps secure the API, it is still a third-party dependency. We need to ensure it and any other dependencies we pull into the project are secure, without known vulnerabilities. Snyk Open Source , for example, helps check packages for security concerns during development or in continuous integration/continuous delivery (CI/CD) pipelines. CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier. Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) . To avoid such scenarios, always follow best practices when implementing CORS configurations. You can also take further security steps, like implementing heade

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".

**Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.**

origins. Developers use CORS to access other applications’ services within their own. This approach eliminates the need to rewrite features from scratch, accelerating development time and improving the developer experience. As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites. Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections. Understanding these vulnerabilities and adopting best practices to implement CORS securely helps mitigate these risks but also supports you in maintaining your application’s functionality. In this article, we’ll first cover what CORS is and some of its use cases. Then, we’ll use a code sample to implement CORS in a Node.js application. After exploring the potential security concerns, we’ll review

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".

**Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.**

e on the /books route doesn’t explicitly specify which origins can make a GET request. So, the setting enables all origins to make requests to the path. This approach isn’t a good idea for security reasons, but you can configure more restrictive rules for your production environment. Configure CORS Using four different configurations, you can more securely implement CORS with the cors middleware. Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins. This setting enhances security by restricting access to trusted sources and preventing unauthorized cross-origin requests. The example below only allows requests from ` https://example.com `: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once conte

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".

**CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).**

Lately, we have received a lot of questions from our clients about CORS becoming obsolete. They are rightfully concerned about this possibility because so much of Web 2.0 depends on the interoperability mechanisms that CORS provides. 
 In this write-up, we shed some light on whether this is a valid fear, and the actual reality of the situation. 
 What Is CORS? 
 CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP). In general, this means that websites that support CORS will allow resources to be shared with other sites, with the CORS policy acting as the gatekeeper. 
 The high-level model for how CORS requests are handled is illustrated in the graph below: 
   
 
   
 Figure 1 - The browser’s decision graph for a allowing a CORS request 
   
 Is CORS Obsolete? 
 There are two answers to this question. 
 Fir

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".

**However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.**

rmitted HTTP Methods 
 5 corsOptions . methods =[ 'GET' ] ; Implement security headers outside of CORS You can implement additional security headers outside of CORS to further secure your application. HTTP security headers are HTTP headers that indicate the security aspects of an HTTP communication between a client and a server. Helmet.js provides a set of security headers with sensible defaults. However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines. Follow the steps below to set it up. First, run the following command in your Node.js application directory’s command line to install Helmet: 
.shiki-code-block pre.shiki {
 margin: 0;
 /* Padding lives on (below), not here, so the trailing inline
 padding stays part of the scrollable area. A scroll container drops its
 end-side padding once content overflows, leaving long lines flush
 against th

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".

**An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**

The same-origin policy is a restrictive cross-origin specification that limits the ability for a website to interact with resources outside of the source domain; it generally allows a domain to issue requests to other domains, but not to access the responses. A null-origin allowlist entry widens that gate for a specific, attacker-reachable document class. Cross-origin resource calls from internal documents and sandboxed requests can specify the null origin, so a sandboxed iframe on an attacker page, or any user-uploaded HTML rendered in a sandbox, produces exactly the Origin: null the server has been told to trust. Procedure: send the request with an explicit Origin: null header and confirm the reflected ACAO; then prove reachability by loading the same resource from a sandboxed iframe with credentials and reading the body cross-origin. The credentialed half still matters: the response must also signal that it can be shared when the request's credentials mode is include, otherwise the browser will not attach the cookie and the read returns nothing the attacker lacks.

*Disproof:* The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.

**Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.**

Host a page on a domain you control that issues fetch(target, {credentials:'include'}) and exfiltrates the decoded body to your own collector. Run it against the test account's own session, never a real user's. A readable account-scoped body is the finding; a visible ACAO header with no readable body is a configuration observation only.

*Disproof:* If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.

**CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.**

CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.

HackTricks reference: cors (https://kathan19.gitbook.io/howtohunt/cors/cors.md)

*Disproof:* gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.

**CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.**

CORS candidates are harvested from collected endpoint data by running meg and filtering the results through gf cors, so CORS testing is driven from scan or proxy output rather than manual browsing.

HackTricks reference: cors (https://kathan19.gitbook.io/howtohunt/cors/cors.md)

*Disproof:* gf cors returns no candidates from the collected data and manual review finds no endpoint reflecting an arbitrary Origin in access-control-allow-origin.

## Variations

**When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO.**

Mechanism: When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.

*Disproof:* The claim is false when the attacker request is CORS-safelisted in method, headers and content type, in which case no preflight is sent at all and the only control is the CORS check on the single response; conversely a server that rejects the preflight with a 4xx still blocks the real request, so permissiveness in the preflight alone is only a bypass if the real request also fires.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.cors.auto.01` — cors: observe, exercise, confirm (goal: `Establish, exercise and confirm a cors condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.**

Probe: send the request twice, once with no Cookie and no Authorization, once with a valid session cookie, and diff the two response bodies. If the bodies are identical (or the unauthenticated one is a 401), there is nothing for a credentialed read to steal. Read the response header block for Access-Control-Allow-Credentials specifically, not for the presence of CORS headers in general. ZAP states the precondition for authenticated cross-origin reads directly: authenticated AJAX queries require Access-Control-Allow-Credentials: true alongside an ACAO that is null or the malicious page's domain. So the rejection test is: wildcard ACAO, no ACAC, and no per-user variation in the body. Sonar's origin-reflection writeup names the mirror-image real bug for contrast: a server that reflects whatever Origin it receives nullifies CSRF protection and permits authenticated requests from any domain - that is echoing, not wildcard, and this rule must not swallow it. Hunting value: this filters the single largest CORS false-positive class, killing every ACAO wildcard hit on public docs, marketing pages, JS bundles, static assets and anonymous catalogue endpoints, none of which a credentialed request can escalate.

*Disproof:* The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.

**An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.**

Before reporting, fetch the same path unauthenticated from a clean session. If the body is byte-identical to the authenticated response, the data was already public and CORS changed nothing about who could read it. Record the unauthenticated diff as the disproof artefact so the triage decision is auditable rather than assumed.

*Disproof:* A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.

**An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body.**

Mechanism: An endpoint that answers a foreign-origin request with no `Access-Control-Allow-Origin` header at all is not a CORS finding: the CORS check returns failure immediately when the header is absent, so the attacker script never receives a readable body. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.

*Disproof:* The rule is wrong when the absent header is a symptom of the CORS layer failing only for that one case — for example a framework emits ACAO on the same route for `Origin: https://evil.example` but 500s or falls through to a handler branch that omits it for `Origin: null`, or the header is added by a CDN/proxy layer that only rewrites responses above a size threshold or cache status; the route is then genuinely misconfigured for the affected origins and the omission is the bug, not the policy.

**A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails.**

Mechanism: A response carrying the literal `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true` cannot leak credentialed data cross-origin, because the CORS check only short-circuits to success on the wildcard when the request's credentials mode is not "include"; a credentialed request falls through to the exact byte-serialization comparison against `*` and fails. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.

*Disproof:* The rule is wrong and the finding is real when the server does NOT send a literal `*` but instead reflects or allowlists the requesting origin in ACAO (frameworks commonly special-case the `*` + credentials combination and emit the attacker's origin instead), or when the endpoint varies on an unauthenticated-but-per-user identifier such as a session-free profile id; then the credentialed CORS check succeeds and the body crosses origins.
**Hypothesis:** CORS reflection on one host and session cookies on another host means the account family is vulnerable to cross-origin credential theft
- Invalidated by: No host in the family had all three. Reflect-only hosts issued no cookie and their canonical data paths 404'd; cookie-only hosts emitted no CORS headers at all; one host pinned ACAO to a fixed developer origin with no reflection
- **Rejection rule:** The exploitable condition is CONJUNCTIVE and lives on a single path: arbitrary-Origin reflection AND ACAC:true AND a cookie on that same path. Reflection on host A with cookies on host B is two harmless facts, not a finding - probe for the combination before reporting it

**Hypothesis:** A hardcoded Access-Control-Allow-Origin value in the response plus Access-Control-Allow-Credentials:true is an exploitable CORS misconfiguration
- Invalidated by: The ACAO value was byte-identical regardless of the Origin sent - the server pinned it rather than reflecting. A pinned ACAO cannot be matched by an attacker origin, so the browser blocks the credentialed read
- **Rejection rule:** CORS reflection requires the ACAO value to CHANGE with the Origin header. Send an attacker Origin and a second arbitrary Origin and compare: identical values are a pinned allowlist, and pinned-plus-ACAC is not exploitable. Word the finding as 'reflects' only after you have observed it vary

**Hypothesis:** A CORS endpoint reflects an arbitrary attacker Origin with Access-Control-Allow-Credentials:true, therefore an attacker's page can steal the victim's data
- Invalidated by: The cited paths returned a byte-identical application shell rather than JSON and appear nowhere in the bundle; the application keys every data call on an Authorization or caller-supplied token, so the browser never attaches a credential cross-origin; zero Set-Cookie on any path, so there is nothing for the attacker's page to read; and the client never uses credentials:'include'
- **Rejection rule:** Reflection plus ACAC:true is only credential theft when a secret is keyed on something the browser attaches automatically. Prove a cookie-keyed or ambient-credential read exists on the SAME path: a Set-Cookie, a cookie-backed data call, or credentials:'include' actually used in the client. If the data is Authorization-keyed, there is no cross-origin read to perform

## Validation

**Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it.**

Mechanism: Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposing it. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.

*Disproof:* The claim is false when the endpoint's body is byte-identical for anonymous and credentialed callers, or when the response is blocked by a cross-origin resource policy / CORP check the attacker page cannot satisfy, in either case the header is present but no differing data reached the attacker script.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from cors.fp_rule.wildcard_allow_origin_plus_allow_credentials_is_blocked_by_the_browser, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.wildcard_allow_origin_plus_allow_credentials_is_blocked_by_the_browser) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from cors.fp_rule.missing_allow_origin_header_is_a_block_not_a_misconfiguration, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.fp_rule.missing_allow_origin_header_is_a_block_not_a_misconfiguration) states the full boundary.

**To decide this case, observe: Mechanism: Origin reflection becomes a proven CORS data leak only when a controlled foreign origin receives a readable body on a request made with credentials mode "include"; the ACAO header value alone never demonstrates that data crossed origins, because the browser re-runs the CORS check on the response before exposi**

Derived from cors.validation.origin_reflection_is_only_provable_by_an_actual_credentialed_read, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.validation.origin_reflection_is_only_provable_by_an_actual_credentialed_read) states the full boundary.

**To decide this case, observe: Mechanism: When a cross-origin request carries a non-safelisted method or header, the protective control is the CORS preflight, not the absence of ACAO on the final response: the browser asks permission first, so a server that answers the preflight permissively (or fails to distinguish OPTIONS from other methods) is the bypass point even if the eventual response omits ACAO.**

Derived from cors.bypass.the_preflight_is_the_control_that_actually_blocks_side_effecting_cross_origin_requests, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (cors.bypass.the_preflight_is_the_control_that_actually_blocks_side_effecting_cross_origin_requests) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (research)
  - <https://bishopfox.com/blog/is-cors-obsolete>
- **developer.chrome.com** (writeup)
  - <https://developer.chrome.com/blog/private-network-access-preflight>
- **expressjs.com** (writeup)
  - <https://expressjs.com/en/resources/middleware/cors.html>
- **fetch.spec.whatwg.org** (writeup)
  - <https://fetch.spec.whatwg.org/>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/cors/cors.md>
- **portswigger.net** (docs)
  - <https://portswigger.net/web-security/cors/>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/security-implications-cors-node-js/>
- **sonarsource.com** (writeup)
  - <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
- **w3.org** (docs)
  - <https://www.w3.org/TR/cors/>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/40040-3/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
