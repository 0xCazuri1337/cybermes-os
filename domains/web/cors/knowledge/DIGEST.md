# CORS Misconfiguration

> surface: `web` · CWE: 942 · OWASP: A05:2021
> maturity: **mature** — 21 items, 21 supported, 2 FP rules, 1 chains

The cross-origin policy grants a foreign origin more access than intended.

**Aliases:** cors, cross origin resource sharing, cors misconfiguration

## Prerequisite

- **A CORS misconfiguration is only exploitable when the attacker's cross-origin request is CORS-safelisted in method, so no preflight fires and no custom header can be required.**  
  `high_confidence` · score 0.9265 · disproved by: If the endpoint answers a bare foreign-origin GET with 4xx, or the body is only obtainable after an OPTIONS preflight, the simple-request precondition does not hold.
  sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Signal

- **An Access-Control-Allow-Origin value equal to the exact attacker Origin supplied, rather than a fixed allowlisted host, indicates server-side origin reflection.**  
  `high_confidence` · score 0.8715 · disproved by: If ACAO is constant across all three probes, or the near-miss origin is rejected while only the exact trusted origin passes, the header is a fixed allowlist and not reflection.
  sources: <https://www.w3.org/TR/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Technique

- **Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.**  
  `high_confidence` · score 0.899 · disproved by: If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
  sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
- **An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.**  
  `high_confidence` · score 0.8665 · disproved by: The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
  sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
- **corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and caching Finally, you can enable preflight requests ( OPTIONS ) caching by setting the cache duration via the maxAge setting.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . exposedHeaders = [ 'X-Custom-Header' ] ; Configure preflight requests and ca".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **This approach allows the client to cache the server’s CORS policy information for a specified time.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This approach allows the client to cache the server’s CORS policy information for a specif".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Plus, overly permissive configurations can allow unauthorized access to user data and sensitive information between origins, potentially causing data breaches or exposing vulnerabilities for bad actors to exploit.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Plus, overly permissive configurations can allow unauthorized access to user data and sens".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session: false }), ( req , res ) => { /* ... */ }); In this code, setting the value of credentials to true allows cross-origin requests to include credentials.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "5 app . get ( '/books' , cors ( corsOptions ), passport . authenticate ( 'jwt' , { session".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
  sources: <https://portswigger.net/web-security/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
- **This CORS configuration permits any origin to interact with your application, opening the door to potential vulnerability.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This CORS configuration permits any origin to interact with your application, opening the ".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Another option is configuring the Access-Control-Allow-Headers CORS header using the allowedHeaders option and Access-Control-Expose-Headers with the exposedHeaders option.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "corsOptions . methods = [ 'GET' , 'POST' ] ; Set custom headers and exposed headers Anothe".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Specifically, we could expose sensitive data to unintended origins, allow unauthorized actions by malicious websites (CSRF attacks), and even enable attackers to bypass SOP protections through techniques such as cross-site scripting (XSS) .**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Specifically, we could expose sensitive data to unintended origins, allow unauthorized act".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS lets web applications bypass SOP limitations, enabling communication between various web services and allowing cross-origin requests.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS lets web applications bypass SOP limitations, enabling communication between various ".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Enable CORS for specific origins You can set the origin option in your CORS settings to configure allowed origins.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Enable CORS for specific origins You can set the origin option in your CORS settings to co".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricted resources between websites in a manner that would normally be disallowed by the Same-Origin Policy (SOP).**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS, or Cross Origin Resource Sharing is a mechanism that allows the sharing of restricte".
  sources: <https://portswigger.net/web-security/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
- **However, it requires some content security policy (CSP) configuration to enable the functionality that the CORS configuration defines.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "However, it requires some content security policy (CSP) configuration to enable the functi".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **As helpful as CORS is, improper implementation can expose your Node.js applications to security risks, such as data breaches and unauthorized access from third-party websites.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As helpful as CORS is, improper implementation can expose your Node.js applications to sec".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **CORS security implications and best practices If we don't configure CORS correctly, we risk triggering the security vulnerabilities mentioned earlier.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CORS security implications and best practices If we don't configure CORS correctly, we ris".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>
- **Misconfigurations may reveal sensitive data to unintended origins or allow malicious websites to bypass same-origin policy (SOP) protections.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Misconfigurations may reveal sensitive data to unintended origins or allow malicious websi".
  sources: <https://portswigger.net/web-security/cors/> · <https://snyk.io/blog/security-implications-cors-node-js/>

## Fp Rule

- **Access-Control-Allow-Origin: * with NO Access-Control-Allow-Credentials: true header is not a CORS data-leak finding on an endpoint whose responses are identical for authenticated and anonymous callers: the browser will not attach cookies, TLS client certs or the Authorization header, so the attacker page reads the same public body a logged-out visitor already gets.**  
  `high_confidence` · score 0.918 · disproved by: The rule is wrong, and the CORS finding is real, if ANY of: (a) Access-Control-Allow-Credentials: true is also present; (b) ACAO is not a literal wildcard but an allowlisted or echoed origin; (c) the endpoint varies on Authorization, Cookie or mTLS state, proven by diffing the anonymous body against the authenticated one; (d) the response is intranet-only or otherwise not retrievable by the attacker without credentials. Any one of those turns the wildcard header into credentialed data exposure.
  sources: <https://www.zaproxy.org/docs/alerts/40040-3/> · <https://www.sonarsource.com/blog/never-underestimate-csrf-why-origin-reflection-is-a-bad-idea/>
- **An endpoint whose response is already public without a session is a CORS false positive and must not be reported as cross-origin data theft.**  
  `high_confidence` · score 0.899 · disproved by: A CORS finding survives only if the unauthenticated body differs from the credentialed cross-origin body; otherwise the exposure is pre-existing public access.
  sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
