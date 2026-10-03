# Open Redirect

> surface: `web` · CWE: 601 · OWASP: A01:2021
> maturity: **mature** — 41 items, 41 supported, 2 FP rules, 1 chains

A redirect target is not constrained to a trusted destination.

**Aliases:** open redirect, unvalidated redirect, redirect uri validation

## Signal

- **An open redirect is only present when user-supplied input reaches the destination of a redirect without validation, as distinct from any redirect that exists.**  
  `high_confidence` · score 0.929 · disproved by: If no supplied parameter alters the Location host, or the destination is always a fixed internal route, there is no open redirect to pursue.
  sources: <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory> · <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/>

## Technique

- **For example, a representation in the payload of a PUT request ( Section 4.3.4 ) represents the desired state of the target resource if the request is successfully applied, whereas a representation in the payload of a POST request ( Section 4.3.3 ) represents information to be processed by the target resource.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, a representation in the payload of a PUT request ( Section 4.3.4 ) represents".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **HTTP message framing does not use the multipart boundary as an indicator of message body length, though it might be used by implementations that generate or process the payload.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP message framing does not use the multipart boundary as an indicator of message body l".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A payload within a CONNECT request message has no defined semantics; sending a payload body on a CONNECT request might cause some existing implementations to reject the request.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a CONNECT request message has no defined semantics; sending a payload bod".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **If the response has a Content-Location header field and its field-value is a reference to the same URI as the effective request URI, the payload is a representation of the resource identified by the effective request URI.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the response has a Content-Location header field and its field-value is a reference to ".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A payload within a HEAD request message has no defined semantics; sending a payload body on a HEAD request might cause some existing implementations to reject the request.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a HEAD request message has no defined semantics; sending a payload body o".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Although this specification does not define any use for such a payload, future extensions to HTTP might use the OPTIONS body to make more detailed queries about the target resource.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although this specification does not define any use for such a payload, future extensions ".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **In other words, if one were to perform a GET request on this URI at the time of this message's generation, then a 200 (OK) response would contain the same representation that is enclosed as payload in this message.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In other words, if one were to perform a GET request on this URI at the time of this messa".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **For a request message: If the request has a Content-Location header field, then the sender asserts that the payload is a representation of the resource identified by the Content-Location field-value.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For a request message: If the request has a Content-Location header field, then the sender".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since the 205 status code implies that no additional content will be provided, a server MU".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **If no payload is desired, an origin server ought to send 204 (No Content) instead.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If no payload is desired, an origin server ought to send 204 (No Content) instead.".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A payload within a GET request message has no defined semantics; sending a payload body on a GET request might cause some existing implementations to reject the request.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a GET request message has no defined semantics; sending a payload body on".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request had been a GET, except that the payload header fields ( Section 3.3 ) MAY be omitted.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The server SHOULD send the same header fields in response to a HEAD request as it would ha".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the request method is GET or HEAD and the response status code is 203 (Non-Authoritativ".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A client that generates an OPTIONS request containing a payload body MUST send a valid Content-Type header field describing the representation media type.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A client that generates an OPTIONS request containing a payload body MUST send a valid Con".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **An origin server that allows PUT on a given target resource MUST send a 400 (Bad Request) response to a PUT request that contains a Content-Range header field ( Section 4.2 of [RFC7233] ), since the payload is likely to be partial content that has been mistakenly PUT as a full representation.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An origin server that allows PUT on a given target resource MUST send a 400 (Bad Request) ".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **In a response to a HEAD request, the representation header fields describe the representation data that would have been enclosed in the payload body if the same request had been a GET.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a response to a HEAD request, the representation header fields describe the representat".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A server MUST generate a Content-Length field with a value of "0" if no payload body is to".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **The response payload, if any, might also describe the communication options in a machine or human-readable representation.**  
  `high_confidence` · score 0.912 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The response payload, if any, might also describe the communication options in a machine o".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **There are several types of redirects: Redirects that indicate the resource might be available at a different URI, as provided by the Location field, as in the status codes 301 (Moved Permanently) , 302 (Found) , and 307 (Temporary Redirect) .**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There are several types of redirects: Redirects that indicate the resource might be availa".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A 100-continue expectation informs recipients that the client is about to send a (presumably large) message body in this request and wishes to receive a 100 (Continue) interim response if the request-line and header fields are not sufficient to cause an immediate success, redirect, or error response.**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A 100-continue expectation informs recipients that the client is about to send a (presumab".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A payload within a DELETE request message has no defined semantics; sending a payload body on a DELETE request might cause some existing implementations to reject the request.**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a DELETE request message has no defined semantics; sending a payload body".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **If the result of processing a POST would be equivalent to a representation of an existing resource, an origin server MAY redirect the user agent to that resource by sending a 303 (See Other) response with the existing resource's identifier in the Location field.**  
  `high_confidence` · score 0.8845 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the result of processing a POST would be equivalent to a representation of an existing ".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A sender that generates a message containing a payload body SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A sender that generates a message containing a payload body SHOULD generate a Content-Type".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined for the first type of redirect ( [RFC1945] , Section 9.3 ).**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined f".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Automatic redirection needs to done with care for methods not known to be safe , as defined in Section 4.2.1 , since the user might not wish to redirect an unsafe request.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Automatic redirection needs to done with care for methods not known to be safe , as define".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-Location" header field references a URI that can be used as an identifier for a specific resource corresponding to the representation in this message's payload.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-Location" h".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Early user agents split on whether the method applied to the redirect target would be the same as the original request or would be rewritten as GET.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Early user agents split on whether the method applied to the redirect target would be the ".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type.**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In practice, resource owners do not always properly configure their origin server to provi".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **This flexibility regarding line breaks applies only to text within a representation that has been assigned a "text" media type; it does not apply to "multipart" types or HTTP elements outside the payload body (e.g., header fields).**  
  `high_confidence` · score 0.857 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This flexibility regarding line breaks applies only to text within a representation that h".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote at".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenti".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote at".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenti".
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>

## Validation

- **An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.**  
  `high_confidence` · score 0.874 · disproved by: If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.
  sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications> · <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/>

## Fp Rule

- **A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.**  
  `high_confidence` · score 0.948 · disproved by: The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.**  
  `high_confidence` · score 0.918 · disproved by: The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
  sources: <https://www.zaproxy.org/docs/alerts/10028/> · <https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam>

## Chain Link

- **An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.**  
  `high_confidence` · score 0.984 · disproved by: If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.
  sources: <https://httpwg.org/specs/rfc7231.html> · <https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability>
