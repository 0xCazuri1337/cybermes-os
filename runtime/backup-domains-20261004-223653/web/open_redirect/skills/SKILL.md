---
name: open_redirect-hunting
description: Use when hunting Open Redirect in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Open Redirect — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 601 · OWASP A01:2021
> evidence: 66 items, 26 supported, 7 FP rules, 1 chains
> maturity: **mature**

A redirect target is not constrained to a trusted destination.

**Also called:** open redirect, unvalidated redirect, redirect uri validation


## Recon signals (where to look)

- An open redirect is only present when user-supplied input reaches the destination of a redirect without validation, as distinct from any redirect that exists.  _(merged 1 duplicate row(s))_
  - **Disproof:** If no supplied parameter alters the Location host, or the destination is always a fixed internal route, there is no open redirect to pursue.
  - Sources: <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>

## Techniques (what to change)

- A 100-continue expectation informs recipients that the client is about to send a (presumably large) message body in this request and wishes to receive a 100 (Continue) interim response if the request-line and header fields are not sufficient to cause an immediate success, redirect, or error response.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A 100-continue expectation informs recipients that the client is about to send a (presumab".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A client that generates an OPTIONS request containing a payload body MUST send a valid Content-Type header field describing the representation media type.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A client that generates an OPTIONS request containing a payload body MUST send a valid Con".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A payload within a CONNECT request message has no defined semantics; sending a payload body on a CONNECT request might cause some existing implementations to reject the request.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a CONNECT request message has no defined semantics; sending a payload bod".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A payload within a DELETE request message has no defined semantics; sending a payload body on a DELETE request might cause some existing implementations to reject the request.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a DELETE request message has no defined semantics; sending a payload body".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A payload within a GET request message has no defined semantics; sending a payload body on a GET request might cause some existing implementations to reject the request.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a GET request message has no defined semantics; sending a payload body on".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A payload within a HEAD request message has no defined semantics; sending a payload body on a HEAD request might cause some existing implementations to reject the request.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A payload within a HEAD request message has no defined semantics; sending a payload body o".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A sender that generates a message containing a payload body SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A sender that generates a message containing a payload body SHOULD generate a Content-Type".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A server MUST generate a Content-Length field with a value of "0" if no payload body is to".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote at".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- Although this specification does not define any use for such a payload, future extensions to HTTP might use the OPTIONS body to make more detailed queries about the target resource.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Although this specification does not define any use for such a payload, future extensions ".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- An origin server that allows PUT on a given target resource MUST send a 400 (Bad Request) response to a PUT request that contains a Content-Range header field ( Section 4.2 of [RFC7233] ), since the payload is likely to be partial content that has been mistakenly PUT as a full representation.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An origin server that allows PUT on a given target resource MUST send a 400 (Bad Request) ".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- Automatic redirection needs to done with care for methods not known to be safe , as defined in Section 4.2.1 , since the user might not wish to redirect an unsafe request.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Automatic redirection needs to done with care for methods not known to be safe , as define".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenti".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- Early user agents split on whether the method applied to the redirect target would be the same as the original request or would be rewritten as GET.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Early user agents split on whether the method applied to the redirect target would be the ".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- For a request message: If the request has a Content-Location header field, then the sender asserts that the payload is a representation of the resource identified by the Content-Location field-value.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For a request message: If the request has a Content-Location header field, then the sender".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- For example, a representation in the payload of a PUT request ( Section 4.3.4 ) represents the desired state of the target resource if the request is successfully applied, whereas a representation in the payload of a POST request ( Section 4.3.3 ) represents information to be processed by the target resource.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For example, a representation in the payload of a PUT request ( Section 4.3.4 ) represents".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- HTTP message framing does not use the multipart boundary as an indicator of message body length, though it might be used by implementations that generate or process the payload.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "HTTP message framing does not use the multipart boundary as an indicator of message body l".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- If no payload is desired, an origin server ought to send 204 (No Content) instead.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If no payload is desired, an origin server ought to send 204 (No Content) instead.".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the request method is GET or HEAD and the response status code is 203 (Non-Authoritativ".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- If the response has a Content-Location header field and its field-value is a reference to the same URI as the effective request URI, the payload is a representation of the resource identified by the effective request URI.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the response has a Content-Location header field and its field-value is a reference to ".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- If the result of processing a POST would be equivalent to a representation of an existing resource, an origin server MAY redirect the user agent to that resource by sending a 303 (See Other) response with the existing resource's identifier in the Location field.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If the result of processing a POST would be equivalent to a representation of an existing ".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- In a response to a HEAD request, the representation header fields describe the representation data that would have been enclosed in the payload body if the same request had been a GET.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a response to a HEAD request, the representation header fields describe the representat".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- In other words, if one were to perform a GET request on this URI at the time of this message's generation, then a 200 (OK) response would contain the same representation that is enclosed as payload in this message.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In other words, if one were to perform a GET request on this URI at the time of this messa".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In practice, resource owners do not always properly configure their origin server to provi".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".
  - Sources: <https://httpwg.org/specs/rfc7231.html>
- Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined for the first type of redirect ( [RFC1945] , Section 9.3 ).  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined f".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-Location" header field references a URI that can be used as an identifier for a specific resource corresponding to the representation in this message's payload.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-Location" h".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Since the 205 status code implies that no additional content will be provided, a server MU".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- The response payload, if any, might also describe the communication options in a machine or human-readable representation.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The response payload, if any, might also describe the communication options in a machine o".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request had been a GET, except that the payload header fields ( Section 3.3 ) MAY be omitted.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The server SHOULD send the same header fields in response to a HEAD request as it would ha".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- There are several types of redirects: Redirects that indicate the resource might be available at a different URI, as provided by the Location field, as in the status codes 301 (Moved Permanently) , 302 (Found) , and 307 (Temporary Redirect) .  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There are several types of redirects: Redirects that indicate the resource might be availa".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- This flexibility regarding line breaks applies only to text within a representation that has been assigned a "text" media type; it does not apply to "multipart" types or HTTP elements outside the payload body (e.g., header fields).  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This flexibility regarding line breaks applies only to text within a representation that h".
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.  _(merged 2 duplicate row(s))_ _(unverified)_
  - **Disproof:** The redirect parameter refuses external hosts or ignores off-site values and always resolves to a fixed internal path.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/> · <https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md>

## Tests

- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host) states the full boundary.
  - Sources: <https://expressjs.com/en/advanced/best-practice-security.html> · <https://openid.net/specs/openid-connect-core-1_0.html>
- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 2 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect) states the full boundary.
  - Sources: <https://expressjs.com/en/advanced/best-practice-security.html> · <https://openid.net/specs/openid-connect-core-1_0.html> · <https://developers.google.com/identity/protocols/oauth2/web-server>
- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter) states the full boundary.
  - Sources: <https://developers.google.com/identity/protocols/oauth2/web-server> · <https://expressjs.com/en/advanced/best-practice-security.html>

## Validation bar (how to prove it)

- An open redirect is proved by a 3xx response whose Location header resolves to an attacker-controlled origin, captured with the redirect not followed; the presence of a `next`, `returnUrl` or `redirect` parameter on a request that returned 200 proves nothing.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the response cannot be observed with its headers intact — a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured to follow redirects — in which case the Location must be captured from a raw exchange or from the browser's network log, and a screenshot of the final page is insufficient evidence.
  - Sources: <https://developers.google.com/identity/protocols/oauth2/web-server> · <https://expressjs.com/en/advanced/best-practice-security.html>
- An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.
  - Sources: <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/> · <https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications>

## False-positive rules (when to reject it)

- A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.  _(merged 1 duplicate row(s))_
  - **Disproof:** The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.
  - Sources: <https://www.zaproxy.org/docs/alerts/10028/> · <https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam>
- A 3xx response whose Location value is a relative reference (/login, ~/folder/Login.aspx, ../dashboard) or an absolute URL on the request's own origin is not an open redirect, because URL resolution against the current base keeps the navigation on the same origin, so no untrusted site ever receives the victim.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule fails if the resolved value's authority differs from the request origin in any way the browser honours: a protocol-relative //evil.example, a backslash form \evil.example that some clients normalise to //, an absolute URL with a userinfo part (https://app.example.com@evil.example), a same-origin-looking host that is actually a subdomain of an attacker domain, or a value that the framework rewrites (for example a Rails redirect_to that expands a model attribute, or a 307 that replays the body to another origin). Any of those means the string after resolution is off-origin and the finding is real.
  - Sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- A next=/returnUrl= parameter whose reflected value only occupies the path, query or fragment of a Location value whose scheme and authority are fixed in code is not an open redirect, because the browser resolves the authority from the code and only a same-origin path segment is attacker-controlled.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule stops being true the moment the attacker can reach the scheme or authority: a Location value that is the bare parameter (Location: <user>), a value concatenated without a separator after the host so that user input supplies userinfo or a new authority (https://app.example.com@evil.example, //evil.example, \evil.example, or a value beginning with a scheme), a prefix assembled by string concatenation from a configurable base, or a second redirect hop where the stored off-domain string is itself used as the next Location. Any of those makes the same reflected string the actual navigation target and the finding real.
  - Sources: <https://cwe.mitre.org/data/definitions/601.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- A redirect parameter whose value must resolve to a path on the application's own origin is not an open redirect; the finding requires the attacker to control the destination origin, not merely the path or the query string that follows the application's own host.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is wrong when the value is resolved by a client rather than the server — a protocol-relative value, a scheme-relative or backslash-normalised form, or a value that a downstream client (email client, chat renderer, mobile deep-link handler) reinterprets as absolute — because the server-side check passes while the user agent still leaves the origin.
  - Sources: <https://expressjs.com/en/advanced/best-practice-security.html> · <https://openid.net/specs/openid-connect-core-1_0.html>
- A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.  _(merged 1 duplicate row(s))_
  - **Disproof:** The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- An authorization server answering with a `redirect_uri_mismatch` error has refused the unregistered destination, so that exchange is the authorisation server's defence working and must not be reported as an open redirect on the client.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is wrong when the client is the component at fault — it holds a pre-registered wildcard or prefix pattern that the server honours, so an attacker's host matches a registered pattern and the code is returned to it — or when the mismatch is only for the tested variant while a weaker registered form still accepts the malicious origin, in which case the server's exact-match rule is not what stopped the attack.
  - Sources: <https://developers.google.com/identity/protocols/oauth2/web-server> · <https://openid.net/specs/openid-connect-core-1_0.html>

## Evidence requirements

- A convincing observation for this class is: A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.  _(merged 3 duplicate row(s))_ _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.c6c732df) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: A server that receives an Expect field-value other than 100-continue MAY respond with a 417 (Expectation Failed) status code to indicate that the unexpected expectation cannot be met.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.852c145c) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: HEAD The HEAD method is identical to GET except that the server MUST NOT send a message body in the response (i.e., the response terminates at the end of the header section).  _(merged 2 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.77f2d9a5) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.1fb211f8) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: Redirection 3xx The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request.  _(merged 2 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.57ed1a35) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: Redirection to a different resource, identified by the Location field, that can represent an indirect response to the request, as in the 303 (See Other) status code.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.64eea101) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.74923980) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- A convincing observation for this class is: that offers a choice of matching resources, each capable of representing the original request target, as in the 300 (Multiple Choices) status code.  _(merged 1 duplicate row(s))_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.3b706ea3) states the full boundary.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- The consequential open-redirect evidence is the post-authentication hop — the redirect that fires after a real login or token grant, not a bare redirect on an unauthenticated entry point, because the pre-auth redirect carries no session while the post-auth one lands the user on the attacker's page already carrying a fresh session.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is false when the pre-auth redirect is itself the finding — for example it feeds a `Referer`-based reset or a state parameter that the attacker can poison, or it is on a page that performs an authenticated action before redirecting — in which case the unauthenticated redirect is independently exploitable and its severity does not depend on a completed login.
  - Sources: <https://developers.google.com/identity/protocols/oauth2/web-server> · <https://expressjs.com/en/advanced/best-practice-security.html>

## Defence bypasses

- An open-redirect defence that inspects the destination with a real URL parser and compares the host is bypassed by any implementation that does a substring, suffix or endsWith test on the raw string, because a value such as an attacker host whose name merely contains the allowed host, or an allowed host with a trailing credential-holding prefix, satisfies the substring test while resolving elsewhere.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is false when the check parses with a WHATWG-compatible URL constructor and compares the parsed host for exact equality, because the confusable forms then fail to match and no substring confusion is possible; a check that also rejects relative and scheme-relative input closes the remaining variants.
  - Sources: <https://expressjs.com/en/advanced/best-practice-security.html> · <https://openid.net/specs/openid-connect-core-1_0.html>

## Chaining opportunities

- An open redirect on the OAuth authorize endpoint chains into authorization-code theft when redirect_uri is accepted from user input instead of an allowlist.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the authorize endpoint rejects or ignores an unregistered redirect_uri and the Location field stays on an allowlisted origin, the chain does not form and the finding is a normal post-login navigation.
  - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability>

## Rejected before you report

- **An endpoint reflects a redirect parameter into the Location header, therefore it is an open redirect**
  - Killed by: The 302 pointed back at the same host with the parameter echoed into the URL. No request ever left the origin, so an attacker cannot place their page in the redirect chain
  - Rule: A reflected redirect parameter is not an open redirect. Resolve the Location and confirm the 3xx leaves the origin: a same-host 302 with the parameter echoed is not a finding, and 'reflected parameter' alone will be read as padding on review


## Hunt procedure

1. Supply an absolute URL to your own host as the redirect parameter and confirm the 3xx Location header points at it.
2. Check whether the parameter is validated after the redirect is issued, and whether a nested redirect (redirect_uri on an OAuth flow) is honoured.
3. State the phishing impact plainly; an open redirect with no sensitive token in the URL is usually informational, not high.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/open_redirect/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id open_redirect`
