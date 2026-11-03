<!-- GENERATED from db/wks.db — do not edit -->
# Host Header Injection

## Definition

The server builds a security-relevant URL or decision from a caller-controlled Host header.

- **CWE:** 644
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["host header", "password reset poisoning", "absolute url poisoning"]

Canonical home for `host_header`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.**

RFC 9110 states a request may be misdirected such that the received Host header field differs from the connection's host or port, which is exactly the condition a host-header attack exploits. Before hunting, find an application path that echoes the Host value into a response: a password-reset link, an absolute redirect, an emailed canonical URL, or a cache key. If no path reflects Host, the class has no foothold on that target.

*Disproof:* If the application never reflects the Host value into any response body, header or outbound link, a forged Host produces no observable difference and the prerequisite fails.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: When probing for Host header attacks you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner**

Derived from host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding) states the full boundary.

## Exploitation

**Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure.**

se case for Vault is to provide one of your services, such as your webserver, short lived credentials to your database or a third-party resource like an AWS S3 bucket. Using a central secret storage like Vault offers security benefits such as centralized auditing, enforced credentials rotation or encrypted data storage. However, a central storage is also a very interesting target for an attacker. Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure. Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers. Readers familiar with Vault can feel free to skip this section. Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored se

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting a vulnerability in Vault could give an attacker full access to a wide range of ".

**Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers.**

S3 bucket. Using a central secret storage like Vault offers security benefits such as centralized auditing, enforced credentials rotation or encrypted data storage. However, a central storage is also a very interesting target for an attacker. Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure. Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers. Readers familiar with Vault can feel free to skip this section. Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets. For authentication, it supports pluggable auth methods ranging from static credentials, LDAP or Radius, to full integration into third-party OpenID Connect (OIDC) providers or Cloud I

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Before diving into the technical details of the vulnerabilities, the next section gives an".

**Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets.**

a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure. Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers. Readers familiar with Vault can feel free to skip this section. Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets. For authentication, it supports pluggable auth methods ranging from static credentials, LDAP or Radius, to full integration into third-party OpenID Connect (OIDC) providers or Cloud Identity Access Management (IAM) platforms. For infrastructure that runs on a supported cloud provider, using the provider's IAM platform for authentication is a logical choice. Take AWS as an example: Almost every wo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Authenticating to Vault Interfacing with Vault requires authentication and Vault supports ".

**If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function.**

AWS IAM role lambda-role . A vault policy can now be used to grant the dbclient role access to the database secret. When the lambda function executes, it authenticates to Vault by sending a request to the /v1/auth/aws/login API endpoint. I’ll go into the exact layout of this request later in the post, but for now just assume that the request allows Vault to verify the AWS IAM role of the caller. If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function. This token can now be used to fetch the database secret from Vault. Depending on the database backend, this secret could be a static user-password combination, a short lived client certificate or even a dynamically created credential pair . Using Vault in this way has some nice security benefits: The lambda function itself does not need to contain bootstrap credentials and every access to the dat

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authentication succeeds, Vault returns a short-lived API token for the dbclient role ba".

**Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .**

ess to the database credentials is auditable. Rotating old or compromised database credentials is straightforward and can be centrally enforced. However, this operational simplicity is only possible because of hidden complexity in the AWS iam auth method. How does the /v1/auth/aws/login API endpoint actually work and is there a way a unauthenticated attacker can impersonate a random AWS IAM role? Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 . We are interested in the iam mechanism, which is the recommended variant and also used in our previous Lambda example. iam auth is built on top of an AWS API method called GetCallerIdentity , part of the AWS Security Token Service (STS). As its name implies, GetCallerIdentity returns details about the IAM role or user whose credentials were used to call the API. To understand how Vault uses this

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two di”) does not occur under a test that isolates that control.

**The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.**

low a limited form of impersonation. A popular example use case is to give clients the ability to upload a file to S3 without giving them access to credentials with write permissions. The Vault aws authentication mechanism is a simple variant of this technique.  

 

 The client pre-signs an HTTP request to the STS GetCallerIdentity method and sends a serialized version of it to the Vault server. The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result. The server-side part of this flow is implemented in pathLoginUpdate in builtin/credential/aws/path_login.go : func ( b * backend ) pathLoginUpdateIam ( ctx context . Context , req * logical . Request , data * framework . FieldData ) (* logical . Response , error ) {     method := data . Get ( "iam_http_request_method" ).( string )      ...      // In the future, might consider supporting GET

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The Vault server sends the pre-signed requests to the STS host and extracts the ”) does not occur under a test that isolates that control.

**On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.**

On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.

HackTricks reference: host header (https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md)

*Disproof:* None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.

**On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.**

On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.

HackTricks reference: host header (https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md)

*Disproof:* None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.

**When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.**

The mechanism is a precedence disagreement, not a broken allowlist. Websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy, and in that kind of architecture the Host header that the back-end server receives may contain the domain name for one of these intermediary systems. To solve that problem the front-end may inject the X-Forwarded-Host header, containing the original value of the Host header from the client's initial request, and for this reason, when an X-Forwarded-Host header is present, many frameworks will refer to this instead. That last clause is the hunting trap: you may observe this behavior even when there is no front-end that uses this header. Procedure: hold Host at the legitimate value, add X-Forwarded-Host with the attacker value, and diff the response against a clean baseline. Any change in a generated absolute URL, a redirect Location, or an allow/deny decision is the finding. The same holds for X-Host, X-Forwarded-Server, X-HTTP-Host-Override and Forwarded, so probe the whole override family rather than the single well-known name.

*Disproof:* The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.

## Variations

**A server or application that trusts X-Forwarded-Host as a fallback when the Host header is absent, or that consults X-Forwarded-Host even when a Host header is present, can be made to build absolute URLs, reset links, and cached content from an attacker-controlled hostname.**

The X-Forwarded-Host header is a de facto standard for reaching the original client hostname through a proxy, but it is unvalidated when accepted from any client. If the application does not strip it at the reverse proxy, an attacker can send Host: www.example.com plus X-Forwarded-Host: attacker.com. The back-end then resolves every outbound URL (password resets, OAuth callbacks, embedded asset URLs) against attacker.com. This is the most common and most reliably exploitable path to host-header injection because it bypasses any validation that only inspects the Host header.

*Disproof:* Refute only if an authoritative source shows the header is stripped by a trusted front-end (e.g., an explicitly configured proxy that removes X-Forwarded-Host from client traffic), or that the back-end ignores it in favour of Host in all code paths.

**Sending duplicate Host headers, or mixing an absolute-form request target with a Host header, can produce a divergence between the front-end router and the application logic, allowing a payload to pass validation while reaching a different code path.**

Servers disagree on which Host header instance to honour. A front-end may trust the first occurrence while the back-end trusts the final occurrence, or the request-line may be normalised differently from the Host header. Ambiguous requests can therefore be routed to the intended target while the injected payload lands in the validated value. The same ambiguity applies to an absolute URL on the request line versus a separate Host header; different stacks prioritise these differently, and the front end may not perform the same validation as the application.

*Disproof:* Refute if an authoritative source demonstrates that the stack in question consistently resolves duplicate headers to a single source of truth and applies identical validation to the resolved value.

**When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected.**

Mechanism: When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.

*Disproof:* It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.host_header.auto.01` — host_header: observe, exercise, confirm (goal: `Establish, exercise and confirm a host_header condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.**

Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.

*Disproof:* It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.

**An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.**

Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.

*Disproof:* It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.

**Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed.**

Mechanism: Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when the response carries no-store or private cache directives, or when the application is fronted only by a per-user browser cache the attacker cannot write to.

*Disproof:* It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when the response carries no-store or private cache directives, or when the application is fronted only by a per-user browser cache the attacker cannot write to.

**A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.**

The observation is a crash, a reset, or corrupted state on a device when the Host header is sent at exactly the configured maximum length, which is commonly written up as host-header handling weakness and escalated as routing manipulation or password-reset poisoning. Two different failures are being conflated. Host-header routing abuse depends on a backend that trusts the field to choose an upstream, generate absolute URLs, or select a cache key, and the header value is attacker-chosen data in that case: the user agent is a client-supplied header, so a control that checks the name but not the address can be bypassed by forging it. A length-check defect is different. In a documented embedded case, the length of the Host header value is checked to ensure that it is at most the configured maximum and that length is then used as the index into a heap buffer, so a value of exactly the configured size results in a one byte buffer overwrite with a NULL byte. No backend routing decision exists to steer, and no cache key changes. The distinguishing test is the shape of the effect: if varying the Host value across many syntactically valid hostnames produces no differential response in links, redirects, or cache hits, and only the boundary length crashes the process, the finding belongs to input validation, not to host-header injection.

*Disproof:* Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.

**A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.**

Reflected client-side issues driven by the Host header are the classic host-header false positive, and the reason is structural. When probing for Host header attacks you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner. The reflection is therefore not a payload delivery mechanism. The same holds for an attacker who poisons their own request: they poison their own session, which they already control. Reject unless one of two upgrades is demonstrated: a shared cache in front of the page, which turns the useless reflected vulnerability into a dangerous stored one by persuading the cache to serve a poisoned response to other users; or a server-side sink, where the reflected value reaches an authorisation check, a redirect construction, or an absolute-URL builder, in which case the finding belongs to host header URL poisoning, not to reflected XSS.

*Disproof:* The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.

## Validation

**The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.**

Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.

*Disproof:* If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.

**To decide this case, observe: When probing for Host header attacks you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner.**

Derived from host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding) states the full boundary.

**To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.**

Derived from host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour) states the full boundary.

**To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.**

Derived from host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.

**To decide this case, observe: Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.**

Derived from host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist) states the full boundary.

## Impact

**Without Host validation, an attacker can dispatch requests to the first (internal) name-based virtual host on the server, gaining access to applications that were not intended to be externally reachable.**

Web servers host multiple applications on one IP address and route them by the Host header. Supplying an arbitrary or unregistered hostname can route the request to the first virtual host on the list, or to a virtual host that is not exposed through the front end. This can reveal internal applications, administrative panels, or content that the attacker's proxy would not normally reach, and it is the prerequisite for many downstream effects such as cache poisoning and password reset poisoning.

*Disproof:* Refute if an authoritative source shows the server is configured to return an error for unknown hosts (e.g., a catch-all vhost returning 400/444) or otherwise refuses to route requests for unregistered hostnames.

**When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.**

Step: send the same request twice with two different Host header values pointing at distinct backends and compare the response body, any absolute URL the server generates from that Host, and which tenant's data comes back. The attacker gains whatever the wrongly selected backend serves, including credentials issued for a host the attacker chose, because a load balancer in front of an identity or session API that makes routing decisions based on the Host header will deliver the request to the attacker's intended backend on the attacker's terms. Note that a user agent normally supplies the Host field itself, so the primitive only exists where a proxy forwards or trusts the client value.

*Disproof:* If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations>
- **assistsec.info** (research)
  - <https://assistsec.info/en/vulnerabilities/host-header-injection>
- **cve.circl.lu** (research)
  - <https://cve.circl.lu/cwe/CWE-644>
- **docs.devguard.org** (research)
  - <https://docs.devguard.org/vulnerability-database/GHSA-c55v-343g-5xff/>
- **github.com** (docs)
  - <https://github.com/armourinfosec/Secure-PHP-Development/blob/main/Security/Host-Header-Injection.md>
- **googleprojectzero.blogspot.com** (research)
  - <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **helpnetsecurity.com** (research)
  - <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
- **httpd.apache.org** (writeup)
  - <https://httpd.apache.org/docs/2.4/mod/core.html>
- **httpwg.org** (standard)
  - <https://httpwg.org/specs/rfc9110.html>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
- **nginx.org** (docs)
  - <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
  - <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
- **owasp.github.io** (docs)
  - <https://owasp.github.io/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection>
- **portswigger.net** (research)
  - <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf>
  - <https://portswigger.net/web-security/host-header/exploiting>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc9110.html>
- **secportal.io** (research)
  - <https://secportal.io/vulnerabilities/cache-poisoning>
  - <https://secportal.io/vulnerabilities/host-header-injection>
- **snyk.io** (writeup)
  - <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
