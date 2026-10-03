# Methodology — Host Header Injection

> Derived from 16 verified items. Regenerate with `python -m wks.methodgen --class host_header --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The server builds a security-relevant URL or decision from a caller-controlled Host header.

**References.** CWE-644 · A05:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.**

RFC 9110 states a request may be misdirected such that the received Host header field differs from the connection's host or port, which is exactly the condition a host-header attack exploits. Before hunting, find an application path that echoes the Host value into a response: a password-reset link, an absolute redirect, an emailed canonical URL, or a cache key. If no path reflects Host, the class has no foothold on that target.

- *Disproof:* If the application never reflects the Host value into any response body, header or outbound link, a forged Host produces no observable difference and the prerequisite fails.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [snyk.io](https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.**

The mechanism is a precedence disagreement, not a broken allowlist. Websites are often accessed via some kind of intermediary system, such as a load balancer or a reverse proxy, and in that kind of architecture the Host header that the back-end server receives may contain the domain name for one of these intermediary systems. To solve that problem the front-end may inject the X-Forwarded-Host header, containing the original value of the Host header from the client's initial request, and for this reason, when an X-Forwarded-Host header is present, many frameworks will refer to this instead. That last clause is the hunting trap: you may observe this behavior even when there is no front-end that uses this header. Procedure: hold Host at the legitimate value, add X-Forwarded-Host with the attacker value, and diff the response against a clean baseline. Any change in a generated absolute URL, a redirect Location, or an allow/deny decision is the finding. The same holds for X-Host, X-Forwarded-Server, X-HTTP-Host-Override and Forwarded, so probe the whole override family rather than the single well-known name.

- *Disproof:* The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [portswigger.net](https://portswigger.net/web-security/host-header/exploiting)

## 3. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.**

Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.

- *Disproof:* If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.
- *Evidence:* high_confidence — [httpd.apache.org](https://httpd.apache.org/docs/2.4/mod/core.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.html)

## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.**

Reflected client-side issues driven by the Host header are the classic host-header false positive, and the reason is structural. When probing for Host header attacks you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner. The reflection is therefore not a payload delivery mechanism. The same holds for an attacker who poisons their own request: they poison their own session, which they already control. Reject unless one of two upgrades is demonstrated: a shared cache in front of the page, which turns the useless reflected vulnerability into a dangerous stored one by persuading the cache to serve a poisoned response to other users; or a server-side sink, where the reflected value reaches an authorisation check, a redirect construction, or an absolute-URL builder, in which case the finding belongs to host header URL poisoning, not to reflected XSS.

- *Disproof:* The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [portswigger.net](https://portswigger.net/web-security/host-header/exploiting)

**A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.**

The observation is a crash, a reset, or corrupted state on a device when the Host header is sent at exactly the configured maximum length, which is commonly written up as host-header handling weakness and escalated as routing manipulation or password-reset poisoning. Two different failures are being conflated. Host-header routing abuse depends on a backend that trusts the field to choose an upstream, generate absolute URLs, or select a cache key, and the header value is attacker-chosen data in that case: the user agent is a client-supplied header, so a control that checks the name but not the address can be bypassed by forging it. A length-check defect is different. In a documented embedded case, the length of the Host header value is checked to ensure that it is at most the configured maximum and that length is then used as the index into a heap buffer, so a value of exactly the configured size results in a one byte buffer overwrite with a NULL byte. No backend routing decision exists to steer, and no cache key changes. The distinguishing test is the shape of the effect: if varying the Host value across many syntactically valid hostnames produces no differential response in links, redirects, or cache hits, and only the boundary length crashes the process, the finding belongs to input validation, not to host-header injection.

- *Disproof:* Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746)

**An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.**

Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.

- *Disproof:* It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_proxy_module.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.html)

**A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.**

Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.

- *Disproof:* It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.
- *Evidence:* high_confidence — [httpd.apache.org](https://httpd.apache.org/docs/2.4/mod/core.html); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc9110.html)

## 5. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected.**

Mechanism: When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.

- *Disproof:* It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.
- *Evidence:* high_confidence — [httpd.apache.org](https://httpd.apache.org/docs/2.4/mod/core.html); [nginx.org](https://nginx.org/en/docs/http/ngx_http_realip_module.html)

## 6. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**When a password-reset email builds its absolute link from a Host value the framework resolves from an override header, poisoning that header during a victim's reset request produces an attacker-received reset token and full account takeover from a single unauthenticated request.**

Three facts compose. First, the vulnerable construction: if a web application uses the host header for authorization checks or to construct absolute links, an attacker may be able to manipulate the host header to force the construction of malicious links. Second, the bypass of validation: because a front-end may inject X-Forwarded-Host to preserve the original host, many frameworks will refer to that header instead, and the behaviour is observable even with no front-end using it, so a deployment that validates Host strictly is still exploitable through the override name. Third, the amplification: if the target uses a web cache, the same poisoning can be turned from a useless reflected weakness into a stored one served to other users, which lets a single poisoned response harvest several victims' reset tokens rather than one. Composed: trigger a reset for the victim with an attacker-controlled override header, let the application build a reset URL pointing at the attacker's domain, receive the token in the attacker's mail or hosting logs, and complete the reset. No authentication is needed at any point.

- *Disproof:* The chain is refuted if: the reset link is built from a server-side configured base URL or a canonical host allowlist that ignores both Host and the override headers, so the emitted link never leaves the legitimate domain; the reset token is delivered only to the account's registered mailbox and the link host is fixed regardless of the request, which removes the attacker's receiver entirely; or the reset token is single-use, short-lived, and invalidated on any parameter change, so a captured link cannot be redeemed. Emit the actual reset email and inspect the link host; do not infer from the request alone.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations); [portswigger.net](https://portswigger.net/web-security/host-header/exploiting)

## 7. Impact

_What is actually demonstrable, and what to stop claiming._

**When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.**

Step: send the same request twice with two different Host header values pointing at distinct backends and compare the response body, any absolute URL the server generates from that Host, and which tenant's data comes back. The attacker gains whatever the wrongly selected backend serves, including credentials issued for a host the attacker chose, because a load balancer in front of an identity or session API that makes routing decisions based on the Host header will deliver the request to the attacker's intended backend on the attacker's terms. Note that a user agent normally supplies the Host field itself, so the primitive only exists where a proxy forwards or trusts the client value.

- *Disproof:* If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.
- *Evidence:* high_confidence — [googleprojectzero.blogspot.com](https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html); [httpwg.org](https://httpwg.org/specs/rfc9110.html)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
