---
name: host_header-hunting
description: Use when hunting Host Header Injection in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Host Header Injection — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 644 · OWASP A05:2021
> evidence: 25 items, 16 supported, 3 FP rules, 1 chains
> maturity: **mature**

The server builds a security-relevant URL or decision from a caller-controlled Host header.

**Also called:** host header, password reset poisoning, absolute url poisoning


## Prerequisites (do not start without these)

- Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the application never reflects the Host value into any response body, header or outbound link, a forged Host produces no observable difference and the prerequisite fails.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>

## Techniques (what to change)

- Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two di”) does not occur under a test that isolates that control.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.  _(merged 1 duplicate row(s))_
  - **Disproof:** None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://portswigger.net/web-security/host-header/exploiting> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
- The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The Vault server sends the pre-signed requests to the STS host and extracts the ”) does not occur under a test that isolates that control.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.  _(merged 1 duplicate row(s))_
  - **Disproof:** The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>

## Tests

- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour) states the full boundary.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
- To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.  _(merged 1 duplicate row(s))_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect) states the full boundary.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- To decide this case, observe: Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite) states the full boundary.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>

## Validation bar (how to prove it)

- The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>

## False-positive rules (when to reject it)

- A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.  _(merged 1 duplicate row(s))_
  - **Disproof:** Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
- A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.  _(merged 1 duplicate row(s))_
  - **Disproof:** The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
- A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
- An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.  _(merged 1 duplicate row(s))_
  - **Disproof:** It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.
  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when the response carries no-store or private cache directives, or when the application is fronted only by a per-user browser cache the attacker cannot write to.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>

## Impact framing

- When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.  _(merged 1 duplicate row(s))_
  - **Disproof:** If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.
  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- Without Host validation, an attacker can dispatch requests to the first (internal) name-based virtual host on the server, gaining access to applications that were not intended to be externally reachable.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refute if an authoritative source shows the server is configured to return an error for unknown hosts (e.g., a catch-all vhost returning 400/444) or otherwise refuses to route requests for unregistered hostnames.
  - Sources: <https://owasp.github.io/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection>

## Defence bypasses

- A server or application that trusts X-Forwarded-Host as a fallback when the Host header is absent, or that consults X-Forwarded-Host even when a Host header is present, can be made to build absolute URLs, reset links, and cached content from an attacker-controlled hostname.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refute only if an authoritative source shows the header is stripped by a trusted front-end (e.g., an explicitly configured proxy that removes X-Forwarded-Host from client traffic), or that the back-end ignores it in favour of Host in all code paths.
  - Sources: <https://assistsec.info/en/vulnerabilities/host-header-injection> · <https://cve.circl.lu/cwe/CWE-644> · <https://owasp.github.io/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection>
- Sending duplicate Host headers, or mixing an absolute-form request target with a Host header, can produce a divergence between the front-end router and the application logic, allowing a payload to pass validation while reaching a different code path.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refute if an authoritative source demonstrates that the stack in question consistently resolves duplicate headers to a single source of truth and applies identical validation to the resolved value.
  - Sources: <https://portswigger.net/web-security/host-header/exploiting>
- When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected.  _(merged 1 duplicate row(s))_
  - **Disproof:** It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.
  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>

## Chaining opportunities

- A host-header injection can be chained with web cache poisoning to serve attacker-controlled JavaScript to authenticated administrators, escalating to stored XSS and one-click remote code execution.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refute only if an authoritative source shows the Craft CMS instance is behind a proxy that strips X-Forwarded-Host, trustedHosts is not set to 'any', the URL validation is not bypassable, or the caching layer does not honour the response for the legitimate cache key.
  - Sources: <https://docs.devguard.org/vulnerability-database/GHSA-c55v-343g-5xff/> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf> · <https://secportal.io/vulnerabilities/cache-poisoning>
- When a password-reset email builds its absolute link from a Host value the framework resolves from an override header, poisoning that header during a victim's reset request produces an attacker-received reset token and full account takeover from a single unauthenticated request.  _(merged 1 duplicate row(s))_
  - **Disproof:** The chain is refuted if: the reset link is built from a server-side configured base URL or a canonical host allowlist that ignores both Host and the override headers, so the emitted link never leaves the legitimate domain; the reset token is delivered only to the account's registered mailbox and the link host is fixed regardless of the request, which removes the attacker's receiver entirely; or the reset token is single-use, short-lived, and invalidated on any parameter change, so a captured link cannot be redeemed. Emit the actual reset email and inspect the link host; do not infer from the request alone.
  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>


## Hunt procedure

1. Send a request with Host: your-collaborator-domain and check whether the response, a password-reset link or a cached page reflects it.
2. Test both the Host header and X-Forwarded-Host / X-Forwarded-For, and confirm which proxy headers the edge actually trusts.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/web/host_header/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id host_header`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
