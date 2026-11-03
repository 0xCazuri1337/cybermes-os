<!-- GENERATED from db/wks.db — do not edit -->
# Host Header Injection

> surface: `web` · CWE: 644 · OWASP: A05:2021
> maturity: **mature** — 25 items, 16 supported, 3 FP rules, 1 chains

The server builds a security-relevant URL or decision from a caller-controlled Host header.

**Aliases:** host header, password reset poisoning, absolute url poisoning

## Prerequisite

- **Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.**  
  `high_confidence` · score 0.9565 · disproved by: If the application never reflects the Host value into any response body, header or outbound link, a forged Host produces no observable difference and the prerequisite fails.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>

## Technique

- **When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.**  
  `high_confidence` · score 0.93 · disproved by: The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
- **On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.**  
  `high_confidence` · score 0.885 · disproved by: None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
  sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://portswigger.net/web-security/host-header/exploiting> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
- **The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.**  
  `high_confidence` · score 0.857 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The Vault server sends the pre-signed requests to the STS host and extracts the ”) does not occur under a test that isolates that control.
  sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .**  
  `high_confidence` · score 0.7995 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two di”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>

## Test

- **To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.**  
  `high_confidence` · score 0.8965 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect) states the full boundary.
  sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>

## Fp Rule

- **A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.**  
  `high_confidence` · score 0.93 · disproved by: The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
- **An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.**  
  `high_confidence` · score 0.924 · disproved by: It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.
  sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
- **A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.**  
  `high_confidence` · score 0.9205 · disproved by: Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>

## Impact

- **When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.**  
  `high_confidence` · score 0.948 · disproved by: If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>

## Bypass

- **When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected.**  
  `high_confidence` · score 0.8655 · disproved by: It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.
  sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
- **A server or application that trusts X-Forwarded-Host as a fallback when the Host header is absent, or that consults X-Forwarded-Host even when a Host header is present, can be made to build absolute URLs, reset links, and cached content from an attacker-controlled hostname.**  
  `high_confidence` · score 0.8515 · disproved by: Refute only if an authoritative source shows the header is stripped by a trusted front-end (e.g., an explicitly configured proxy that removes X-Forwarded-Host from client traffic), or that the back-end ignores it in favour of Host in all code paths.
  sources: <https://assistsec.info/en/vulnerabilities/host-header-injection> · <https://cve.circl.lu/cwe/CWE-644> · <https://owasp.github.io/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection>

## Chain Link

- **A host-header injection can be chained with web cache poisoning to serve attacker-controlled JavaScript to authenticated administrators, escalating to stored XSS and one-click remote code execution.**  
  `high_confidence` · score 0.97 · disproved by: Refute only if an authoritative source shows the Craft CMS instance is behind a proxy that strips X-Forwarded-Host, trustedHosts is not set to 'any', the URL validation is not bypassable, or the caching layer does not honour the response for the legitimate cache key.
  sources: <https://docs.devguard.org/vulnerability-database/GHSA-c55v-343g-5xff/> · <https://portswigger.net/kb/papers/c3wwniai/web-cache-entanglement.pdf> · <https://secportal.io/vulnerabilities/cache-poisoning>
- **When a password-reset email builds its absolute link from a Host value the framework resolves from an override header, poisoning that header during a victim's reset request produces an attacker-received reset token and full account takeover from a single unauthenticated request.**  
  `high_confidence` · score 0.9025 · disproved by: The chain is refuted if: the reset link is built from a server-side configured base URL or a canonical host allowlist that ignores both Host and the override headers, so the emitted link never leaves the legitimate domain; the reset token is delivered only to the account's registered mailbox and the link host is fixed regardless of the request, which removes the attacker's receiver entirely; or the reset token is single-use, short-lived, and invalidated on any parameter change, so a captured link cannot be redeemed. Emit the actual reset email and inspect the link host; do not infer from the request alone.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>

## Pattern

- **When the Host header value is reflected into password reset links, an attacker who can trigger a reset for a victim can poison the reset URL and steal the token when the victim clicks the link.**  
  `high_confidence` · score 0.8355 · disproved by: Refute if an authoritative source shows the application validates the Host header against an allowlist of legitimate domains before reflecting it into reset links, or otherwise does not use the header in the reset URL.
  sources: <https://owasp.github.io/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/17-Testing_for_Host_Header_Injection> · <https://secportal.io/vulnerabilities/host-header-injection>

## Remediation

- **Host header validation must be enforced at the edge: a catch-all virtual host returning 400/444 for unknown hosts, UseCanonicalName On so SERVER_NAME is trustworthy, and stripping client-controlled forwarding headers before they reach the application.**  
  `high_confidence` · score 0.8355 · disproved by: Refute if an authoritative source demonstrates a configuration that both enforces a single canonical host at the edge and strips forwarding headers yet still reflects an unvalidated Host value into outgoing URLs.
  sources: <https://github.com/armourinfosec/Secure-PHP-Development/blob/main/Security/Host-Header-Injection.md> · <https://secportal.io/vulnerabilities/cache-poisoning>
