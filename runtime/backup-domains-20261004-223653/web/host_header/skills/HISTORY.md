# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- host_header@current
+++ host_header@new
@@ -70,4 +70,4 @@
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
 ---
-Full class document: `domains/web/host_header/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id host_header`
+Full class document: `domains/web/host_header/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id host_header`
```

## 2026-10-02 19:37 — 97 diff lines
- items: 23 (supported 16), FP rules 4, chains 1, state mature

```diff
--- host_header@current
+++ host_header@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 644 · OWASP A05:2021
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 16 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 The server builds a security-relevant URL or decision from a caller-controlled Host header.
@@ -26,30 +26,66 @@
 
 ## Techniques (what to change)
 
-- Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure.
+- Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting a vulnerability in Vault could give an attacker full access to a wide range of ".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers.
+- Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Before diving into the technical details of the vulnerabilities, the next section gives an".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets.
+- Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Authenticating to Vault Interfacing with Vault requires authentication and Vault supports ".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function.
+- If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authentication succeeds, Vault returns a short-lived API token for the dbclient role ba".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .
+- Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 . _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different au".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.
+- The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM in".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 - When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.
   - **Disproof:** The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
+## Tests
+
+- To decide this case, observe: you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner. The reflection is therefore not a payload delivery mechanism.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding) states the full boundary.
+  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
+- To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to sta
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour) states the full boundary.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls. How to apply it in the fi
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect) states the full boundary.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- To decide this case, observe: ation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demon
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite) states the full boundary.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy h
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist) states the full boundary.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
+
+## Validation bar (how to prove it)
+
+- The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.
+  - **Disproof:** If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+
 ## False-positive rules (when to reject it)
 
+- A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.
+  - **Disproof:** It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.
+  - **Disproof:** It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed. _(unverified)_
+  - **Disproof:** It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when the response carries no-store or private cache directives, or when the application is fronted only by a per-user browser cache the attacker cannot write to.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
 - A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.
   - **Disproof:** Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
@@ -63,6 +99,12 @@
   - **Disproof:** If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 
+## Defence bypasses
+
+- When an application trusts X-Forwarded-Host or equivalent proxy headers to build absolute URLs, the control that must exist is a list of hops whose forwarding headers are honoured, and the bypass is sending that header directly from outside that list and getting it reflected.
+  - **Disproof:** It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy header from a connection whose peer address is inside the trusted hop list; if the header is unconditionally trusted from any source, the allowlist control is absent entirely.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
+
 ## Chaining opportunities
 
 - When a password-reset email builds its absolute link from a Host value the framework resolves from an override header, poisoning that header during a victim's reset request produces an attacker-received reset token and full account takeover from a single unauthenticated request.
```

## 2026-10-03 01:46 — 100 diff lines
- items: 24 (supported 16), FP rules 4, chains 1, state mature

```diff
--- host_header@current
+++ host_header@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 644 · OWASP A05:2021
-> evidence: 23 items, 16 supported, 4 FP rules, 1 chains
+> evidence: 24 items, 16 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 The server builds a security-relevant URL or decision from a caller-controlled Host header.
@@ -28,44 +28,47 @@
 
 - Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting a vulnerability in Vault could give an attacker full access to a wide range of ".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 - Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Before diving into the technical details of the vulnerabilities, the next section gives an".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 - Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Authenticating to Vault Interfacing with Vault requires authentication and Vault supports ".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 - If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authentication succeeds, Vault returns a short-lived API token for the dbclient role ba".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 - Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 . _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different au".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
 - The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM in".
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response. _(unverified)_
+  - **Disproof:** None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
+- On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.
+  - **Disproof:** None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
+  - Sources: <https://portswigger.net/web-security/host-header/exploiting> · <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
 - When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.
   - **Disproof:** The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
 ## Tests
 
-- To decide this case, observe: you will often come across seemingly vulnerable behavior that isn't directly exploitable, such as the Host header being reflected in the response markup without HTML-encoding or used directly in script imports; there is no way for an attacker to force a victim's browser to issue an incorrect host in a useful manner. The reflection is therefore not a payload delivery mechanism.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.reflected_host_without_a_cache_is_not_a_client_exploitable_finding) states the full boundary.
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
-- To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to sta
+- To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour) states the full boundary.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls. How to apply it in the fi
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
+- To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- To decide this case, observe: ation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demon
+  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- To decide this case, observe: Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite) states the full boundary.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not a bypass when the edge proxy strips or overwrites client-supplied X-Forwarded-Host before it reaches the application, or when the application only reads the proxy h
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist) states the full boundary.
   - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
 
@@ -73,19 +76,19 @@
 
 - The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.
   - **Disproof:** If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
 
 ## False-positive rules (when to reject it)
 
 - A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.
   - **Disproof:** It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
 - An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.
   - **Disproof:** It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
 - Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed. _(unverified)_
   - **Disproof:** It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when the response carries no-store or private cache directives, or when the application is fronted only by a per-user browser cache the attacker cannot write to.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_proxy_module.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+  - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
 - A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.
   - **Disproof:** Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
```

## 2026-10-04 00:43 — 154 diff lines
- items: 24 (supported 16), FP rules 4, chains 1, state mature

```diff
--- host_header@current
+++ host_header@new
@@ -20,99 +20,111 @@
 
 ## Prerequisites (do not start without these)
 
-- Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.
+- Host-header injection requires the application to derive an absolute URL, link, or cache key from the request Host field, which may differ from the connection's host or port.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the application never reflects the Host value into any response body, header or outbound link, a forged Host produces no observable difference and the prerequisite fails.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://snyk.io/blog/how-to-avoid-web-cache-poisoning-attacks/>
 
 ## Techniques (what to change)
 
-- Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure. _(unverified)_
+- Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Authenticating to Vault Interfacing with Vault requires authentication and Vault supports ".
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+- Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Before diving into the technical details of the vulnerabilities, the next section gives an".
+  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
+- Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting a vulnerability in Vault could give an attacker full access to a wide range of ".
   - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Before diving into the technical details of the vulnerabilities, the next section gives an".
-  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Authenticating to Vault Interfacing with Vault requires authentication and Vault supports ".
-  - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function. _(unverified)_
+- If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authentication succeeds, Vault returns a short-lived API token for the dbclient role ba".
   - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 . _(unverified)_
+- Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different au".
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
-- The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result. _(unverified)_
+- On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
+  - Sources: <https://portswigger.net/web-security/host-header/exploiting> · <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
+- The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM in".
   - Sources: <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response. _(unverified)_
-  - **Disproof:** None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
-  - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
-- On any AEM instance the /api.json path is worth poisoning with Host, X-Forwarded-Server and X-Forwarded-Host (or a localhost Host value) to see whether an attacker-controlled host value ends up in a cached response.
-  - **Disproof:** None of those headers is reflected into the response body or stored in a cache entry, and cache keys vary so no poisoned value is ever served to another user.
-  - Sources: <https://portswigger.net/web-security/host-header/exploiting> · <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://kathan19.gitbook.io/howtohunt/host-header-attack/host-header.md>
-- When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.
+- When a front-end injects X-Forwarded-Host to preserve the original host through a load balancer, an attacker can inject the payload through that header and bypass validation applied to Host, because the framework resolves the override header instead of the validated one.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and the override header is inert, if the response is byte-identical to the clean baseline with the override present, meaning the framework ignored it; the only change is in a header or body region no browser or downstream consumer uses to make a security decision; or the deployment genuinely terminates at a proxy that strips every override header before the framework sees it, which must be shown by observing that the attacker value never reaches any application-controlled output. Validate by diffing, not by the presence of the header in the request.
   - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
 ## Tests
 
-- To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist) states the full boundary.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.
+  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+- To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
-- To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.
+- To decide this case, observe: Mechanism: An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.an_absolute_url_in_a_response_body_alone_is_not_an_open_redirect) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- To decide this case, observe: Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.
+- To decide this case, observe: Mechanism: The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.validation.prove_host_injection_with_a_password_reset_url_rewrite) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.bypass.x_forwarded_host_trusted_without_a_known_proxy_allowlist) states the full boundary.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
 
 ## Validation bar (how to prove it)
 
-- The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.
+- The convincing host-header validation is a request/response pair where a reset or confirmation email is requested while sending a foreign Host, and the response body contains an absolute link or token-bearing URL pointing at the attacker's domain rather than the legitimate one.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the emitted URL always uses a server-side configured canonical domain regardless of the Host sent, the pair fails and the injection does not exist; if the endpoint is unauthenticated but the URL is still server-derived, this is not host-header injection at all.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
 
 ## False-positive rules (when to reject it)
 
-- A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.
+- A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
+- A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
+  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
+- A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS exploitable when the response body, Location header, or any absolute link differs between a legitimate host and an attacker-controlled host; it is a non-finding when every host value yields byte-identical status, headers and body, because a 200 on an unknown vhost is normal virtual-host routing behaviour.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
-- An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.
+- An attacker-controlled hostname appearing inside an absolute URL in a response body is not an open redirect, because the user must still act on a link whose destination is chosen by the application; the class is open redirect only when the server itself issues a 3xx whose Location the attacker controls.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS an open redirect when a request parameter or header is reflected into the Location header of a 302 or 301 and the browser follows it off-site; it is not when the host appears only in body content the client renders as text, in which case the correct finding is host-header injection or content injection rather than redirection.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
-- Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed. _(unverified)_
+- Calling a reflected host value 'web cache poisoning' overstates it unless a caching layer actually keys on that host value, so the report must show a cache in front or a backend that caches by the supplied host before the class can be claimed.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** It IS cache poisoning when a shared cache keys responses on the attacker-supplied host or absolute URL and later serves that poisoned entry to other visitors; it is NOT when the response carries no-store or private cache directives, or when the application is fronted only by a per-user browser cache the attacker cannot write to.
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://www.rfc-editor.org/rfc/rfc9110.html>
-- A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.
-  - **Disproof:** Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>
-- A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.
-  - **Disproof:** The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
 
 ## Impact framing
 
-- When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.
+- When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.  _(merged 1 duplicate row(s))_
... (truncated)
```

## 2026-10-04 00:50 — 15 diff lines
- items: 24 (supported 16), FP rules 4, chains 1, state mature

```diff
--- host_header@current
+++ host_header@new
@@ -114,10 +114,8 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Send a request with Host: your-collaborator-domain and check whether the response, a password-reset link or a cached page reflects it.
+2. Test both the Host header and X-Forwarded-Host / X-Forwarded-For, and confirm which proxy headers the edge actually trusts.
 
 ### What counts as proof
 
```

## 2026-10-04 13:20 — 11 diff lines
- items: 24 (supported 16), FP rules 4, chains 1, state mature

```diff
--- host_header@current
+++ host_header@new
@@ -58,7 +58,7 @@
   - Sources: <https://httpd.apache.org/docs/2.4/mod/core.html> · <https://nginx.org/en/docs/http/ngx_http_realip_module.html>
 - To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.host_header_poisoning_requires_a_shared_cache_or_specific_backend_condition) states the full boundary.
-  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.rfc-editor.org/rfc/rfc9110.html>
+  - Sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://nginx.org/en/docs/http/ngx_http_proxy_module.html>
 - To decide this case, observe: Mechanism: A server returning 200 for an arbitrary Host header is not by itself a vulnerability; the finding survives only when the unrecognised host changes the response content, produces a redirect, an absolute URL to an attacker domain, or a password-reset link built from the host.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (host_header.fp_rule.accepting_an_arbitrary_host_header_is_only_a_defect_when_it_changes_behaviour) states the full boundary.
   - Sources: <https://www.rfc-editor.org/rfc/rfc9110.html> · <https://httpd.apache.org/docs/2.4/mod/core.html>
```
