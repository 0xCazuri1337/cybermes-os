# Host Header Injection

> surface: `web` · CWE: 644 · OWASP: A05:2021
> maturity: **mature** — 12 items, 12 supported, 2 FP rules, 1 chains

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
- **If authentication succeeds, Vault returns a short-lived API token for the dbclient role back to the lambda function.**  
  `high_confidence` · score 0.8545 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If authentication succeeds, Vault returns a short-lived API token for the dbclient role ba".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM information out of the result.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The Vault server sends the pre-signed requests to the STS host and extracts the AWS IAM in".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different authentication mechanisms internally: iam and ec2 .**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Let’s take a look. sts:GetCallerIdentity Vault’s aws auth method supports two different au".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **Exploiting a vulnerability in Vault could give an attacker full access to a wide range of important secrets and large parts of the target's infrastructure.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Exploiting a vulnerability in Vault could give an attacker full access to a wide range of ".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **Before diving into the technical details of the vulnerabilities, the next section gives an overview about Vault’s authentication architecture and the way it integrates with cloud providers.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Before diving into the technical details of the vulnerabilities, the next section gives an".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>
- **Authenticating to Vault Interfacing with Vault requires authentication and Vault supports role-based access control to govern access to stored secrets.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Authenticating to Vault Interfacing with Vault requires authentication and Vault supports ".
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>

## Fp Rule

- **A Host or X-Forwarded-Host value reflected unencoded into the response markup, with no shared cache in front of the page, is not a finding on its own: no attacker can force a victim's browser to send an incorrect host in a useful manner.**  
  `high_confidence` · score 0.93 · disproved by: The rule is wrong, and there is a real finding, if: a shared cache serves the poisoned response to a second, different session (then it is cache poisoning, and cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key is the right class); or the reflected value is consumed server-side, changing an authz decision, a Location header, or a generated absolute URL even in a single-request replay; or the reflection reaches an HTTP response header that the browser treats as navigable (Location, Link, Refresh). Same-request reflection into HTML markup alone never qualifies.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
- **A Host header whose value length exactly equals the server's configured maximum produces a one-byte NULL overwrite in the server's own parser, which is a length-check defect and not host-header routing or cache steering.**  
  `high_confidence` · score 0.9205 · disproved by: Changing only the Host header to another valid hostname changes the response body, an absolute URL, or the cache entry served, which shows the field is being consumed for routing or keying rather than only for length validation.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2023-1746> · <https://www.helpnetsecurity.com/2026/08/31/ai-crawlers-scan-exposed-credentials/>

## Impact

- **When an intermediary routes on the Host header field, an attacker-chosen Host value steers the request to a different backend and yields cross-tenant credential impact.**  
  `high_confidence` · score 0.948 · disproved by: If both Host values return responses from the same backend and any generated absolute URL ignores the supplied Host, the routing trust boundary does not exist and there is no host_header impact to report.
  sources: <https://httpwg.org/specs/rfc9110.html> · <https://googleprojectzero.blogspot.com/2020/10/enter-the-vault-auth-issues-hashicorp-vault.html>

## Chain Link

- **When a password-reset email builds its absolute link from a Host value the framework resolves from an override header, poisoning that header during a victim's reset request produces an attacker-received reset token and full account takeover from a single unauthenticated request.**  
  `high_confidence` · score 0.9025 · disproved by: The chain is refuted if: the reset link is built from a server-side configured base URL or a canonical host allowlist that ignores both Host and the override headers, so the emitted link never leaves the legitimate domain; the reset token is delivered only to the account's registered mailbox and the link host is fixed regardless of the request, which removes the attacker's receiver entirely; or the reset token is single-use, short-lived, and invalidated on any parameter change, so a captured link cannot be redeemed. Emit the actual reset email and inspect the link host; do not infer from the request alone.
  sources: <https://academy.hackthebox.com/course/preview/abusing-http-misconfigurations> · <https://portswigger.net/web-security/host-header/exploiting>
