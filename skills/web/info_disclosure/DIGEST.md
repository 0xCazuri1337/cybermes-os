<!-- GENERATED from db/wks.db — do not edit -->
# Information Disclosure

> surface: `web` · CWE: 200 · OWASP: A01:2021
> maturity: **mature** — 24 items, 13 supported, 5 FP rules, 2 chains

Error output, directory listings or metadata reveal more about the system than the caller should learn.

**Aliases:** info disclosure, information exposure, verbose errors, debug exposure, secrets exposure

## Prerequisite

- **An internet-exposed SSH, SMB, RDP or Postgres service is discovered and compromised within minutes of exposure, so the exposure-to-compromise window is bounded by minutes rather than by the patch cycle.**  
  `high_confidence` · score 0.874 · disproved by: If the exposed service is reachable only from inside a segmented trust boundary, or sits behind an authenticated gateway that rejects anonymous and weak-credential connections, then the minutes-scale compromise window does not apply.
  sources: <https://capec.mitre.org/data/definitions/118.html> · <https://unit42.paloaltonetworks.com/exposed-services-public-clouds/>

## Signal

- **A response header naming a specific framework version such as X-AspNet-Version is a passive-signal information disclosure because it lets an attacker select a matching public exploit without further probing.**  
  `high_confidence` · score 0.8965 · disproved by: If the header carries a pinned non-version value with no build number, or a gateway strips the field before it reaches the client, then no version oracle exists for the attacker.
  sources: <https://capec.mitre.org/data/definitions/497.html> · <https://www.zaproxy.org/docs/alerts/10061/>
- **An AWS account where resource-explorer-2:ListResources is called from a long-lived access key before July 2025 was a cloud information disclosure with no CloudTrail record, because the call was classified as a data event logging only if the customer enabled data-event logging.**  
  `high_confidence` · score 0.874 · disproved by: If the account already records resource-explorer-2 as a management event, or the calls originate from an ephemeral role session rather than a long-lived access key, then the enumeration leaves a log and the silence is genuine rather than structural.
  sources: <https://capec.mitre.org/data/definitions/118.html> · <https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/>
- **Directory listings and crawler files expose hidden resources and structure.**  
  `high_confidence` · score 0.7425 · disproved by: Refuted if the exposure vector is removed: generic error responses, disabled directory listing, non-URL session exchange, allowlisted Host for password resets, excluded backup/.git files, no hardcoded secrets, sanitized version banners and patched frameworks.
  sources: <https://portswigger.net/web-security/information-disclosure> · <https://portswigger.net/web-security/information-disclosure/exploiting> · <https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/index.html>

## Technique

- **Any application on an EC2 instance can read instance metadata including IAM role credentials from the link-local address 169.254.169.254, and EKS pods by default can reach the worker node's metadata the same way.**  
  `high_confidence` · score 0.915 · disproved by: If the instance enforces IMDSv2 so a session token must be obtained by PUT before any read is honoured, and the token hop limit is left at default so intermediate proxies do not forward it, then a blind SSRF cannot retrieve credentials.
  sources: <https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/> · <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/eks-pods-can-steal-host-credentials/> · <https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/>
- **Client-side disclosure is mined from shipped JavaScript, which routinely exposes API base URLs, internal hostnames, and commented-out credentials absent from the HTML.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when the shipped bundle contains no internal hostname, key, or credential and every reference is a public endpoint already visible in the HTML.
  sources: <https://cwe.mitre.org/data/definitions/200.html> · <https://portswigger.net/web-security/information-disclosure> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/01.%20Pre-Engagement/07.%20JavaScript%20Deobfuscation/JavaScript%20Deobfuscation.md>

## Validation

- **An information disclosure is confirmed by comparing the same request sent unauthenticated and with a valid session and by differencing responses across object identifiers: if a field the unauthenticated caller should not influence differs, the response content is the disclosure.**  
  `high_confidence` · score 0.954 · disproved by: If the unauthenticated and authenticated responses are byte-identical, or the only difference is a session cookie or CSRF token carrying no server-side data, then no information crossed the authorisation boundary and there is no disclosure to validate.
  sources: <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-acl/> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>

## Fp Rule

- **Coordinated scraping of a platform's public API surface, including public repositories, gists, followers and org memberships, all returning HTTP 200 with no failed-auth signal, is the platform working as designed and is a false positive for information disclosure unless the activity is shown to have crossed into private data.**  
  `high_confidence` · score 0.899 · disproved by: If the activity is shown to have successfully cloned private repositories or used a compromised token to read non-public objects, then it crossed the design boundary and the finding is a real disclosure rather than a false positive.
  sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>

## Evidence

- **Verbose error messages and stack traces disclose sensitive internals.**  
  `high_confidence` · score 0.8815 · disproved by: Refuted if the exposure vector is removed: generic error responses, disabled directory listing, non-URL session exchange, allowlisted Host for password resets, excluded backup/.git files, no hardcoded secrets, sanitized version banners and patched frameworks.
  sources: <https://cwe.mitre.org/data/definitions/200.html> · <https://portswigger.net/web-security/information-disclosure> · <https://blog.certcube.com/information-disclosure-guide/>
- **Version disclosure chains to CVE exploitation.**  
  `high_confidence` · score 0.842 · disproved by: Refuted if the exposure vector is removed: generic error responses, disabled directory listing, non-URL session exchange, allowlisted Host for password resets, excluded backup/.git files, no hardcoded secrets, sanitized version banners and patched frameworks.
  sources: <https://portswigger.net/web-security/information-disclosure> · <https://portswigger.net/web-security/information-disclosure/exploiting/lab-infoleak-in-error-messages> · <https://www.tenable.com/cve/CVE-2017-5638>
- **Hard-coded secrets, API keys, and credentials in source code.**  
  `high_confidence` · score 0.7375 · disproved by: Refuted if the exposure vector is removed: generic error responses, disabled directory listing, non-URL session exchange, allowlisted Host for password resets, excluded backup/.git files, no hardcoded secrets, sanitized version banners and patched frameworks.
  sources: <https://blog.certcube.com/information-disclosure-guide/> · <https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-information-disclosure-vulnerabilities>

## Impact

- **Where exposure measurement reports that more than 80 percent of OT control, power monitoring and IoT systems communicate over legacy insecure protocols such as BACnet and MODBUS, the disclosed asset and protocol inventory is what makes physical disruption a reachable outcome rather than a theoretical one.**  
  `high_confidence` · score 0.89 · disproved by: If the disclosed inventory cannot be reached from the adversary's compromised asset, or the OT segment is segmented such that no path exists from IT to the affected devices, then the disclosure informs attack planning without enabling physical impact.
  sources: <https://capec.mitre.org/data/definitions/158.html> · <https://www.claroty.com/blog/data-center-exposures-and-the-pathways-putting-data-center-assets-at-risk> · <https://www.claroty.com/blog/cyberattack-on-norwegian-dam-highlights-password-exposure-risks>

## Bypass

- **An attacker bypasses attribution of cloud enumeration by querying a service-linked-role-backed resource index rather than calling resource APIs directly, because the resulting requests are logged against the AWS service role and not against the compromised identity.**  
  `high_confidence` · score 0.899 · disproved by: If the account already logs resource-explorer-2 as a management event, or the enumeration is performed with the compromised key directly rather than through the service role's index, then the requests remain attributable to the identity and the laundering bypass does not apply.
  sources: <https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/> · <https://unit42.paloaltonetworks.com/exposed-services-public-clouds/>

## False-positive rules

- **Hypothesis:** JavaScript source maps are fetchable unauthenticated and expose the unminified application, therefore this is sensitive information disclosure
  - **Invalidated by:** Zero hits across roughly a megabyte of sourcesContent. The single token-like literal was a public SDK application id already present in the served bundle, and one map was vendor boilerplate. The maps are live and genuinely reveal structure, but they contain nothing sensitive
  - **Rule:** Source maps being served is a hardening gap. It becomes a sensitive disclosure only when the sourcesContent carries credentials, keys, PII or internal endpoints. Scan the extracted sources for those patterns and report the count; zero hits means the finding reduces to unminified code, which most programmes explicitly exclude

- **Hypothesis:** A path discovered in source maps is an internal API contract, therefore the application exposes undocumented internal endpoints
  - **Invalidated by:** The paths appear only as page-route constants or as placeholder field values inside a public documentation example; neither is a reachable server endpoint. The 'internal contract' framing did not survive the check
  - **Rule:** Before reporting an endpoint discovered in source or docs, prove the client issues a request to it. A string that is only a page-route constant, or an example value inside a public docs example, is not an exposed endpoint

- **Hypothesis:** An admin information endpoint discloses project configuration including a registration flag, therefore the deployment is misconfigured
  - **Invalidated by:** Collections and users returned forbidden, schema introspection was disabled, and authentication rejected the credentials. The disclosed flag described a configuration that was in fact enforced, and the version was not disclosed so no known vulnerability maps to it
  - **Rule:** A config endpoint that reports a hardening flag is not a finding when the endpoints that flag protects actually enforce it. Enumerate the protected surface before reporting the disclosure; if it is all forbidden or disabled, the disclosure documents a working control

- **Hypothesis:** The application lacks HSTS, therefore it is vulnerable to downgrade attacks
  - **Invalidated by:** HSTS is present on all the real application and API paths; only the root redirect lacks it, and that response is a redirect rather than content. Session cookies on the media host carried HttpOnly, SameSite and Secure
  - **Rule:** Measure a security header on the paths that actually serve content and set session state, not on a root redirect. HSTS absent only from the redirect while present on every real path is cosmetic

## Related classes (via chains)

- `sqli` SQL Injection (3 chains)
- `lateral_movement` Lateral Movement (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `ad_enumeration` Active Directory Enumeration (1 chains)
