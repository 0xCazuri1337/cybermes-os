# Information Disclosure

> surface: `web` · CWE: 200 · OWASP: A01:2021
> maturity: **researching** — 14 items, 14 supported, 1 FP rules, 2 chains

Error output, directory listings or metadata reveal more about the system than the caller should learn.

**Aliases:** info disclosure, information exposure, verbose errors, debug exposure, secrets exposure

## Prerequisite

- **In an Active Directory environment a non-privileged domain user can enumerate the domain forest, domain controllers, group membership and domain trust relationships, and that enumeration is the prerequisite for kerberoasting and ACL abuse rather than an end in itself.**  
  `high_confidence` · score 0.89 · disproved by: If the same enumeration queries fail for a standard domain user and only succeed with an explicit administrative credential or a host-specific privilege, then low-privilege enumeration is not available in that domain and this prerequisite does not hold.
  sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md>
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
- **A bare Unix epoch timestamp in an otherwise generic response is an information disclosure only when it can be aggregated across responses to expose an exploitable pattern, making aggregation the deciding test rather than presence.**  
  `high_confidence` · score 0.8415 · disproved by: If each response carries a timestamp derived only from the moment of the request, or no second timestamp from the same source exists to correlate against, then there is nothing to aggregate and the disclosure does not materialise.
  sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.zaproxy.org/docs/alerts/10096/>

## Technique

- **A production ASP.NET application with the trace viewer reachable without root authentication discloses the physical webroot path, the last 80 requested files and the credentials of recent logins in plaintext.**  
  `high_confidence` · score 0.9265 · disproved by: If the trace feature is disabled in the production build or the handler requires the server's root authentication, or request-body logging redacts credential fields, then no other user's plaintext credentials are recoverable.
  sources: <https://www.zaproxy.org/docs/alerts/10095/> · <https://checkmarx.com/blog/ericsson-sensitive-data-exposure-via-trace-axd/>
- **Any application on an EC2 instance can read instance metadata including IAM role credentials from the link-local address 169.254.169.254, and EKS pods by default can reach the worker node's metadata the same way.**  
  `high_confidence` · score 0.915 · disproved by: If the instance enforces IMDSv2 so a session token must be obtained by PUT before any read is honoured, and the token hop limit is left at default so intermediate proxies do not forward it, then a blind SSRF cannot retrieve credentials.
  sources: <https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/> · <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/eks-pods-can-steal-host-credentials/> · <https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/>
- **A GraphQL API with introspection enabled in production discloses the types and operations the endpoint supports, including operations reserved for high-privilege users, and an undocumented endpoint absent from the gateway route table discloses by existing at all.**  
  `high_confidence` · score 0.8875 · disproved by: If introspection is disabled or restricted to authenticated administrators in production, or the deployment enforces field-level authorisation inside the resolver rather than at the gateway, then the schema reveals no operation the caller could not already reach by name.
  sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>

## Validation

- **An information disclosure is confirmed by comparing the same request sent unauthenticated and with a valid session and by differencing responses across object identifiers: if a field the unauthenticated caller should not influence differs, the response content is the disclosure.**  
  `high_confidence` · score 1.0 · disproved by: If the unauthenticated and authenticated responses are byte-identical, or the only difference is a session cookie or CSRF token carrying no server-side data, then no information crossed the authorisation boundary and there is no disclosure to validate.
  sources: <https://capec.mitre.org/data/definitions/118.html> · <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-acl/> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
- **A low-entropy disclosure such as a timestamp, build identifier or repeated internal hostname is promoted from finding to vulnerability only when values collected across multiple responses or hosts aggregate into a pattern that narrows an attacker's search space.**  
  `high_confidence` · score 0.8415 · disproved by: If each collected value is unique per request and no cross-response or cross-host relationship exists, then no aggregation is possible and the disclosure remains noise regardless of how many instances were sampled.
  sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.zaproxy.org/docs/alerts/10096/>

## Fp Rule

- **Coordinated scraping of a platform's public API surface, including public repositories, gists, followers and org memberships, all returning HTTP 200 with no failed-auth signal, is the platform working as designed and is a false positive for information disclosure unless the activity is shown to have crossed into private data.**  
  `high_confidence` · score 0.899 · disproved by: If the activity is shown to have successfully cloned private repositories or used a compromised token to read non-public objects, then it crossed the design boundary and the finding is a real disclosure rather than a false positive.
  sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>

## Impact

- **Where exposure measurement reports that more than 80 percent of OT control, power monitoring and IoT systems communicate over legacy insecure protocols such as BACnet and MODBUS, the disclosed asset and protocol inventory is what makes physical disruption a reachable outcome rather than a theoretical one.**  
  `high_confidence` · score 0.89 · disproved by: If the disclosed inventory cannot be reached from the adversary's compromised asset, or the OT segment is segmented such that no path exists from IT to the affected devices, then the disclosure informs attack planning without enabling physical impact.
  sources: <https://capec.mitre.org/data/definitions/158.html> · <https://www.claroty.com/blog/data-center-exposures-and-the-pathways-putting-data-center-assets-at-risk> · <https://www.claroty.com/blog/cyberattack-on-norwegian-dam-highlights-password-exposure-risks>

## Bypass

- **An attacker bypasses attribution of cloud enumeration by querying a service-linked-role-backed resource index rather than calling resource APIs directly, because the resulting requests are logged against the AWS service role and not against the compromised identity.**  
  `high_confidence` · score 0.899 · disproved by: If the account already logs resource-explorer-2 as a management event, or the enumeration is performed with the compromised key directly rather than through the service role's index, then the requests remain attributable to the identity and the laundering bypass does not apply.
  sources: <https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/> · <https://unit42.paloaltonetworks.com/exposed-services-public-clouds/>

## Chain Link

- **Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack them offline without triggering account lockout.**  
  `high_confidence` · score 0.945 · disproved by: If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.
  sources: <https://capec.mitre.org/data/definitions/191.html> · <https://capec.mitre.org/data/definitions/497.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md>

## Related classes (via chains)

- `sqli` SQL Injection (3 chains)
- `lateral_movement` Lateral Movement (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `ad_enumeration` Active Directory Enumeration (1 chains)

## Known gaps

Not yet satisfied: `fp_rules`
