# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 15 (supported 15), FP rules 2, chains 2, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 15 (supported 15), FP rules 2, chains 2, state mature

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -95,4 +95,4 @@
 - `ad_enumeration` (1 shared chain(s))
 
 ---
-Full class document: `domains/web/info_disclosure/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id info_disclosure`
+Full class document: `domains/web/info_disclosure/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id info_disclosure`
```

## 2026-10-02 19:37 — 63 diff lines
- items: 15 (supported 14), FP rules 2, chains 2, state mature

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 200 · OWASP A01:2021
-> evidence: 15 items, 15 supported, 2 FP rules, 2 chains
+> evidence: 15 items, 14 supported, 2 FP rules, 2 chains
 > maturity: **mature**
 
 Error output, directory listings or metadata reveal more about the system than the caller should learn.
@@ -20,9 +20,6 @@
 
 ## Prerequisites (do not start without these)
 
-- In an Active Directory environment a non-privileged domain user can enumerate the domain forest, domain controllers, group membership and domain trust relationships, and that enumeration is the prerequisite for kerberoasting and ACL abuse rather than an end in itself.
-  - **Disproof:** If the same enumeration queries fail for a standard domain user and only succeed with an explicit administrative credential or a host-specific privilege, then low-privilege enumeration is not available in that domain and this prerequisite does not hold.
-  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md>
 - An internet-exposed SSH, SMB, RDP or Postgres service is discovered and compromised within minutes of exposure, so the exposure-to-compromise window is bounded by minutes rather than by the patch cycle.
   - **Disproof:** If the exposed service is reachable only from inside a segmented trust boundary, or sits behind an authenticated gateway that rejects anonymous and weak-credential connections, then the minutes-scale compromise window does not apply.
   - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://unit42.paloaltonetworks.com/exposed-services-public-clouds/>
@@ -41,15 +38,24 @@
 
 ## Techniques (what to change)
 
-- A GraphQL API with introspection enabled in production discloses the types and operations the endpoint supports, including operations reserved for high-privilege users, and an undocumented endpoint absent from the gateway route table discloses by existing at all.
-  - **Disproof:** If introspection is disabled or restricted to authenticated administrators in production, or the deployment enforces field-level authorisation inside the resolver rather than at the gateway, then the schema reveals no operation the caller could not already reach by name.
-  - Sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>
 - Any application on an EC2 instance can read instance metadata including IAM role credentials from the link-local address 169.254.169.254, and EKS pods by default can reach the worker node's metadata the same way.
   - **Disproof:** If the instance enforces IMDSv2 so a session token must be obtained by PUT before any read is honoured, and the token hop limit is left at default so intermediate proxies do not forward it, then a blind SSRF cannot retrieve credentials.
   - Sources: <https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/> · <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/eks-pods-can-steal-host-credentials/> · <https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/>
-- A production ASP.NET application with the trace viewer reachable without root authentication discloses the physical webroot path, the last 80 requested files and the credentials of recent logins in plaintext.
+- A production ASP.NET application with the trace viewer reachable without root authentication discloses the physical webroot path, the last 80 requested files and the credentials of recent logins in plaintext. _(unverified)_
   - **Disproof:** If the trace feature is disabled in the production build or the handler requires the server's root authentication, or request-body logging redacts credential fields, then no other user's plaintext credentials are recoverable.
   - Sources: <https://www.zaproxy.org/docs/alerts/10095/> · <https://checkmarx.com/blog/ericsson-sensitive-data-exposure-via-trace-axd/>
+
+## Tests
+
+- To decide this case, observe: m many responses and hosts, then ask two questions: is the value space small, and is the pattern stable across samples. Only when both are true does the item clear the bar, and the write-up should carry the collected series as evidence rather than the single instance that triggered it.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (info_disclosure.validation.aggregate_to_exploitable_pattern) states the full boundary.
+  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.zaproxy.org/docs/alerts/10096/>
+- To decide this case, observe: ut to the object under test. Vary one dimension per pair, hold the rest fixed, and record the baseline so later changes can be distinguished from output that was always there.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (info_disclosure.validation.differential_response_comparison) states the full boundary.
+  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
+- To decide this case, observe: GraphQL queries against public objects all return data. Because these paths are public by design, requests produce HTTP 200 responses and generate no failed-auth signal, and an operator can build a detailed map of an organization, such as its public repositories, its members, who those members follow, and which projects they touch, entirely from public data. The traffic blends
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (info_disclosure.fp_rule.public_scraping_without_privilege_crossing) states the full boundary.
+  - Sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>
 
 ## Validation bar (how to prove it)
 
@@ -81,12 +87,6 @@
   - **Disproof:** If the account already logs resource-explorer-2 as a management event, or the enumeration is performed with the compromised key directly rather than through the service role's index, then the requests remain attributable to the identity and the laundering bypass does not apply.
   - Sources: <https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/> · <https://unit42.paloaltonetworks.com/exposed-services-public-clouds/>
 
-## Chaining opportunities
-
-- Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack them offline without triggering account lockout.
-  - **Disproof:** If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.
-  - Sources: <https://capec.mitre.org/data/definitions/191.html> · <https://capec.mitre.org/data/definitions/497.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md>
-
 ## Chains to
 
 - `sqli` (3 shared chain(s))
```

## 2026-10-03 01:46 — 72 diff lines
- items: 18 (supported 15), FP rules 2, chains 2, state mature

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 200 · OWASP A01:2021
-> evidence: 15 items, 14 supported, 2 FP rules, 2 chains
+> evidence: 18 items, 15 supported, 2 FP rules, 2 chains
 > maturity: **mature**
 
 Error output, directory listings or metadata reveal more about the system than the caller should learn.
@@ -38,6 +38,9 @@
 
 ## Techniques (what to change)
 
+- Client-side disclosure is mined from shipped JavaScript, which routinely exposes API base URLs, internal hostnames, and commented-out credentials absent from the HTML.
+  - **Disproof:** Refuted when the shipped bundle contains no internal hostname, key, or credential and every reference is a public endpoint already visible in the HTML.
+  - Sources: <https://cwe.mitre.org/data/definitions/200.html> · <https://portswigger.net/web-security/information-disclosure> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/01.%20Pre-Engagement/07.%20JavaScript%20Deobfuscation/JavaScript%20Deobfuscation.md>
 - Any application on an EC2 instance can read instance metadata including IAM role credentials from the link-local address 169.254.169.254, and EKS pods by default can reach the worker node's metadata the same way.
   - **Disproof:** If the instance enforces IMDSv2 so a session token must be obtained by PUT before any read is honoured, and the token hop limit is left at default so intermediate proxies do not forward it, then a blind SSRF cannot retrieve credentials.
   - Sources: <https://securitylabs.datadoghq.com/articles/misconfiguration-spotlight-imds/> · <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/eks-pods-can-steal-host-credentials/> · <https://unit42.paloaltonetworks.com/compromised-cloud-compute-credentials/>
@@ -47,15 +50,12 @@
 
 ## Tests
 
-- To decide this case, observe: m many responses and hosts, then ask two questions: is the value space small, and is the pattern stable across samples. Only when both are true does the item clear the bar, and the write-up should carry the collected series as evidence rather than the single instance that triggered it.
+- To decide this case, observe: The validation procedure is to sample the same field from many responses and hosts, then ask two questions: is the value space small, and is the pattern stable across samples.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (info_disclosure.validation.aggregate_to_exploitable_pattern) states the full boundary.
   - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.zaproxy.org/docs/alerts/10096/>
-- To decide this case, observe: ut to the object under test. Vary one dimension per pair, hold the rest fixed, and record the baseline so later changes can be distinguished from output that was always there.
+- To decide this case, observe: The trap is diffing against an unrelated endpoint: two pages on the same application share headers, so a naive comparison attributes ordinary template output to the object under test.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (info_disclosure.validation.differential_response_comparison) states the full boundary.
   - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
-- To decide this case, observe: GraphQL queries against public objects all return data. Because these paths are public by design, requests produce HTTP 200 responses and generate no failed-auth signal, and an operator can build a detailed map of an organization, such as its public repositories, its members, who those members follow, and which projects they touch, entirely from public data. The traffic blends
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (info_disclosure.fp_rule.public_scraping_without_privilege_crossing) states the full boundary.
-  - Sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>
 
 ## Validation bar (how to prove it)
 
@@ -64,7 +64,7 @@
   - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://www.zaproxy.org/docs/alerts/10096/>
 - An information disclosure is confirmed by comparing the same request sent unauthenticated and with a valid session and by differencing responses across object identifiers: if a field the unauthenticated caller should not influence differs, the response content is the disclosure.
   - **Disproof:** If the unauthenticated and authenticated responses are byte-identical, or the only difference is a session cookie or CSRF token carrying no server-side data, then no information crossed the authorisation boundary and there is no disclosure to validate.
-  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-acl/> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
+  - Sources: <https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/s3-bucket-public-acl/> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
 
 ## False-positive rules (when to reject it)
 
@@ -75,11 +75,23 @@
   - **Disproof:** If the activity is shown to have successfully cloned private repositories or used a compromised token to read non-public objects, then it crossed the design boundary and the finding is a real disclosure rather than a false positive.
   - Sources: <https://securitylabs.datadoghq.com/articles/coordinated-github-api-enumeration/> · <https://checkmarx.com/blog/move-over-verbose-error-messages-graphql-apis-are-here/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: Identical responses mean no session-dependent disclosure.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (info_disclosure.validation.differential_response_comparison) states the full boundary.
+  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack... _(unverified)_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (info_disclosure.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://checkmarx.com/blog/api-security-exposed-api-endpoint-leaks-over-11-million-telco-customers-data/>
+
 ## Impact framing
 
 - Where exposure measurement reports that more than 80 percent of OT control, power monitoring and IoT systems communicate over legacy insecure protocols such as BACnet and MODBUS, the disclosed asset and protocol inventory is what makes physical disruption a reachable outcome rather than a theoretical one.
   - **Disproof:** If the disclosed inventory cannot be reached from the adversary's compromised asset, or the OT segment is segmented such that no path exists from IT to the affected devices, then the disclosure informs attack planning without enabling physical impact.
   - Sources: <https://capec.mitre.org/data/definitions/158.html> · <https://www.claroty.com/blog/data-center-exposures-and-the-pathways-putting-data-center-assets-at-risk> · <https://www.claroty.com/blog/cyberattack-on-norwegian-dam-highlights-password-exposure-risks>
+- An endpoint surfaced by web page source review is a triage lead whose severity depends on what that endpoint exposes, ranging from an authentication bypass to a sensitive information leak. _(unverified)_
+  - **Disproof:** The endpoint turns out to be unreachable or fully authorized and exposes neither sensitive data nor an authentication decision.
+  - Sources: <https://capec.mitre.org/data/definitions/118.html> · <https://kathan19.gitbook.io/howtohunt/web-page-source-code-review/codereviewtips.md>
 
 ## Defence bypasses
 
```

## 2026-10-03 05:00 — 33 diff lines
- items: 18 (supported 15), FP rules 6, chains 2, state mature

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 200 · OWASP A01:2021
-> evidence: 18 items, 15 supported, 2 FP rules, 2 chains
+> evidence: 18 items, 15 supported, 6 FP rules, 2 chains
 > maturity: **mature**
 
 Error output, directory listings or metadata reveal more about the system than the caller should learn.
@@ -99,6 +99,21 @@
   - **Disproof:** If the account already logs resource-explorer-2 as a management event, or the enumeration is performed with the compromised key directly rather than through the service role's index, then the requests remain attributable to the identity and the laundering bypass does not apply.
   - Sources: <https://securitylabs.datadoghq.com/articles/enumerating-aws-the-quiet-way-cloudtrail-free-discovery-with-resource-explorer/> · <https://unit42.paloaltonetworks.com/exposed-services-public-clouds/>
 
+## Rejected before you report
+
+- **JavaScript source maps are fetchable unauthenticated and expose the unminified application, therefore this is sensitive information disclosure**
+  - Killed by: Zero hits across roughly a megabyte of sourcesContent. The single token-like literal was a public SDK application id already present in the served bundle, and one map was vendor boilerplate. The maps are live and genuinely reveal structure, but they contain nothing sensitive
+  - Rule: Source maps being served is a hardening gap. It becomes a sensitive disclosure only when the sourcesContent carries credentials, keys, PII or internal endpoints. Scan the extracted sources for those patterns and report the count; zero hits means the finding reduces to unminified code, which most programmes explicitly exclude
+- **A path discovered in source maps is an internal API contract, therefore the application exposes undocumented internal endpoints**
+  - Killed by: The paths appear only as page-route constants or as placeholder field values inside a public documentation example; neither is a reachable server endpoint. The 'internal contract' framing did not survive the check
+  - Rule: Before reporting an endpoint discovered in source or docs, prove the client issues a request to it. A string that is only a page-route constant, or an example value inside a public docs example, is not an exposed endpoint
+- **An admin information endpoint discloses project configuration including a registration flag, therefore the deployment is misconfigured**
+  - Killed by: Collections and users returned forbidden, schema introspection was disabled, and authentication rejected the credentials. The disclosed flag described a configuration that was in fact enforced, and the version was not disclosed so no known vulnerability maps to it
+  - Rule: A config endpoint that reports a hardening flag is not a finding when the endpoints that flag protects actually enforce it. Enumerate the protected surface before reporting the disclosure; if it is all forbidden or disabled, the disclosure documents a working control
+- **The application lacks HSTS, therefore it is vulnerable to downgrade attacks**
+  - Killed by: HSTS is present on all the real application and API paths; only the root redirect lacks it, and that response is a redirect rather than content. Session cookies on the media host carried HttpOnly, SameSite and Secure
+  - Rule: Measure a security header on the paths that actually serve content and set session state, not on a root redirect. HSTS absent only from the redirect while present on every real path is cosmetic
+
 ## Chains to
 
 - `sqli` (3 shared chain(s))
```
