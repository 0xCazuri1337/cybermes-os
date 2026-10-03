# Active Directory Enumeration

> surface: `ad` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 22 items, 22 supported, 2 FP rules, 1 chains

Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.

**Aliases:** ad enumeration, domain enumeration, ldap enumeration of ad, cldap, trust enumeration, domain trust enumeration

## Prerequisite

- **Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.**  
  `high_confidence` · score 0.929 · disproved by: The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625> · <https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/>

## Signal

- **An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.**  
  `high_confidence` · score 0.863 · disproved by: If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.**  
  `high_confidence` · score 0.8615 · disproved by: If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>
- **While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **We will cover how to identify, exploit, and prevent each of these injection attacks.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **We will discuss how to identify, exploit, and prevent each vulnerability.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>

## Validation

- **Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating whether an environment would actually detect reconnaissance.**  
  `high_confidence` · score 0.8105 · disproved by: If the decoy accounts receive no alerts during a controlled adversary-emulation run while events 4625/4768/4769/4771 are confirmed present in the log pipeline, the validation premise fails.
  sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Fp Rule

- **AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool is living-off-the-land tradecraft, not a distinct vulnerability; do not file the absence of a command-line alert as a control failure, because the same module an administrator uses for routine domain queries is the one an attacker reuses.**  
  `high_confidence` · score 0.8715 · disproved by: The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.
  sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **Reject a ad_enumeration finding until it is distinguished from the adjacent behaviour this class also covers. "Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating..." and "Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.869 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Domain account names, group memberships and privilege are discoverable" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>

## Related classes (via chains)

- `lateral_movement` Lateral Movement (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `info_disclosure` Information Disclosure (1 chains)
