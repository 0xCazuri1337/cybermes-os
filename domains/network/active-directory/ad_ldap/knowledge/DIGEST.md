# LDAP as an Attack Surface

> surface: `ad` · CWE: CWE-90 · OWASP: —
> maturity: **mature** — 21 items, 21 supported, 2 FP rules, 1 chains

Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.

**Aliases:** ldap, ldap injection, ldap filter injection, null bind, anonymous bind, ldap signing, channel binding

## Prerequisite

- **Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.**  
  `high_confidence` · score 0.874 · disproved by: A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.
  sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.**  
  `high_confidence` · score 0.8355 · disproved by: If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Technique

- **An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.**  
  `high_confidence` · score 0.8805 · disproved by: If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
- **While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an environment is tightly managed and an adversary can gain a foothold and bypass EDR o".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.794 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module introduces Active Directory, the LDAP protocol, working with LDAP and AD searc".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **We will discuss how to identify, exploit, and prevent each vulnerability.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.7755 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **We will cover how to identify, exploit, and prevent each of these injection attacks.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>

## Fp Rule

- **An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.**  
  `high_confidence` · score 0.8465 · disproved by: A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.
  sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.**  
  `high_confidence` · score 0.844 · disproved by: The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.
  sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
