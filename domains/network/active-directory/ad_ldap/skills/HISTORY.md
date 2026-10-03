# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 21 (supported 21), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 21 (supported 21), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -91,4 +91,4 @@
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
 ---
-Full class document: `domains/network/active-directory/ad_ldap/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
+Full class document: `domains/network/active-directory/ad_ldap/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
```

## 2026-10-02 19:37 — 91 diff lines
- items: 22 (supported 6), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 21 items, 21 supported, 2 FP rules, 1 chains
+> evidence: 22 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -29,57 +29,63 @@
 
 ## Techniques (what to change)
 
-- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.
+- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an environment is tightly managed and an adversary can gain a foothold and bypass EDR o".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.
+- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
-- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.
+- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module introduces Active Directory, the LDAP protocol, working with LDAP and AD searc".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- We will cover how to identify, exploit, and prevent each of them through various methods.
+- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.
+- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will cover how to identify, exploit, and prevent each of these injection attacks.
+- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
-- We will discuss how to identify, exploit, and prevent each vulnerability.
+- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
+- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.
+- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.
+- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
 - An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.
   - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
+
+## Tests
+
+- To decide this case, observe: that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory. Only when all three agree (graph present, domain naming attributes present, ADWS answering on the same host) is the observation a real DC exposure.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones) states the full boundary.
+  - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-03 01:46 — 97 diff lines
- items: 23 (supported 7), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 22 items, 6 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 7 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -31,59 +31,56 @@
 
 - If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an environment is tightly managed and an adversary can gain a foothold and bypass EDR o".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module introduces Active Directory, the LDAP protocol, working with LDAP and AD searc".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
 - We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
 - Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
 - An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.
   - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
 
 ## Tests
 
-- To decide this case, observe: that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory. Only when all three agree (graph present, domain naming attributes present, ADWS answering on the same host) is the observation a real DC exposure.
+- To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones) states the full boundary.
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
@@ -96,5 +93,11 @@
   - **Disproof:** A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ldap.fp_rule.anonymous_ldap_read_is_default_ad_configuration) states the full boundary.
+  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
+
 ---
 Full class document: `domains/network/active-directory/ad_ldap/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
```
