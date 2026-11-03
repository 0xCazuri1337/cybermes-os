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

## 2026-10-04 00:43 — 151 diff lines
- items: 23 (supported 7), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -20,84 +20,99 @@
 
 ## Prerequisites (do not start without these)
 
-- An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.
+- An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.  _(merged 1 duplicate row(s))_
   - **Disproof:** If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
-- Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.
+- Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.  _(merged 1 duplicate row(s))_
   - **Disproof:** A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.
   - Sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
 
 ## Techniques (what to change)
 
-- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels. _(unverified)_
+- An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
+- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
+- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an environment is tightly managed and an adversary can gain a foothold and bypass EDR o".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
+  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
+- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module introduces Active Directory, the LDAP protocol, working with LDAP and AD searc".
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
+- We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
+- We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
+  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+- We will cover how to identify, exploit, and prevent each of these vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
+- We will discuss how to identify, exploit, and prevent TLS attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
+  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+- We will discuss how to identify, exploit, and prevent each vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
+- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module introduces Active Directory, the LDAP protocol, working with LDAP and AD searc".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
-- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.
-  - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
 
 ## Tests
 
-- To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.
+- To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones) states the full boundary.
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
 ## False-positive rules (when to reject it)
 
-- An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.
+- An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.
+  - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
... (truncated)
```

## 2026-10-04 19:46 — 9 diff lines
- items: 23 (supported 7), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -116,6 +116,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/ad_ldap/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 45 diff lines
- items: 23 (supported 11), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 23 items, 7 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -41,8 +41,8 @@
 - Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an environment is tightly managed and an adversary can gain a foothold and bypass EDR o".
+- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an environment is tightly managed and an adversary can gain a foothold and by”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
 - Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
@@ -50,16 +50,16 @@
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facil”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module introduces Active Directory, the LDAP protocol, working with LDAP and AD searc".
+- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This module introduces Active Directory, the LDAP protocol, working with LDAP an”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
 - We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
```

## 2026-10-04 21:53 — 21 diff lines
- items: 22 (supported 10), FP rules 2, chains 1, state mature

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 23 items, 11 supported, 2 FP rules, 1 chains
+> evidence: 22 items, 10 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -58,9 +58,6 @@
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-- This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This module introduces Active Directory, the LDAP protocol, working with LDAP an”) does not occur under a test that isolates that control.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
 - We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
 - We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
```

## 2026-10-28 14:45 — 59 diff lines
- items: 9 (supported 8), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 22 items, 10 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 9 items, 8 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
 
@@ -32,45 +32,9 @@
 - An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an environment is tightly managed and an adversary can gain a foothold and by”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facil”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-- We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-- We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-- We will discuss how to identify, exploit, and prevent TLS attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will discuss how to identify, exploit, and prevent each vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 - While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
   - Sources: <https://cwe.mitre.org/data/definitions/90.html>
```

## 2026-10-28 17:55 — 24 diff lines
- items: 7 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 9 items, 8 supported, 2 FP rules, 1 chains
+> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -32,12 +32,6 @@
 - An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
-- If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an environment is tightly managed and an adversary can gain a foothold and by”) does not occur under a test that isolates that control.
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-  - Sources: <https://cwe.mitre.org/data/definitions/90.html>
 
 ## Tests
 
```

## 2026-10-29 14:36 — 27 diff lines
- items: 10 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
+> evidence: 10 items, 9 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
@@ -32,6 +32,15 @@
 - An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.
   - Sources: <https://cwe.mitre.org/data/definitions/90.html> · <https://www.rfc-editor.org/rfc/rfc4511.html>
+- Anonymous LDAP bind on a domain controller can expose user accounts, groups, and directory structure without credentials.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Anonymous bind is disabled and returns insufficientAccessRights.
+  - Sources: <https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md> · <https://tryhackme.com/room/adbasicenumeration>
+- LDAP injection occurs when user input is concatenated into an LDAP filter, allowing an attacker to alter query logic and bypass authentication.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Input is escaped per RFC 4515 or parameterized queries are used.
+  - Sources: <https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md> · <https://www.kayssel.com/newsletter/issue-30/>
+- Nmap LDAP scripts enumerate naming contexts, users, and groups from a domain controller on ports 389 and 636.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** LDAP ports are filtered or the server requires signing and rejects the query.
+  - Sources: <https://h3ll-ka1ser.gitbook.io/boot2root/active-directory-penetration-testing/enumeration/no-credentials/ldap-enumeration> · <https://tryhackme.com/room/adbasicenumeration>
 
 ## Tests
 
```

## 2026-10-31 06:41 — 40 diff lines
- items: 10 (supported 5), FP rules 0, chains 1, state researching
- still missing: items, fp_rules

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-90 · OWASP —
-> evidence: 10 items, 9 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 10 items, 5 supported, 0 FP rules, 1 chains
+> maturity: **researching** — missing: items, fp_rules
 
 Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.
 
@@ -44,22 +44,22 @@
 
 ## Tests
 
-- To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones) states the full boundary.
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 
 ## False-positive rules (when to reject it)
 
-- An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.  _(merged 1 duplicate row(s))_
+- An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.
   - Sources: <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.  _(merged 1 duplicate row(s))_
+- An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ldap.fp_rule.anonymous_ldap_read_is_default_ad_configuration) states the full boundary.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 10 (supported 5), FP rules 0, chains 1, state researching
- still missing: items, fp_rules

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -79,7 +79,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/active-directory/ad_ldap/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
+Full class document: `skills/network/active-directory/ad_ldap/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ldap`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 10 (supported 5), FP rules 0, chains 1, state researching
- still missing: items, fp_rules

```diff
--- ad_ldap@current
+++ ad_ldap@new
@@ -5,7 +5,8 @@
 
 # LDAP as an Attack Surface — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
