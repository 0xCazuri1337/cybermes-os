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
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -91,4 +91,4 @@
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
 ---
-Full class document: `domains/network/active-directory/ad_ntlm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ntlm`
+Full class document: `domains/network/active-directory/ad_ntlm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ntlm`
```

## 2026-10-02 19:37 — 98 diff lines
- items: 23 (supported 5), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 21 items, 21 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
@@ -26,60 +26,69 @@
 
 ## Techniques (what to change)
 
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
+- Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack. _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Then, when the remote service attempts to access the specified path, we’d require authenti".
+  - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.
+- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
-- We will cover how to identify, exploit, and prevent each of them through various methods.
+- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.
+- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- We will cover how to identify, exploit, and prevent each of these injection attacks.
+- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- We will discuss how to identify, exploit, and prevent each vulnerability.
+- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
+- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.
+- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.
+- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.
   - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
+
+## Tests
+
+- To decide this case, observe: ward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure. Escalate only when the relay fingerprint or a second authenticated session exists.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft) states the full boundary.
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-03 01:46 — 121 diff lines
- items: 24 (supported 6), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 23 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 24 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
@@ -22,71 +22,71 @@
 
 - NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.
   - **Disproof:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
 ## Techniques (what to change)
 
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Then, when the remote service attempts to access the specified path, we’d require authenti".
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
 - We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
 - We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/>
 - We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
 - An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.
   - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
 ## Tests
 
-- To decide this case, observe: ward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure. Escalate only when the relay fingerprint or a second authenticated session exists.
+- To decide this case, observe: Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
@@ -94,10 +94,16 @@
 
 - Reject a ad_ntlm finding until it is distinguished from the adjacent behaviour this class also covers. "An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts..." and "NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "NTLM authentication traffic cannot be treated as an anomaly until a pe" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.
   - **Disproof:** The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ntlm.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+
 ---
... (truncated)
```
