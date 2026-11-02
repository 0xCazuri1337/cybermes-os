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

## 2026-10-04 00:43 — 163 diff lines
- items: 24 (supported 6), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -20,90 +20,102 @@
 
 ## Prerequisites (do not start without these)
 
-- NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.
+- NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
 ## Techniques (what to change)
 
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
+- An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
+- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack. _(unverified)_
+- Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Then, when the remote service attempts to access the specified path, we’d require authenti".
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
+- We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- We will cover how to identify, exploit, and prevent each of these vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
+  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+- We will discuss how to identify, exploit, and prevent TLS attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/>
+- We will discuss how to identify, exploit, and prevent each vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
+  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
+- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
-- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
-- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
-- An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.
-  - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
 ## Tests
... (truncated)
```

## 2026-10-04 19:46 — 9 diff lines
- items: 24 (supported 6), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -119,6 +119,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/ad_ntlm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_ntlm`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 44 diff lines
- items: 24 (supported 11), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 24 items, 6 supported, 2 FP rules, 1 chains
+> evidence: 24 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
@@ -44,23 +44,23 @@
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facil”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Then, when the remote service attempts to access the specified path, we’d require authenti".
+- Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Then, when the remote service attempts to access the specified path, we’d requir”) does not occur under a test that isolates that control.
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
+  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This exposes enterprises to vulnerabilities and exploitation from simple misconf”) does not occur under a test that isolates that control.
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This will make us more effective as attackers and equip us to give sound recomme”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
 - We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
```

## 2026-10-28 14:39 — 68 diff lines
- items: 12 (supported 8), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 24 items, 11 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 8 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
@@ -38,51 +38,18 @@
 - Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facil”) does not occur under a test that isolates that control.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Then, when the remote service attempts to access the specified path, we’d requir”) does not occur under a test that isolates that control.
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when: the response is byte-identical to the baseline when the same request is made without the crafted input. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This exposes enterprises to vulnerabilities and exploitation from simple misconf”) does not occur under a test that isolates that control.
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This will make us more effective as attackers and equip us to give sound recomme”) does not occur under a test that isolates that control.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
-- We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- We will discuss how to identify, exploit, and prevent TLS attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/>
-- We will discuss how to identify, exploit, and prevent each vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
 
 ## Tests
 
+- A relay is not proven by the attacker's SMB listener alone: the Impacket challenge and GUID identify the capture point, while a completed relay also requires a target that accepts the relayed credentials without signing or channel binding; the LDAP/RBCD path, for example, requires unsigned LDAP.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The relay claim fails when the capture host shows only the default Impacket challenge/GUID and no second authenticated session, or when the intended target enforces SMB signing, LDAP signing, or EPA and rejects the relayed credentials.
+  - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - To decide this case, observe: Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
```

## 2026-10-28 15:47 — 70 diff lines
- items: 9 (supported 9), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 12 items, 8 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 9 items, 9 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
 
@@ -20,6 +20,9 @@
 
 ## Prerequisites (do not start without these)
 
+- LDAP signing and Extended Protection for Authentication are target-side controls that can reject a relayed NTLM exchange; a successful relay requires a target service whose signing and channel-binding policy accepts the relayed authentication.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A relay can fail after the victim authenticates to the attacker because the target rejects the unsigned or channel-mismatched exchange. Do not report a relay from the capture alone; require the target-side session and confirm the target's signing and channel-binding policy.
+  - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
 - NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
@@ -29,21 +32,6 @@
 - An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Then, when the remote service attempts to access the specified path, we’d requir”) does not occur under a test that isolates that control.
-  - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
 ## Tests
 
@@ -59,15 +47,21 @@
 - One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.  _(merged 1 duplicate row(s))_
   - **Disproof:** The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
-- Reject a ad_ntlm finding until it is distinguished from the adjacent behaviour this class also covers. "An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts..." and "NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "NTLM authentication traffic cannot be treated as an anomaly until a pe" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- SMB signing is a target-side control: a successful SMB relay requires a server that does not require signing, while a signing requirement causes the relayed session to fail rather than proving the victim was compromised.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A signing-enabled SMB server is a blocked relay target for that path, not proof that a relay succeeded. Do not downgrade the finding to informational without checking the other target protocols, and do not report success from the victim's authentication alone.
+  - Sources: <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
 
 ## Evidence requirements
 
 - A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ntlm.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+
+## Impact framing
+
+- Relaying NTLM authentication to ADCS web enrollment can obtain a certificate for the relay victim, which the attacker can then use to impersonate that victim; ADCS is a relay target distinct from SMB and LDAP.  _(merged 1 duplicate row(s))_
+  - **Disproof:** An ADCS web-enrollment endpoint being reachable is not proof of a relay. Reject the finding unless the CA issued a certificate for the relayed identity and that certificate authenticated to a service outside the engagement's authorized test path, or the certificate's issuance is otherwise demonstrated.
+  - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 
 
 ## Hunt procedure
```

## 2026-10-29 14:36 — 26 diff lines
- items: 12 (supported 12), FP rules 2, chains 1, state mature

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 9 items, 9 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
 
@@ -32,6 +32,12 @@
 - An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+- NTLM relay forwards a captured authentication in real time to another service, authenticating as the victim without cracking the password.  _(merged 1 duplicate row(s))_
+  - **Disproof:** SMB signing, LDAP signing, and channel binding are enforced, or no relay path exists.
+  - Sources: <https://amandaguglieri.github.io/hackinglife/authentication/ntlm/> · <https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/>
+- Pass-the-Hash authenticates as a user using the NT hash without knowing the password, because NTLM treats the hash as the credential.  _(merged 1 duplicate row(s))_
+  - **Disproof:** NTLM is disabled in favor of Kerberos, or the NT hash cannot be extracted due to Credential Guard or LSA protection.
+  - Sources: <https://cyberdefenders.org/cybersecurity-glossary/active-directory-security/> · <https://wizardcyber.com/learning-hub/learning-post/what-is-ntlm/>
 
 ## Tests
 
```

## 2026-10-31 06:41 — 58 diff lines
- items: 12 (supported 6), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-294 · OWASP —
-> evidence: 12 items, 12 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 12 items, 6 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.
 
@@ -23,13 +23,13 @@
 - LDAP signing and Extended Protection for Authentication are target-side controls that can reject a relayed NTLM exchange; a successful relay requires a target service whose signing and channel-binding policy accepts the relayed authentication.  _(merged 1 duplicate row(s))_
   - **Disproof:** A relay can fail after the victim authenticates to the attacker because the target rejects the unsigned or channel-mismatched exchange. Do not report a relay from the capture alone; require the target-side session and confirm the target's signing and channel-binding policy.
   - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
-- NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_
+- NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
 ## Techniques (what to change)
 
-- An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.  _(merged 1 duplicate row(s))_
+- An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 - NTLM relay forwards a captured authentication in real time to another service, authenticating as the victim without cracking the password.  _(merged 1 duplicate row(s))_
@@ -41,16 +41,16 @@
 
 ## Tests
 
-- A relay is not proven by the attacker's SMB listener alone: the Impacket challenge and GUID identify the capture point, while a completed relay also requires a target that accepts the relayed credentials without signing or channel binding; the LDAP/RBCD path, for example, requires unsigned LDAP.  _(merged 1 duplicate row(s))_
+- A relay is not proven by the attacker's SMB listener alone: the Impacket challenge and GUID identify the capture point, while a completed relay also requires a target that accepts the relayed credentials without signing or channel binding; the LDAP/RBCD path, for example, requires unsigned LDAP.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The relay claim fails when the capture host shows only the default Impacket challenge/GUID and no second authenticated session, or when the intended target enforces SMB signing, LDAP signing, or EPA and rejects the relayed credentials.
   - Sources: <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
-- To decide this case, observe: Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft) states the full boundary.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 
 ## False-positive rules (when to reject it)
 
-- One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.  _(merged 1 duplicate row(s))_
+- One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
 - SMB signing is a target-side control: a successful SMB relay requires a server that does not require signing, while a signing requirement causes the relayed session to fail rather than proving the victim was compromised.  _(merged 1 duplicate row(s))_
@@ -59,7 +59,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ntlm.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
```

## 2026-10-31 08:23 — 11 diff lines
- items: 12 (supported 6), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- ad_ntlm@current
+++ ad_ntlm@new
@@ -61,7 +61,7 @@
 
 - A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ntlm.fp_rule.auto.derived) states the full boundary.
-  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
+  - Sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
 
 ## Impact framing
 
```
