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
--- exposed_services@current
+++ exposed_services@new
@@ -111,4 +111,4 @@
 - `lateral_movement` (2 shared chain(s))
 
 ---
-Full class document: `domains/network/infrastructure/exposed_services/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
+Full class document: `domains/network/infrastructure/exposed_services/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
```

## 2026-10-02 19:37 — 86 diff lines
- items: 8 (supported 4), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 21 items, 21 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 8 items, 4 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
 
@@ -24,68 +24,23 @@
   - **Disproof:** An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
   - Sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
 
-## Recon signals (where to look)
-
-- An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.
-  - **Disproof:** Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-
 ## Techniques (what to change)
 
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- We will cover how to identify, exploit, and prevent each of them through various methods.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
-- We will cover how to identify, exploit, and prevent each of these injection attacks.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- We will discuss how to identify, exploit, and prevent each vulnerability.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
-- For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.
   - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
-
-## Validation bar (how to prove it)
-
-- A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.
-  - **Disproof:** Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-03 01:46 — 48 diff lines
- items: 9 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 8 items, 4 supported, 2 FP rules, 1 chains
+> evidence: 9 items, 5 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
@@ -28,19 +28,22 @@
 
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
+  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
 - Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
 - Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
+- A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.
+  - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
+  - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
 - An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.
   - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
+  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
 
 ## False-positive rules (when to reject it)
 
@@ -52,7 +55,7 @@
 
 - An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.
   - **Disproof:** Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Rejected before you report
 
```
