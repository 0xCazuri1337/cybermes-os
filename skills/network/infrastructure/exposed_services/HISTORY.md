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

## 2026-10-04 00:38 — 92 diff lines
- items: 32 (supported 28), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 9 items, 5 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 32 items, 28 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
 
@@ -41,9 +41,78 @@
 - A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.
   - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
   - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
+- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
+- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
+- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
+- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
+- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
+- Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
 - An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.
   - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
+- Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
+- Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/640.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
+- Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
+- Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/119.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
+- Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/91.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
+- Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
+- OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
+- Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
+- Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
+- Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
+- Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/521.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
+- RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/193.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
+- Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
+- Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
+- Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
+- Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
+- Ypuffy documents CVE-2018-14665 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-14665) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-04 00:43 — 215 diff lines
- items: 32 (supported 28), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -20,109 +20,109 @@
 
 ## Prerequisites (do not start without these)
 
-- Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.
+- Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.  _(merged 1 duplicate row(s))_
   - **Disproof:** An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
   - Sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
 
 ## Techniques (what to change)
 
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
+- A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
+  - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
+- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
+- An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
+  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
+- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
+- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
+  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
+- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
+- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
+- Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
+- Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
+- Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/640.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
+- Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
+  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
+- Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/119.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
+- Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/91.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
+- Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
+- OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
+- Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
+- Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
+- Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
+- Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/521.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
+- RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/193.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
+- Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
+- Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
+- Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
-- A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.
-  - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
-  - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
-- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
-- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
-- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
-- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
-- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
... (truncated)
```

## 2026-10-04 00:50 — 14 diff lines
- items: 32 (supported 28), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -140,10 +140,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Fingerprint the exposed service, then check its OWN version CVEs against the exact build -- never a CVE class inferred from the product name.
 
 ### What counts as proof
 
```

## 2026-10-04 13:16 — 21 diff lines
- items: 33 (supported 29), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 32 items, 28 supported, 2 FP rules, 1 chains
+> evidence: 33 items, 29 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
@@ -83,6 +83,9 @@
 - Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
+- Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
+  - Sources: <https://cwe.mitre.org/data/definitions/284.html> · <https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/>
 - Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
```

## 2026-10-04 19:46 — 9 diff lines
- items: 33 (supported 29), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -154,6 +154,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/infrastructure/exposed_services/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 22 diff lines
- items: 33 (supported 30), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 33 items, 29 supported, 2 FP rules, 1 chains
+> evidence: 33 items, 30 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
@@ -107,8 +107,8 @@
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
 - Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
```

## 2026-10-28 10:06 — 125 diff lines
- items: 33 (supported 7), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 33 items, 30 supported, 2 FP rules, 1 chains
+> evidence: 33 items, 7 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
@@ -29,79 +29,79 @@
 - A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
   - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
-- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
 - An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.  _(merged 1 duplicate row(s))_
   - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
-- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
 - Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
-- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
-- Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
-- Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
-- Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/640.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
-- Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
 - Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
-- Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/119.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
-- Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/91.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
-- Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
-- OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
-- Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
-- Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
 - Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
   - Sources: <https://cwe.mitre.org/data/definitions/284.html> · <https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/>
-- Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
-- Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/521.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
-- RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/193.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
-- Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
-- Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
-- Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -110,10 +110,10 @@
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
+- Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
... (truncated)
```

## 2026-10-28 14:45 — 123 diff lines
- items: 12 (supported 8), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 33 items, 7 supported, 2 FP rules, 1 chains
+> evidence: 12 items, 8 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.
@@ -29,93 +29,30 @@
 - A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.
   - Sources: <https://attack.mitre.org/tactics/TA0001/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
-- AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
 - An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.  _(merged 1 duplicate row(s))_
   - **Disproof:** If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
   - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/20.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
-- Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
-- Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+- CVE-2019-11043 is an out-of-bounds write in PHP-FPM's FastCGI path handling: NVD records that in PHP 7.1.x before 7.1.33, 7.2.x before 7.2.24, and 7.3.x before 7.3.11, certain FPM configurations allow a write past allocated buffers into FCGI protocol data, opening remote code execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The finding fails when the target runs a fixed PHP release, uses a non-FPM SAPI, or its FPM configuration does not expose the FCGI path described by the CVE; a banner match without the vulnerable path is only a version observation.
   - Sources: <https://cwe.mitre.org/data/definitions/787.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
-- Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/287.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
-- Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+- CVE-2019-12384 is a polymorphic deserialization flaw in FasterXML jackson-databind before 2.9.9.1; when logback-core is on the classpath, an attacker can use the deserialized object to reach code execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The finding fails when jackson-databind is fixed, logback-core is absent, or the application does not deserialize attacker-controlled polymorphic data.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
+- CVE-2020-7247 is an OS command injection in OpenSMTPD 6.6: a crafted SMTP MAIL FROM value containing shell metacharacters can execute arbitrary commands as root in the default configuration.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The finding fails when the server is not OpenSMTPD 6.6, the configuration rejects the crafted MAIL FROM, or the command does not execute; a bare SMTP banner is only a service observation.
+  - Sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
+- CVE-2020-8165 is a deserialization of untrusted data flaw in Rails before 5.2.4.3 and before 6.0.3.1; an attacker can unmarshal user-provided objects in MemCacheStore or RedisCacheStore, potentially achieving remote code execution.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The finding fails when the Rails version is fixed, the application does not use MemCacheStore or RedisCacheStore, or user input never reaches a cached object that is deserialized.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
+- CVE-2020-9484 is a deserialization flaw in Apache Tomcat's persistent session handling: when an attacker controls a session file and Tomcat uses a FileStore-backed PersistenceManager, a crafted request can deserialize the attacker's object and execute code.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The finding fails when Tomcat is outside the affected branches, uses a different session store, has a filter that rejects the attacker's object, or the attacker cannot control a file at a path known to FileStore.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
-- Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/640.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
-- Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
-- Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/119.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
-- Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/91.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
-- Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+- CVE-2020-9496 is unsafe XML-RPC deserialization in Apache OFBiz 17.12.03; an XML-RPC request can deserialize attacker-controlled data, and NVD also records a cross-site scripting issue in the same component.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The finding fails when OFBiz is not 17.12.03, the XML-RPC endpoint is disabled or patched, or the request does not reach a deserialization sink.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
-- OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
-- Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
-- Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
-- Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
-  - Sources: <https://cwe.mitre.org/data/definitions/284.html> · <https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/>
-- Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
-- Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/521.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
-- RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/193.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
-- Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
-- Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
-- Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/755.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
-  - Sources: <https://attack.mitre.org/techniques/T1133/> · <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>
-- Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
-- Ypuffy documents CVE-2018-14665 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-14665) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
-  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>
+- CVE-2021-21311 is a server-side request forgery in Adminer 4.0.0 through 4.7.8; the bundled single-file adminer.php can make the server request an attacker-chosen URL, and the issue is fixed in 4.7.9.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The finding fails when Adminer is 4.7.9 or later, the vulnerable driver is not bundled, or the request path does not let the attacker choose the outbound URL.
+  - Sources: <https://cwe.mitre.org/data/definitions/918.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
... (truncated)
```

## 2026-11-02 23:13 — 11 diff lines
- items: 12 (supported 8), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -90,7 +90,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/infrastructure/exposed_services/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
+Full class document: `skills/network/infrastructure/exposed_services/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id exposed_services`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 12 (supported 8), FP rules 2, chains 1, state mature

```diff
--- exposed_services@current
+++ exposed_services@new
@@ -5,7 +5,8 @@
 
 # Exposed Remote Services — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
