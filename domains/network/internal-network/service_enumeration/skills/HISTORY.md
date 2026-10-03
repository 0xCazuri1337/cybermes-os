# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
--- service_enumeration@current
+++ service_enumeration@new
@@ -70,4 +70,4 @@
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ---
-Full class document: `domains/network/internal-network/service_enumeration/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration`
+Full class document: `domains/network/internal-network/service_enumeration/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration`
```

## 2026-10-02 19:37 — 50 diff lines
- items: 4 (supported 4), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration@current
+++ service_enumeration@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 4 items, 4 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A service's announcement identifies its implementation and often its version, which selects the technique that applies to it.
 
@@ -20,36 +20,6 @@
 
 ## Techniques (what to change)
 
-- As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Utilizing this method alone has caused often-already overburdened personnel responsible for managing OT vulnerabilities to waste resources prioritizing those that are not exploitable or will not ever be exploited.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Utilizing this method alone has caused often-already overburdened personnel responsible fo".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Comprehensive device discovery will allow them to fully understand the attack surface and any exploitable entry points.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Comprehensive device discovery will allow them to fully understand the attack surface and ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Threat Validation and Stress Testing:   During the validation stage, organizations should validate the ways a potential attacker could exploit an identified exposure, and how monitoring and control systems may react.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Threat Validation and Stress Testing:   During the validation stage, organizations should ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- If an exploit is not published, organizations may need to investigate via other means including software bills of materials (SBOMs) or vulnerability exploitability eXchange (VEX) files.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an exploit is not published, organizations may need to investigate via other means incl".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- As a result, it is imperative that organizations implement exposure management, which is the proactive cybersecurity approach of identifying, assessing, and addressing potential vulnerabilities and risks before they can be exploited.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As a result, it is imperative that organizations implement exposure management, which is t".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Comprehensive device discovery will allow them to fully understand the attack surface and any exploitable entry points.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Comprehensive device discovery will allow them to fully understand the attack surface and ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Threat Validation and Stress Testing:   During the validation stage, organizations should validate the ways a potential attacker could exploit an identified exposure, and how monitoring and control systems may react.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Threat Validation and Stress Testing:   During the validation stage, organizations should ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- If an exploit is not published, organizations may need to investigate via other means including software bills of materials (SBOMs) or vulnerability exploitability eXchange (VEX) files.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an exploit is not published, organizations may need to investigate via other means incl".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- Utilizing this method alone has caused often-already overburdened personnel responsible for managing OT vulnerabilities to waste resources prioritizing those that are not exploitable or will not ever be exploited.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Utilizing this method alone has caused often-already overburdened personnel responsible fo".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 - Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.
   - **Disproof:** If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
   - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://www.rfc-editor.org/rfc/rfc6335.html>
```

## 2026-10-03 01:46 — 35 diff lines
- items: 6 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration@current
+++ service_enumeration@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-200 · OWASP —
-> evidence: 4 items, 4 supported, 2 FP rules, 1 chains
+> evidence: 6 items, 6 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 A service's announcement identifies its implementation and often its version, which selects the technique that applies to it.
@@ -22,7 +22,10 @@
 
 - Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.
   - **Disproof:** If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
-  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://www.rfc-editor.org/rfc/rfc6335.html>
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://www.rfc-editor.org/rfc/rfc6335.html>
+- Full TCP port scanning with service version detection is the entry step that establishes which attack surface exists before any technique is attempted.
+  - **Disproof:** Refuted when the target is unreachable or filters the scan so that no port state is observable, in which case the scan yields no attack surface at all.
+  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10.%20Network%20Enumeration%20with%20Nmap/Network%20Enumeration%20with%20Nmap.md>
 
 ## Validation bar (how to prove it)
 
@@ -39,5 +42,11 @@
   - **Disproof:** Proof the rule wrong would be a session from a sanctioned jump host that is demonstrably not sanctioned operator work -- carrying a non-standard virtual channel, running bulk transfer, or creating a port-forwarding rule on the destination -- which would mean the exemption must be conditioned on channel and process evidence rather than on source host alone.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: The observable that triggers this false positive is a port scan result listing open TCP ports on an internet-facing host, filed directly as a vulnerability.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration.fp_rule.open_port_alone_is_not_a_finding) states the full boundary.
+  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
+
 ---
 Full class document: `domains/network/internal-network/service_enumeration/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration`
```
