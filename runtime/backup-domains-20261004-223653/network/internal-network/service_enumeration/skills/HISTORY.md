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

## 2026-10-04 00:43 — 59 diff lines
- items: 6 (supported 6), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- service_enumeration@current
+++ service_enumeration@new
@@ -20,33 +20,48 @@
 
 ## Techniques (what to change)
 
-- Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.
+- Full TCP port scanning with service version detection is the entry step that establishes which attack surface exists before any technique is attempted.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the target is unreachable or filters the scan so that no port state is observable, in which case the scan yields no attack surface at all.
+  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10.%20Network%20Enumeration%20with%20Nmap/Network%20Enumeration%20with%20Nmap.md>
+- Port and service scanning is used to acquire the list of open services and their banners, and that list is what determines which technique is even applicable to a host.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the scan is run inside an authorized scope and the banners collected match the documented services for every host in that scope, then no unexpected service surface was found and there is nothing to report.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://www.rfc-editor.org/rfc/rfc6335.html>
-- Full TCP port scanning with service version detection is the entry step that establishes which attack surface exists before any technique is attempted.
-  - **Disproof:** Refuted when the target is unreachable or filters the scan so that no port state is observable, in which case the scan yields no attack surface at all.
-  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cwe.mitre.org/data/definitions/200.html> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10.%20Network%20Enumeration%20with%20Nmap/Network%20Enumeration%20with%20Nmap.md>
 
 ## Validation bar (how to prove it)
 
-- An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.
+- An RDP session is confirmed malicious only when the account's enumeration-derived RDP access rights and the origin of its credential both support the session; rights alone or a successful session alone are insufficient.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the claim wrong would be a session where the account holds no enumerated RDP right to the destination yet the session succeeded, or one where the credential was legitimately issued to the operator but the session still carried a non-standard channel and created a forward -- in either case rights and credential origin would not have discriminated the finding, and channel plus process evidence would have to be the deciding signal.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 
 ## False-positive rules (when to reject it)
 
-- An open TCP port on an internet-facing host is a baseline observation, not a finding; do not file a port as a vulnerability unless a specific weakness is reachable on that port - an unauthenticated service, a default credential, or a known-vulnerable version - because every listening service is by definition exposed to the network.
+- An open TCP port on an internet-facing host is a baseline observation, not a finding; do not file a port as a vulnerability unless a specific weakness is reachable on that port - an unauthenticated service, a default credential, or a known-vulnerable version - because every listening service is by definition exposed to the network.  _(merged 1 duplicate row(s))_
   - **Disproof:** The service listening on the port accepts unauthenticated requests, ships a default or well-known credential, or runs a version with a known exploitable CVE - in which case the open port is the delivery path for a real, demonstrable weakness and belongs in the report as such.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
-- RDP sessions arriving from a known administrator workstation, a sanctioned jump host, or a training lab endpoint are expected and must not be reported as exposed-service misuse.
+- RDP sessions arriving from a known administrator workstation, a sanctioned jump host, or a training lab endpoint are expected and must not be reported as exposed-service misuse.  _(merged 1 duplicate row(s))_
   - **Disproof:** Proof the rule wrong would be a session from a sanctioned jump host that is demonstrably not sanctioned operator work -- carrying a non-standard virtual channel, running bulk transfer, or creating a port-forwarding rule on the destination -- which would mean the exemption must be conditioned on channel and process evidence rather than on source host alone.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable that triggers this false positive is a port scan result listing open TCP ports on an internet-facing host, filed directly as a vulnerability.
+- A convincing observation for this class is: The observable that triggers this false positive is a port scan result listing open TCP ports on an internet-facing host, filed directly as a vulnerability.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (service_enumeration.fp_rule.open_port_alone_is_not_a_finding) states the full boundary.
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/internal-network/service_enumeration/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration`
```
