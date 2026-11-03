# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 15 (supported 15), FP rules 4, chains 2, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 15 (supported 15), FP rules 4, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -90,4 +90,4 @@
 - `ad_enumeration` (1 shared chain(s))
 
 ---
-Full class document: `domains/network/internal-network/lateral_movement/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
+Full class document: `domains/network/internal-network/lateral_movement/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
```

## 2026-10-02 19:37 — 73 diff lines
- items: 16 (supported 5), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 15 items, 15 supported, 4 FP rules, 2 chains
+> evidence: 16 items, 5 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -26,34 +26,34 @@
 
 ## Techniques (what to change)
 
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.
@@ -63,9 +63,15 @@
   - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
   - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>
 
+## Tests
+
+- To decide this case, observe: ets to gain legitimate access to target resources rather than creating new authentication. The session becomes evidence only when the ticket was extracted or replayed from your foothold host rather than issued to the admin interactively.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+
 ## False-positive rules (when to reject it)
 
-- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.
+- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement. _(unverified)_
   - **Disproof:** If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.
```

## 2026-10-03 01:46 — 78 diff lines
- items: 17 (supported 5), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 16 items, 5 supported, 3 FP rules, 2 chains
+> evidence: 17 items, 5 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -28,34 +28,34 @@
 
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.
   - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
@@ -65,7 +65,7 @@
 
 ## Tests
 
-- To decide this case, observe: ets to gain legitimate access to target resources rather than creating new authentication. The session becomes evidence only when the ticket was extracted or replayed from your foothold host rather than issued to the admin interactively.
+- To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication. _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
@@ -77,6 +77,12 @@
 - A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.
   - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
+
+## Evidence requirements
+
+- A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity) states the full boundary.
+  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
 
 ## Rejected before you report
 
```

## 2026-10-04 00:43 — 115 diff lines
- items: 17 (supported 5), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -20,67 +20,52 @@
 
 ## Prerequisites (do not start without these)
 
-- Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.
+- Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
 ## Techniques (what to change)
 
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
+  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+- Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
+  - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>
+- Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
+  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
+  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
   - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.
-  - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
-  - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.
-  - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
-  - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>
 
 ## Tests
 
-- To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication. _(unverified)_
+- To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
 ## False-positive rules (when to reject it)
 
-- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement. _(unverified)_
+- A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
+  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
+- Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
-- A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.
-  - **Disproof:** The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
-  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.
+- A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity) states the full boundary.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
 
@@ -101,5 +86,20 @@
 - `info_disclosure` (1 shared chain(s))
 - `ad_enumeration` (1 shared chain(s))
 
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
 Full class document: `domains/network/internal-network/lateral_movement/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 17 (supported 5), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -89,10 +89,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Map one hop at a time from a foothold you already hold; record the reachable path, do not execute the pivot.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 17 (supported 5), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -100,6 +100,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/internal-network/lateral_movement/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 22 diff lines
- items: 17 (supported 7), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 17 items, 5 supported, 3 FP rules, 2 chains
+> evidence: 17 items, 7 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -38,8 +38,8 @@
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
```

## 2026-10-28 14:39 — 49 diff lines
- items: 12 (supported 7), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 17 items, 7 supported, 3 FP rules, 2 chains
+> evidence: 12 items, 7 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -26,30 +26,30 @@
 
 ## Techniques (what to change)
 
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 - Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
   - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>
 - Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.  _(merged 1 duplicate row(s))_
   - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 2 duplicate row(s))_ _(unverified)_
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 2 duplicate row(s))_
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 2 duplicate row(s))_ _(unverified)_
+- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
   - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 2 duplicate row(s))_ _(unverified)_
+- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
   - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 
 ## Tests
 
+- Lateral movement is proven by a successful action on a second host using credentials obtained in the engagement, not by the protocol used; SSH, RDP, SMB, WMI, and WinRM are interchangeable carriers once reachability and credentials exist.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The movement finding fails when the supposed destination action used a pre-existing tester account with no engagement-derived credential, when the action ran only on the original host, or when the destination was never reached and only a protocol banner was observed.
+  - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
 - To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
```

## 2026-10-28 15:47 — 51 diff lines
- items: 12 (supported 10), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 12 items, 7 supported, 3 FP rules, 2 chains
+> evidence: 12 items, 10 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -32,27 +32,27 @@
 - Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.  _(merged 1 duplicate row(s))_
   - **Disproof:** The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.
   - Sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://www.rfc-editor.org/rfc/rfc4251.html> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
-- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
-  - Sources: <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
 
 ## Tests
 
+- An exposed RDP port is not lateral movement; RDP/RDS expands access only when the service is enabled and allows access to accounts with known credentials, so the finding requires an authenticated remote session or action.  _(merged 1 duplicate row(s))_
+  - **Disproof:** RDP is a normal administrative and remote-work service. An open 3389 port, a certificate, or a logon screen is not evidence of unauthorized movement; the authenticated session and the credential provenance are the finding.
+  - Sources: <https://attack.mitre.org/techniques/T1021/001/> · <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-rds>
+- An open WinRM port is not lateral movement; WinRM is a protocol for interacting with a remote system, and the finding requires an authenticated operation that runs a command, modifies the registry, or changes a service on the destination.  _(merged 1 duplicate row(s))_
+  - **Disproof:** WinRM is a standard Windows management service. A listener on 5985 is common in managed fleets and is not, by itself, evidence of compromise. The operation and its principal must be tied to the engagement and outside the destination baseline.
+  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
 - Lateral movement is proven by a successful action on a second host using credentials obtained in the engagement, not by the protocol used; SSH, RDP, SMB, WMI, and WinRM are interchangeable carriers once reachability and credentials exist.  _(merged 1 duplicate row(s))_
   - **Disproof:** The movement finding fails when the supposed destination action used a pre-existing tester account with no engagement-derived credential, when the action ran only on the original host, or when the destination was never reached and only a protocol banner was observed.
   - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
+- PsExec-style SMB lateral movement is demonstrated by remote process execution on the destination, not by an SMB session or a share mount; PsExec executes processes on other systems over an authenticated SMB/RPC path.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A benign backup, software deployment, or administrative script can create an SMB session and a remote service. Reject the finding unless the remote execution used credentials obtained in the engagement and the action is outside the destination's normal administrative baseline.
+  - Sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://learn.microsoft.com/en-us/sysinternals/downloads/psexec>
 - To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+- WMI lateral movement is demonstrated by remote WMI execution on the destination, not by the presence of the WMI service; WMI is both a local and remote management interface, so remote use is a legitimate administrative pattern as well as an adversary technique.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Management tools and endpoint agents routinely use remote WMI. A wmiprvse.exe process or a port 135 or 5985 connection is not a finding without a state-changing operation tied to the engagement.
+  - Sources: <https://attack.mitre.org/techniques/T1047/> · <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-31 06:41 — 38 diff lines
- items: 12 (supported 7), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-284 · OWASP —
-> evidence: 12 items, 10 supported, 3 FP rules, 2 chains
+> evidence: 12 items, 7 supported, 3 FP rules, 2 chains
 > maturity: **mature**
 
 Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.
@@ -26,7 +26,7 @@
 
 ## Techniques (what to change)
 
-- Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.  _(merged 1 duplicate row(s))_
+- Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.
   - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://www.rfc-editor.org/rfc/rfc4251.html>
 - Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.  _(merged 1 duplicate row(s))_
@@ -41,7 +41,7 @@
 - An open WinRM port is not lateral movement; WinRM is a protocol for interacting with a remote system, and the finding requires an authenticated operation that runs a command, modifies the registry, or changes a service on the destination.  _(merged 1 duplicate row(s))_
   - **Disproof:** WinRM is a standard Windows management service. A listener on 5985 is common in managed fleets and is not, by itself, evidence of compromise. The operation and its principal must be tied to the engagement and outside the destination baseline.
   - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
-- Lateral movement is proven by a successful action on a second host using credentials obtained in the engagement, not by the protocol used; SSH, RDP, SMB, WMI, and WinRM are interchangeable carriers once reachability and credentials exist.  _(merged 1 duplicate row(s))_
+- Lateral movement is proven by a successful action on a second host using credentials obtained in the engagement, not by the protocol used; SSH, RDP, SMB, WMI, and WinRM are interchangeable carriers once reachability and credentials exist.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The movement finding fails when the supposed destination action used a pre-existing tester account with no engagement-derived credential, when the action ran only on the original host, or when the destination was never reached and only a protocol banner was observed.
   - Sources: <https://attack.mitre.org/techniques/T1021/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
 - PsExec-style SMB lateral movement is demonstrated by remote process execution on the destination, not by an SMB session or a share mount; PsExec executes processes on other systems over an authenticated SMB/RPC path.  _(merged 1 duplicate row(s))_
@@ -65,7 +65,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity) states the full boundary.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
 
```

## 2026-11-02 23:13 — 11 diff lines
- items: 12 (supported 7), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -99,7 +99,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/internal-network/lateral_movement/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
+Full class document: `skills/network/internal-network/lateral_movement/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id lateral_movement`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 12 (supported 7), FP rules 3, chains 2, state mature

```diff
--- lateral_movement@current
+++ lateral_movement@new
@@ -5,7 +5,8 @@
 
 # Lateral Movement — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
