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
