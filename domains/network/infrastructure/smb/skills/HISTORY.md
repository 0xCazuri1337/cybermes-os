# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 5, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 5, chains 1, state mature

```diff
--- smb@current
+++ smb@new
@@ -81,4 +81,4 @@
 - `lateral_movement` (1 shared chain(s))
 
 ---
-Full class document: `domains/network/infrastructure/smb/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
+Full class document: `domains/network/infrastructure/smb/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smb`
```

## 2026-10-02 19:37 — 47 diff lines
- items: 8 (supported 8), FP rules 5, chains 1, state researching
- still missing: items

```diff
--- smb@current
+++ smb@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-732 · OWASP —
-> evidence: 13 items, 13 supported, 5 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 8 items, 8 supported, 5 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.
 
@@ -20,27 +20,15 @@
 
 ## Techniques (what to change)
 
-- For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
 - SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.
   - **Disproof:** If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.
   - Sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://www.rfc-editor.org/rfc/rfc1002.html>
+
+## Tests
+
+- To decide this case, observe: key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default. It survives only when the attacker recovered the session key or the target did not require signing.
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (smb.fprule.signing_required_ends_relay) states the full boundary.
+  - Sources: <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-03 01:46 — 53 diff lines
- items: 10 (supported 9), FP rules 4, chains 1, state researching
- still missing: items

```diff
--- smb@current
+++ smb@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-732 · OWASP —
-> evidence: 8 items, 8 supported, 5 FP rules, 1 chains
+> evidence: 10 items, 9 supported, 4 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.
@@ -20,13 +20,16 @@
 
 ## Techniques (what to change)
 
+- Anonymous or guest access to an SMB share, and the enumeration that reveals it, is the usual route to credentials or a file drop on a Windows target.
+  - **Disproof:** Refuted when the share requires authentication and rejects guest/anonymous sessions, and no share permits a write, so the share yields neither credentials nor a file drop.
+  - Sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/04.%20Exploitation/19.%20Attacking%20Common%20Services/Attacking%20Common%20Services.md> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Footprinting%20Services.md>
 - SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.
   - **Disproof:** If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.
   - Sources: <https://attack.mitre.org/techniques/T1021/002/> · <https://www.rfc-editor.org/rfc/rfc1002.html>
 
 ## Tests
 
-- To decide this case, observe: key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default. It survives only when the attacker recovered the session key or the target did not require signing.
+- To decide this case, observe: Discard when the tester reported that authentication succeeded but no session could be used: without the shared session key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (smb.fprule.signing_required_ends_relay) states the full boundary.
   - Sources: <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
 
@@ -41,15 +44,21 @@
 - Hidden administrative shares (C$, ADMIN$, IPC$) answering on tcp/445 inside the corporate network are the DEFAULT Windows configuration, not an exposed-share vulnerability; do not file their existence as a finding unless the share is reachable from outside the assessed scope boundary or is created outside the default set (a custom share, a webroot share, or a share added by an operator).
   - **Disproof:** The same share is reachable from a host outside the assessed scope boundary (for example the public internet or a partner network), or the share name is not one of the Windows default administrative shares - a custom data share, an IIS webroot such as \inetpub\wwwroot, or a share created by an operator during deployment - which means somebody chose to expose it.
   - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
-- SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.
+- SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting. _(unverified)_
   - **Disproof:** If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
+  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 - SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.
   - **Disproof:** Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.
   - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/>
 - When the target enforces SMB signing the relay stops at authentication, so a signed-session failure is not a broken-signing finding.
   - **Disproof:** Would be wrong where CVE-2019-1019 style session-key retrieval was possible, since then signing provides no protection against relay.
   - Sources: <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/> · <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
+
+## Evidence requirements
+
+- A convincing observation for this class is: The observable that triggers this false positive is a share enumeration against an internal Windows host returning C$, ADMIN$ and IPC$ - names that appear on essentially every domain-joined machine because the Lanman Server enables them so that administrators and management software can drive hosts remotely over SMB.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smb.fp_rule.admin_shares_present_is_default_windows) states the full boundary.
+  - Sources: <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/> · <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
 
 ## Chaining opportunities
 
```
