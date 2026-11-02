# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 02:41 — 1 diff lines
- items: 8 (supported 8), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-03)
```

## 2026-10-03 05:00 — 29 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_token@current
+++ windows_privesc_token@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP A09:2021
-> evidence: 8 items, 8 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> evidence: 10 items, 10 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A low-privilege token is exchanged for a token acting as a more privileged principal, so the escalation happens in the token the process holds rather than in code execution.
 
@@ -46,6 +46,15 @@
   - **Disproof:** No handle to a higher-privilege token can be obtained, or the privilege alone is not sufficient to open one.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who..." and "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A failed potato-family run against a service account is often a filter" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." and "SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+
 ## Impact framing
 
 - LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.
```

## 2026-10-04 00:43 — 80 diff lines
- items: 10 (supported 10), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_token@current
+++ windows_privesc_token@new
@@ -18,48 +18,63 @@
 
 ## Prerequisites (do not start without these)
 
-- A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.
+- A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.  _(merged 1 duplicate row(s))_
   - **Disproof:** The token already lists both privileges and the potato run still fails to yield a SYSTEM process.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
-- Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.
+- Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A non-elevated process successfully creates or associates a primary token with a process.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
+- Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.  _(merged 1 duplicate row(s))_
   - **Disproof:** A medium-integrity process successfully modifies an object at high or system integrity.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/integrity-levels.md>
-- Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.
-  - **Disproof:** A non-elevated process successfully creates or associates a primary token with a process.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
-- Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.
+- Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.  _(merged 1 duplicate row(s))_
   - **Disproof:** A token from a different user, or one at a higher integrity level, is successfully impersonated without those conditions holding.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
 
 ## Recon signals (where to look)
 
-- After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.
+- After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.  _(merged 1 duplicate row(s))_
   - **Disproof:** The process's local identity, groups, or integrity level also change to the alternate account.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
 
 ## Techniques (what to change)
 
-- A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.
+- A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.  _(merged 1 duplicate row(s))_
   - **Disproof:** A child process launched by the privileged parent runs under a lower-privilege identity with a different primary token.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
-- SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.
+- SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.  _(merged 1 duplicate row(s))_
   - **Disproof:** No handle to a higher-privilege token can be obtained, or the privilege alone is not sufficient to open one.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
 
 ## False-positive rules (when to reject it)
 
-- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who..." and "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." and "SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who..." and "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A failed potato-family run against a service account is often a filter" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
-- Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." and "SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
-  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
 
 ## Impact framing
 
-- LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.
+- LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.  _(merged 1 duplicate row(s))_
   - **Disproof:** LSASS memory cannot be read even from an elevated or SYSTEM context.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/authentication-credentials-uac-and-efs.md>
 
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
 Full class document: `domains/network/active-directory/windows_privesc_token/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_token`
```
