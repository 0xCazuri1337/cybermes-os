# Windows Privilege Escalation via Token Manipulation

> surface: `ad` · CWE: CWE-269 · OWASP: A09:2021
> maturity: **researching** — 12 items, 10 supported, 0 FP rules, 1 chains

A low-privilege token is exchanged for a token acting as a more privileged principal, so the escalation happens in the token the process holds rather than in code execution.

## Prerequisite

- **A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.**  
  `high_confidence` · score 0.83 · disproved by: The token already lists both privileges and the potato run still fails to yield a SYSTEM process.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
- **Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.**  
  `high_confidence` · score 0.83 · disproved by: A medium-integrity process successfully modifies an object at high or system integrity.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/integrity-levels.md>
- **Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.**  
  `high_confidence` · score 0.83 · disproved by: A non-elevated process successfully creates or associates a primary token with a process.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
- **Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.**  
  `high_confidence` · score 0.83 · disproved by: A token from a different user, or one at a higher integrity level, is successfully impersonated without those conditions holding.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>

## Signal

- **A token swap that starts a process under another account is recorded in Security event 4648, which carries the SID of the account that requested the new logon session separately from the account whose credentials were used, so a token-escalation hunt compares those two fields instead of trusting the parent process's access token.**  
  `high_confidence` · score 0.924 · disproved by: Wrong if replaying `runas /user:other cmd.exe` on a host with Audit Logon enabled produces no 4648 record at all, or if the Subject and the credentials-used account are always identical because the child inherited the caller's own token; then this event carries no evidence of the swap and a hunt keyed on it is chasing a routine event. Also wrong as a discriminator when scheduled-task and svchost-initiated 4648 volume on the estate exceeds the number of mismatched rows.
  sources: <https://attack.mitre.org/techniques/T1134/> · <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648>
- **After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.**  
  `high_confidence` · score 0.83 · disproved by: The process's local identity, groups, or integrity level also change to the alternate account.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>

## Technique

- **A process holding SeCreateTokenPrivilege builds a brand-new primary token whose group SIDs it chooses instead of impersonating an existing one, so adding S-1-5-32-544 (BUILTIN\Administrators) to that token escalates privilege without ever opening a SYSTEM token handle.**  
  `high_confidence` · score 0.94 · disproved by: Wrong if a lab host whose account does hold SeCreateTokenPrivilege still cannot get a child process running with S-1-5-32-544 enabled and not deny-only, or if the token can only be created by a caller that is already LocalSystem: the LocalSystem-only grant is then the escalation boundary rather than the token construction, and this hunt step is pointing at the wrong privilege. Also wrong if the child's groups show S-1-5-32-544 as Enabled while the parent already had it Enabled, since that is inheritance and not escalation.
  sources: <https://attack.mitre.org/techniques/T1134/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>
- **A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.**  
  `high_confidence` · score 0.83 · disproved by: A child process launched by the privileged parent runs under a lower-privilege identity with a different primary token.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
- **SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.**  
  `high_confidence` · score 0.83 · disproved by: No handle to a higher-privilege token can be obtained, or the privilege alone is not sufficient to open one.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>

## Fp Rule

- **Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who..." and "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.869 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A failed potato-family run against a service account is often a filter" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>
- **Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." and "SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.869 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>

## Impact

- **LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.**  
  `high_confidence` · score 0.83 · disproved by: LSASS memory cannot be read even from an elevated or SYSTEM context.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/authentication-credentials-uac-and-efs.md>

## Known gaps

Not yet satisfied: `fp_rules`
