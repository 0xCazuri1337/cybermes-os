<!-- GENERATED from db/wks.db — do not edit -->
# Windows Privilege Escalation via Token Manipulation

## Definition

A low-privilege token is exchanged for a token acting as a more privileged principal, so the escalation happens in the token the process holds rather than in code execution.

- **CWE:** CWE-269
- **OWASP:** A09:2021
- **Surface:** ad
- **Aliases:** []

Canonical home for `windows_privesc_token`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.**

A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.

HackTricks reference: privilege escalation abusing tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

*Disproof:* The token already lists both privileges and the potato run still fails to yield a SYSTEM process.

**Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.**

Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.

HackTricks reference: integrity levels (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/integrity-levels.md)

*Disproof:* A medium-integrity process successfully modifies an object at high or system integrity.

**Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.**

Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.

HackTricks reference: access tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

*Disproof:* A non-elevated process successfully creates or associates a primary token with a process.

**Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.**

Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.

HackTricks reference: privilege escalation abusing tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

*Disproof:* A token from a different user, or one at a higher integrity level, is successfully impersonated without those conditions holding.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A token swap that starts a process under another account is recorded in Security event 4648, which carries the SID of the account that requested the new logon session separately from the account whose credentials were used, so a token-escalation hunt compares those two fields instead of trusting the parent process's access token.**

The Audit Logon subcategory emits 4648 whenever a process passes credentials explicitly instead of reusing its own token; `runas /user:` is the named case and scheduled tasks produce the same event. The record is account-level rather than process-tree-level: Subject carries the SID of the account that requested the new logon session, 'Account Whose Credentials Were Used' carries the account whose credentials were used, Target Server Name is 'localhost' when the new process ran locally, and Process ID plus Process Name name the executable that was run. Hunt rule: pull 4648, group by Process ID, and flag rows where the Subject SID differs from the credentials-used account, or where a service host such as svchost.exe is the requester. Compare that row against the 4688 Parent Process ID recorded for the same Process ID before calling it: the child keeps a legitimate parent-child lineage while executing on someone else's token, so lineage alone cannot show the swap. Verify the rule by replaying `runas /user:./netonly cmd.exe` on an auditing host and confirming the two fields diverge. The same event is also routine during normal OS activity, so the per-account baseline volume matters as much as the mismatch itself.

*Disproof:* Wrong if replaying `runas /user:other cmd.exe` on a host with Audit Logon enabled produces no 4648 record at all, or if the Subject and the credentials-used account are always identical because the child inherited the caller's own token; then this event carries no evidence of the swap and a hunt keyed on it is chasing a routine event. Also wrong as a discriminator when scheduled-task and svchost-initiated 4648 volume on the estate exceeds the number of mismatched rows.

**After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.**

After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.

HackTricks reference: access tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

*Disproof:* The process's local identity, groups, or integrity level also change to the alternate account.

## Exploitation

**A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.**

A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.

HackTricks reference: access tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

*Disproof:* A child process launched by the privileged parent runs under a lower-privilege identity with a different primary token.

**SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.**

SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.

HackTricks reference: privilege escalation abusing tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

*Disproof:* No handle to a higher-privilege token can be obtained, or the privilege alone is not sufficient to open one.

**A process holding SeCreateTokenPrivilege builds a brand-new primary token whose group SIDs it chooses instead of impersonating an existing one, so adding S-1-5-32-544 (BUILTIN\Administrators) to that token escalates privilege without ever opening a SYSTEM token handle.**

Probe with `whoami /priv` for SeCreateTokenPrivilege and, in a GPO-managed configuration, check the 'Create a token object' user right. The mechanism is token construction rather than impersonation: build a token whose group list holds the caller's own user SID plus S-1-5-32-544 enabled (not 'Group used for deny only'), duplicate it to a primary token, and launch the payload with CreateProcessAsUser or ImpersonateLoggedOnUser. No SYSTEM process has to be coerced over DCOM or NTLM and no NT AUTHORITY\SYSTEM logon SID has to be found, which is what separates this from the SeImpersonatePrivilege coercion path. Verify by comparing `whoami /groups` in the child against the parent's `whoami /priv` baseline: the escalation is confirmed only when S-1-5-32-544 shows as Enabled in the child rather than deny-only. Defence is this right specifically - Microsoft ties it to the 'Create a token object' policy and notes it cannot be added to a user account that the policy governs, while ATT&CK's mitigation for T1134 is to restrict token creation to the local system account only - so any user or service account holding it inherits the escalation.

*Disproof:* Wrong if a lab host whose account does hold SeCreateTokenPrivilege still cannot get a child process running with S-1-5-32-544 enabled and not deny-only, or if the token can only be created by a caller that is already LocalSystem: the LocalSystem-only grant is then the escalation boundary rather than the token construction, and this hunt step is pointing at the wrong privilege. Also wrong if the child's groups show S-1-5-32-544 as Enabled while the parent already had it Enabled, since that is inheritance and not escalation.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.windows_privesc_token.auto.01` — windows_privesc_token: observe, exercise, confirm (goal: `Establish, exercise and confirm a windows_privesc_token condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who..." and "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who...

Adjacent behaviour that produces the same observable result: A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A failed potato-family run against a service account is often a filter" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be..." and "SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be...

Adjacent behaviour that produces the same observable result: SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

Not yet researched.

## Impact

**LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.**

LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.

HackTricks reference: authentication credentials uac and efs (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/authentication-credentials-uac-and-efs.md)

*Disproof:* LSASS memory cannot be read even from an elevated or SYSTEM context.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1134/>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/269.html>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648>
  - <https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/authentication-credentials-uac-and-efs.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/integrity-levels.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
