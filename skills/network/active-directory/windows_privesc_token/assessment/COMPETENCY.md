# Methodology — Windows Privilege Escalation via Token Manipulation

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class windows_privesc_token --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A low-privilege token is exchanged for a token acting as a more privileged principal, so the escalation happens in the token the process holds rather than in code execution.

**References.** CWE-269 · A09:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.**

A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.

HackTricks reference: privilege escalation abusing tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

- *Disproof:* The token already lists both privileges and the potato run still fails to yield a SYSTEM process.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

**Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.**

Integrity level is the write barrier: a process below an object's integrity level cannot modify it, so escalation must land a token at or above the target's level.

HackTricks reference: integrity levels (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/integrity-levels.md)

- *Disproof:* A medium-integrity process successfully modifies an object at high or system integrity.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/integrity-levels.md)

**Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.**

Any path that creates or associates a primary token with a process needs elevated privilege, so token-manipulation escalation can only be reached from an already-elevated or impersonation-capable context.

HackTricks reference: access tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

- *Disproof:* A non-elevated process successfully creates or associates a primary token with a process.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

**Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.**

Token impersonation is only usable when the target token belongs to the same user and its integrity level does not exceed the current process's, which bounds which tokens are worth hunting for.

HackTricks reference: privilege escalation abusing tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

- *Disproof:* A token from a different user, or one at a higher integrity level, is successfully impersonated without those conditions holding.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A token swap that starts a process under another account is recorded in Security event 4648, which carries the SID of the account that requested the new logon session separately from the account whose credentials were used, so a token-escalation hunt compares those two fields instead of trusting the parent process's access token.**

The Audit Logon subcategory emits 4648 whenever a process passes credentials explicitly instead of reusing its own token; `runas /user:` is the named case and scheduled tasks produce the same event. The record is account-level rather than process-tree-level: Subject carries the SID of the account that requested the new logon session, 'Account Whose Credentials Were Used' carries the account whose credentials were used, Target Server Name is 'localhost' when the new process ran locally, and Process ID plus Process Name name the executable that was run. Hunt rule: pull 4648, group by Process ID, and flag rows where the Subject SID differs from the credentials-used account, or where a service host such as svchost.exe is the requester. Compare that row against the 4688 Parent Process ID recorded for the same Process ID before calling it: the child keeps a legitimate parent-child lineage while executing on someone else's token, so lineage alone cannot show the swap. Verify the rule by replaying `runas /user:./netonly cmd.exe` on an auditing host and confirming the two fields diverge. The same event is also routine during normal OS activity, so the per-account baseline volume matters as much as the mismatch itself.

- *Disproof:* Wrong if replaying `runas /user:other cmd.exe` on a host with Audit Logon enabled produces no 4648 record at all, or if the Subject and the credentials-used account are always identical because the child inherited the caller's own token; then this event carries no evidence of the swap and a hunt keyed on it is chasing a routine event. Also wrong as a discriminator when scheduled-task and svchost-initiated 4648 volume on the estate exceeds the number of mismatched rows.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1134/); [learn.microsoft.com](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648)

**After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.**

After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the other account, so local identity output is not evidence of who the network traffic belongs to.

HackTricks reference: access tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

- *Disproof:* The process's local identity, groups, or integrity level also change to the alternate account.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A process holding SeCreateTokenPrivilege builds a brand-new primary token whose group SIDs it chooses instead of impersonating an existing one, so adding S-1-5-32-544 (BUILTIN\Administrators) to that token escalates privilege without ever opening a SYSTEM token handle.**

Probe with `whoami /priv` for SeCreateTokenPrivilege and, in a GPO-managed configuration, check the 'Create a token object' user right. The mechanism is token construction rather than impersonation: build a token whose group list holds the caller's own user SID plus S-1-5-32-544 enabled (not 'Group used for deny only'), duplicate it to a primary token, and launch the payload with CreateProcessAsUser or ImpersonateLoggedOnUser. No SYSTEM process has to be coerced over DCOM or NTLM and no NT AUTHORITY\SYSTEM logon SID has to be found, which is what separates this from the SeImpersonatePrivilege coercion path. Verify by comparing `whoami /groups` in the child against the parent's `whoami /priv` baseline: the escalation is confirmed only when S-1-5-32-544 shows as Enabled in the child rather than deny-only. Defence is this right specifically - Microsoft ties it to the 'Create a token object' policy and notes it cannot be added to a user account that the policy governs, while ATT&CK's mitigation for T1134 is to restrict token creation to the local system account only - so any user or service account holding it inherits the escalation.

- *Disproof:* Wrong if a lab host whose account does hold SeCreateTokenPrivilege still cannot get a child process running with S-1-5-32-544 enabled and not deny-only, or if the token can only be created by a caller that is already LocalSystem: the LocalSystem-only grant is then the escalation boundary rather than the token construction, and this hunt step is pointing at the wrong privilege. Also wrong if the child's groups show S-1-5-32-544 as Enabled while the parent already had it Enabled, since that is inheritance and not escalation.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1134/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

**A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.**

A process spawned by a compromised high-privilege process inherits that parent's primary token, so hijacking its child processes carries the parent's identity and access.

HackTricks reference: access tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

- *Disproof:* A child process launched by the privileged parent runs under a lower-privilege identity with a different primary token.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/access-tokens.md)

**SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.**

SeImpersonatePrivilege lets a process impersonate any token it can get a handle to, without ever creating one, so every reachable higher-privilege token handle is a potential escalation.

HackTricks reference: privilege escalation abusing tokens (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

- *Disproof:* No handle to a higher-privilege token can be obtained, or the privilege alone is not sufficient to open one.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens.md)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Impact

_What is actually demonstrable, and what to stop claiming._

**LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.**

LSASS is the local component that both caches hashed credentials in memory and issues access tokens, so SYSTEM-level read access there yields credential material and token leverage.

HackTricks reference: authentication credentials uac and efs (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/authentication-credentials-uac-and-efs.md)

- *Disproof:* LSASS memory cannot be read even from an elevated or SYSTEM context.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/authentication-credentials-uac-and-efs.md)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, False-positive rejection, Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
