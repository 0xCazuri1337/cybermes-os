# Windows Privilege Escalation via Service and Named-Pipe Abuse

## Definition

A privileged service is induced to load or impersonate an attacker-chosen identity, so the escalation runs with SYSTEM through a legitimate service entry point.

- **CWE:** CWE-269
- **OWASP:** A04:2021
- **Surface:** ad
- **Aliases:** []

Canonical home for `windows_privesc_service`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Helpline documents CVE-2017-9362 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Helpline (official write-up, doc 180, 37202 chars, sha1 b917aad15b86) describes CVE-2017-9362. Mechanism as documented on the machine: The XML payload to read the file would be , <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///C:\Temp\Password Audit\it_logins.txt"> ]>< A PI version=' 1.0' l ocale= ' en'>

Authoritative record: ManageEngine ServiceDesk Plus before 9312 contains an XML injection at add Configuration items CMDB API.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2017-9362) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.**

Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.

HackTricks reference: service triggers (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md)

*Disproof:* The target service has no trigger registered, or the condition cannot be satisfied from the attacker's context.

**The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.**

The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.

HackTricks reference: named pipe client impersonation (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

*Disproof:* SeImpersonatePrivilege is absent, or no privileged client can be coerced to connect to a rogue pipe instance.

**Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.**

Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.

HackTricks reference: named pipe client impersonation (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

*Disproof:* The pipe server never impersonates its client, or no privileged client can reach the pipe.

**Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.**

Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.

HackTricks reference: named pipe client impersonation (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

*Disproof:* The privileged pipe is created without FILE_APPEND_DATA, or instance matching does not place the attacker's instance ahead of legitimate ones.

**Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.**

Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.

HackTricks reference: service triggers (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md)

*Disproof:* The services cannot be started by a non-privileged caller, or starting them exposes no new listeners.

## Variations

**The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.**

The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.

HackTricks reference: wts impersonator (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/stealing-credentials/wts-impersonator.md)

*Disproof:* The named pipe is absent or ACLs prevent a non-privileged caller from reaching the session enumeration and token APIs.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.windows_privesc_service.auto.01` — windows_privesc_service: observe, exercise, confirm (goal: `Establish, exercise and confirm a windows_privesc_service condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a...

Adjacent behaviour that produces the same observable result: The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or...

Adjacent behaviour that produces the same observable result: The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/269.html>
  - <https://cwe.mitre.org/data/definitions/611.html>
- **man7.org** (research)
  - <https://man7.org/linux/man-pages/man2/execve.2.html>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/stealing-credentials/wts-impersonator.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
- **services.nvd.nist.gov** (research)
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-9362>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
