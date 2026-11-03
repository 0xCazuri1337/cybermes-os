<!-- GENERATED from db/wks.db — do not edit -->
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

**A service registry key where a non-administrator holds only KEY_CREATE_SUB_KEY cannot have its existing values edited, but creating the legacy Performance subkey with Library, Open, Collect and Close names makes the next privileged performance counter consumer load an attacker-chosen DLL inside its own process, so subkey-only write access becomes privilege escalation as NT AUTHORITY\SYSTEM.**

The payload is Microsoft's documented V1 provider registration: a Performance subkey under HKLM\SYSTEM\CurrentControlSet\Services\<service> holding Library (DLL name or full path), Open, Collect and Close, all REG_SZ. When a consumer requests performance data the system uses those values to choose which DLL to load and which exports to call, and V1 providers are implemented as a provider DLL loaded into the consumer process, so the code runs with the CONSUMER's privileges rather than the service's. Hunt: enumerate service keys for a non-admin principal holding RegistryRights CreateSubKey or AppendData/AddSubdirectory (AccessChk -k -w on RpcEptMapper, Dnscache and any other service key; the subkey does not exist by default on those services, which is why subkey-create alone suffices), create the Performance subkey with the four values, then trigger a privileged consumer - `Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' }` loads the DLL inside wmiprvse.exe as NT AUTHORITY\SYSTEM, whereas perfmon.exe only loads it in your own session. Reference: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry.md

*Disproof:* Refuted when the service key grants the caller no subkey-create right, when a `Disable Performance Counters` value already exists on that key, or when the only consumer reachable is a process the attacker already controls (perfmon run as the attacker) - the DLL has to load inside a process that is already SYSTEM for the escalation to hold.

**An endpoint agent's SYSTEM service that accepts the update server address over an unauthenticated localhost IPC channel and installs whatever MSI that server returns lets a local user redirect the service's update source, so the SYSTEM service's own installer runs attacker code as NT AUTHORITY\SYSTEM.**

No memory corruption is needed; the flaw is that a privileged service trusts an unprivileged caller about WHERE to fetch software and WHAT to trust. Chain: (1) drive the agent's localhost IPC (JSON over loopback between a low-integrity UI process and the SYSTEM service) with a provisioning or reconfiguration command whose token and config carry the rogue server address; (2) answer the endpoints the client polls - a config with a very short update interval, a PEM CA that the service installs into the Local Machine Trusted Root store, and a check-update response pointing at a fake version; (3) the service downloads the MSI into its ProgramData directory and, because it accepts any publicly-signed certificate, honours a check_msi_digest flag that can be turned off and a benign CERT_DIGEST MSI property that is never enforced, installs it as NT AUTHORITY\SYSTEM. Hunt for the pattern rather than the product: any SYSTEM service that will accept a server URL from an unprivileged IPC caller and that validates updates by public-CA signature instead of a pinned vendor chain is a candidate. Reference: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md

*Disproof:* Refuted when the agent pins its update endpoint to a fixed allow-list that refuses the rogue host, when it validates the returned package against a vendor certificate chain rather than any publicly-signed certificate, or when the IPC command needs an administrator-authenticated token: without both the redirect and the attacker-signed MSI install succeeding, the service never runs attacker code.

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

**A service object whose DACL grants a non-administrator SERVICE_CHANGE_CONFIG lets that user call ChangeServiceConfig and rewrite the service binary path the Service Control Manager runs, so the next start of that service executes attacker-chosen code as the service account.**

Two conditions, and the escalation needs both. (1) The service object DACL must carry a non-administrator ACE (Authenticated Users, Users, INTERACTIVE, or a service account) holding SERVICE_CHANGE_CONFIG, WRITE_DAC or SERVICE_ALL_ACCESS. `sc sdshow <name>` and AccessChk -c are the enumeration; the SCM documentation states that SERVICE_CHANGE_CONFIG 'grants the caller the right to change the executable file that the system runs' and 'should be granted only to administrators'. (2) With that right, `sc config <name> binpath= "<command>"` (ChangeServiceConfig) rewrites the command the Service Control Manager will run, so restarting the service launches the attacker's command under the service account, typically LocalSystem. Verify the write landed by reading back `sc qc <name>`, then trigger execution with `sc stop`/`sc start` or a reboot for an auto-start service. A rewrite the SCM refuses, or a service the caller cannot start, is not an escalation. Reference: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/README.md

*Disproof:* Refuted when `sc sdshow <service>` shows no non-administrator ACE carrying SERVICE_CHANGE_CONFIG or WRITE_DAC, or when the SCM refuses or resets the rewritten binpath: the reconfigured command must actually be the one launched under the service account, and a service that is disabled and cannot be started demonstrates no execution.

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

**SERVICE_CHANGE_CONFIG is the service access right that permits rewriting the binary path the Service Control Manager runs; a service DACL finding needs a non-administrator principal holding that right, not merely start or stop permission.**

The write primitive is the access right, not the service's presence. Microsoft defines SERVICE_CHANGE_CONFIG as the right required to call ChangeServiceConfig or ChangeServiceConfig2 and notes that it can change the executable the system runs. The HackTricks service-DACL example reaches the same conclusion for Authenticated Users holding SERVICE_ALL_ACCESS. A test should read the service security descriptor, identify the principal and the specific access mask, and then attempt ChangeServiceConfig in a lab. SERVICE_START or SERVICE_STOP alone does not rewrite the binary, so a service that a low-privileged user can start is not automatically a privilege-escalation finding.

*Disproof:* The finding fails when the non-administrator principal has only start or stop rights, when SERVICE_CHANGE_CONFIG is absent from the effective DACL, or when ChangeServiceConfig is denied despite the apparent permission.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/269.html>
  - <https://cwe.mitre.org/data/definitions/611.html>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows/win32/perfctrs/about-performance-counters>
  - <https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key>
  - <https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/stealing-credentials/wts-impersonator.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
- **services.nvd.nist.gov** (research)
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-9362>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-0309>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
