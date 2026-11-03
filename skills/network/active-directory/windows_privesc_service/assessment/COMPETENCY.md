# Methodology — Windows Privilege Escalation via Service and Named-Pipe Abuse

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class windows_privesc_service --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A privileged service is induced to load or impersonate an attacker-chosen identity, so the escalation runs with SYSTEM through a legitimate service entry point.

**References.** CWE-269 · A04:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An endpoint agent's SYSTEM service that accepts the update server address over an unauthenticated localhost IPC channel and installs whatever MSI that server returns lets a local user redirect the service's update source, so the SYSTEM service's own installer runs attacker code as NT AUTHORITY\SYSTEM.**

No memory corruption is needed; the flaw is that a privileged service trusts an unprivileged caller about WHERE to fetch software and WHAT to trust. Chain: (1) drive the agent's localhost IPC (JSON over loopback between a low-integrity UI process and the SYSTEM service) with a provisioning or reconfiguration command whose token and config carry the rogue server address; (2) answer the endpoints the client polls - a config with a very short update interval, a PEM CA that the service installs into the Local Machine Trusted Root store, and a check-update response pointing at a fake version; (3) the service downloads the MSI into its ProgramData directory and, because it accepts any publicly-signed certificate, honours a check_msi_digest flag that can be turned off and a benign CERT_DIGEST MSI property that is never enforced, installs it as NT AUTHORITY\SYSTEM. Hunt for the pattern rather than the product: any SYSTEM service that will accept a server URL from an unprivileged IPC caller and that validates updates by public-CA signature instead of a pinned vendor chain is a candidate. Reference: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md

- *Disproof:* Refuted when the agent pins its update endpoint to a fixed allow-list that refuses the rogue host, when it validates the returned package against a vendor certificate chain rather than any publicly-signed certificate, or when the IPC command needs an administrator-authenticated token: without both the redirect and the attacker-signed MSI install succeeding, the service never runs attacker code.
- *Evidence:* high_confidence — [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/abusing-auto-updaters-and-ipc.md); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2025-0309)

**A service registry key where a non-administrator holds only KEY_CREATE_SUB_KEY cannot have its existing values edited, but creating the legacy Performance subkey with Library, Open, Collect and Close names makes the next privileged performance counter consumer load an attacker-chosen DLL inside its own process, so subkey-only write access becomes privilege escalation as NT AUTHORITY\SYSTEM.**

The payload is Microsoft's documented V1 provider registration: a Performance subkey under HKLM\SYSTEM\CurrentControlSet\Services\<service> holding Library (DLL name or full path), Open, Collect and Close, all REG_SZ. When a consumer requests performance data the system uses those values to choose which DLL to load and which exports to call, and V1 providers are implemented as a provider DLL loaded into the consumer process, so the code runs with the CONSUMER's privileges rather than the service's. Hunt: enumerate service keys for a non-admin principal holding RegistryRights CreateSubKey or AppendData/AddSubdirectory (AccessChk -k -w on RpcEptMapper, Dnscache and any other service key; the subkey does not exist by default on those services, which is why subkey-create alone suffices), create the Performance subkey with the four values, then trigger a privileged consumer - `Get-WmiObject -List | Where-Object { $_.Name -like 'Win32_Perf*' }` loads the DLL inside wmiprvse.exe as NT AUTHORITY\SYSTEM, whereas perfmon.exe only loads it in your own session. Reference: https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry.md

- *Disproof:* Refuted when the service key grants the caller no subkey-create right, when a `Disable Performance Counters` value already exists on that key, or when the only consumer reachable is a process the attacker already controls (perfmon run as the attacker) - the DLL has to load inside a process that is already SYSTEM for the escalation to hold.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/perfctrs/creating-the-applications-performance-key); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/appenddata-addsubdirectory-permission-over-service-registry.md)

**Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.**

Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.

HackTricks reference: service triggers (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md)

- *Disproof:* The target service has no trigger registered, or the condition cannot be satisfied from the attacker's context.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md)

**The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.**

The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.

HackTricks reference: named pipe client impersonation (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

- *Disproof:* SeImpersonatePrivilege is absent, or no privileged client can be coerced to connect to a rogue pipe instance.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

**Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.**

Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.

HackTricks reference: named pipe client impersonation (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

- *Disproof:* The pipe server never impersonates its client, or no privileged client can reach the pipe.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

**Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.**

Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.

HackTricks reference: named pipe client impersonation (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

- *Disproof:* The privileged pipe is created without FILE_APPEND_DATA, or instance matching does not place the attacker's instance ahead of legitimate ones.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md)

**Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.**

Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.

HackTricks reference: service triggers (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md)

- *Disproof:* The services cannot be started by a non-privileged caller, or starting them exposes no new listeners.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a...

Adjacent behaviour that produces the same observable result: The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)

**Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or...

Adjacent behaviour that produces the same observable result: The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
