# Windows Privilege Escalation via Service and Named-Pipe Abuse

> surface: `ad` · CWE: CWE-269 · OWASP: A04:2021
> maturity: **researching** — 9 items, 9 supported, 2 FP rules, 1 chains

A privileged service is induced to load or impersonate an attacker-chosen identity, so the escalation runs with SYSTEM through a legitimate service entry point.

## Technique

- **Service trigger conditions such as a named-pipe connection attempt let an attacker force a privileged service to start, so trigger conditions are themselves a service-start primitive.**  
  `high_confidence` · score 0.854 · disproved by: The target service has no trigger registered, or the condition cannot be satisfied from the attacker's context.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
- **The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the spawned process.**  
  `high_confidence` · score 0.854 · disproved by: SeImpersonatePrivilege is absent, or no privileged client can be coerced to connect to a rogue pipe instance.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
- **Any named-pipe server that a privileged client connects to can be turned into that client's privileges by calling ImpersonateNamedPipeClient, making pipe ACLs and client reachability the deciding factors.**  
  `high_confidence` · score 0.854 · disproved by: The pipe server never impersonates its client, or no privileged client can reach the pipe.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
- **Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or desynchronize their privileged IPC.**  
  `high_confidence` · score 0.854 · disproved by: The privileged pipe is created without FILE_APPEND_DATA, or instance matching does not place the attacker's instance ahead of legitimate ones.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation.md>
- **Starting dormant built-in services such as RemoteRegistry, WebClient/WebDAV or EFS creates new RPC and named-pipe listeners, so a mere service-start primitive chains into further attack surface.**  
  `high_confidence` · score 0.854 · disproved by: The services cannot be started by a non-privileged caller, or starting them exposes no new listeners.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/service-triggers.md>
- **Helpline documents CVE-2017-9362 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2017-9362) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
  sources: <https://cwe.mitre.org/data/definitions/611.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2017-9362>

## Fp Rule

- **Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.893 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
- **Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since instances are matched FIFO, receive real clients and relay or..." and "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.893 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>

## Variant

- **The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a privesc surface: it allows enumerating logged-on sessions and starting a process with a selected user's token.**  
  `high_confidence` · score 0.854 · disproved by: The named pipe is absent or ACLs prevent a non-privileged caller from reaching the session enumeration and token APIs.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/stealing-credentials/wts-impersonator.md>

## Known gaps

Not yet satisfied: `items`
