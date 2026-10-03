---
name: winrm-hunting
description: Use when hunting WinRM and PowerShell Remoting in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# WinRM and PowerShell Remoting — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 14 items, 5 supported, 2 FP rules, 1 chains
> maturity: **mature**

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**Also called:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint


## Techniques (what to change)

- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- Post exploitation commands can be executed on the host that has been compromised through the WinRM service. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- Post exploitation commands can be executed on the host that has been compromised through the WinRM service. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
  - Sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.
  - **Disproof:** If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
- WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.
  - **Disproof:** If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>

## False-positive rules (when to reject it)

- WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.
  - **Disproof:** Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.
  - **Disproof:** Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
  - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Evidence requirements

- A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
  - Sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>

---
Full class document: `domains/network/infrastructure/winrm/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
