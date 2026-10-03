# WinRM and PowerShell Remoting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 15 items, 15 supported, 2 FP rules, 1 chains

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**Aliases:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint

## Technique

- **WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.**  
  `high_confidence` · score 0.8775 · disproved by: If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- **A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.**  
  `high_confidence` · score 0.854 · disproved by: If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
- **In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Upon exploitation the module will attempt to modify the PowerShell execution policy to all".
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- **From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- **WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- **In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In a red team scenario if local administrator access has been achieved then these credenti".
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Post exploitation commands can be executed on the host that has been compromised through t".
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "From a system that has already local administrator access and these privileges are shared ".
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "WinRM stands for Windows Remote Management and is a service that allows administrators to ".
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Upon exploitation the module will attempt to modify the PowerShell execution policy to all".
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Fp Rule

- **An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.**  
  `high_confidence` · score 0.783 · disproved by: Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
