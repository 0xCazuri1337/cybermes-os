# WinRM and PowerShell Remoting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 12 items, 6 supported, 2 FP rules, 1 chains

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**Aliases:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint

## Prerequisite

- **A valid domain credential is not sufficient for WinRM remote execution; by default the principal must be a member of the target's Administrators group, and a local administrator credential is only useful where the same account exists on the target.**  
  `under_review` · score 0.808 · disproved by: The WinRM access finding fails when the credential authenticates but the principal is not in the target's Administrators group, or when the local administrator account does not exist on the destination with the same password.
  sources: <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>

## Technique

- **WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.**  
  `high_confidence` · score 0.8775 · disproved by: If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- **A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.**  
  `under_review` · score 0.854 · disproved by: If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
- **In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**  
  `high_confidence` · score 0.788 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**  
  `high_confidence` · score 0.747 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.**  
  `under_review` · score 0.747 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**  
  `high_confidence` · score 0.747 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Test

- **An open TCP 5985 or 5986 listener is not a WinRM finding; proof requires a WSMan session that executes a command as the authenticated user and returns target-specific output.**  
  `under_review` · score 0.838 · disproved by: The WinRM finding fails when the client only opened TCP 5985/5986 or received a protocol banner, and no authenticated WSMan session executed a command on the target.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>

## Fp Rule

- **An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.**  
  `high_confidence` · score 0.783 · disproved by: Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Evidence

- **A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.**  
  `under_review` · score 0.838 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>

## Bypass

- **A local administrator credential from the source host can be reused for WinRM only when the same local account and password exist on the target; a domain credential is not required, but unique local administrator passwords break the hop.**  
  `under_review` · score 0.783 · disproved by: The reuse finding fails when the destination has a different local administrator password, when the account does not exist on the destination, or when the authentication succeeds only with a domain credential rather than the reused local account.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
