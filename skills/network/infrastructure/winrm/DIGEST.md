<!-- GENERATED from db/wks.db — do not edit -->
# WinRM and PowerShell Remoting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 12 items, 6 supported, 2 FP rules, 1 chains

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**Aliases:** winrm, wsman, powershell remoting, powershell remote, invoke command, constrained endpoint

## Technique

- **WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.**  
  `high_confidence` · score 0.8775 · disproved by: If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
  sources: <https://attack.mitre.org/techniques/T1021/006/> · <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- **In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**  
  `high_confidence` · score 0.788 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.
  sources: <https://learn.microsoft.com/en-us/windows/win32/winrm/portal> · <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**  
  `high_confidence` · score 0.747 · disproved by: Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**  
  `high_confidence` · score 0.747 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>

## Fp Rule

- **An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
- **WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.**  
  `high_confidence` · score 0.783 · disproved by: Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
  sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
