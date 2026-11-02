# WinRM and PowerShell Remoting

## Definition

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["winrm", "wsman", "powershell remoting", "powershell remote", "invoke command", "constrained endpoint"]

Canonical home for `winrm`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.**

What the primitive gives you: remote command execution inside the target's security context. Microsoft's Blackbyte case study records the actor using RDP and PowerShell remoting to obtain access to other servers in the environment, including domain controllers, so the WinRM session was the lateral-movement primitive rather than a code-exploit one. The precondition the next link needs is membership of the Administrators group, since PowerShell Remoting only allows connections from members of the Administrators group by default; sessions then run under the user's context so all operating system access controls apply. Observation that proves the segment: a WSMan CreateShell against the target returns a ShellId and the echoed command output is the target host's, not the local one. Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.

*Disproof:* If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.

**WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.**

WinRM is the Microsoft implementation of WS-Management, SOAP-based and firewall-friendly, and Microsoft documents it as establishing a session with a remote computer over that protocol rather than over DCOM. That distinction has a security reading: because it is HTTP, it is reachable wherever HTTP is allowed, and because it runs commands rather than only querying, it is an execution surface. Microsoft's own guidance on the protocol notes it supports management data from both Windows and non-Windows implementations, so a permissive listener is not confined to the Windows estate. The detection baseline is the TrustedHosts list plus listener configuration: WinRM configured to accept connections from hosts that should not reach it is the finding. MITRE's mitigations for the technique are correspondingly blunt — disable the service, or confine it to specific enclaves with host firewall rules and separate accounts.

*Disproof:* If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.**

Discard when the write-up claims cleartext credentials travel over 5985: per the vendor statement quoted in the research, PowerShell remoting encrypts all communication after initial authentication with a per-session AES-256 symmetric key regardless of transport. It survives when unencrypted channel allowance plus Basic authentication is configured, which does expose the credential itself.

*Disproof:* Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.

**An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.**

Discard when the only observation is that port 5985 answered: the service is enabled as part of normal server administration and the tooling notes that using it requires administrator-level credentials the tester does not hold. It survives when an authenticated remote PowerShell session was established and a command ran as SYSTEM or an administrator.

*Disproof:* Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1021/006/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/winrm-security>
  - <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2023/07/06/the-five-day-job-a-blackbyte-ransomware-intrusion-case-study/>
- **pentestlab.blog** (writeup)
  - <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/>
- **stationx.net** (writeup)
  - <https://www.stationx.net/powershell-remoting/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
