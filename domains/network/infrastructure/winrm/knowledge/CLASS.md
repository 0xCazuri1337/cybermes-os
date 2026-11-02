# WinRM and PowerShell Remoting

## Definition

PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["winrm", "wsman", "powershell remoting", "powershell remote", "invoke command", "constrained endpoint"]

Canonical home for `winrm`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A valid domain credential is not sufficient for WinRM remote execution; by default the principal must be a member of the target's Administrators group, and a local administrator credential is only useful where the same account exists on the target.**

WinRM authorization is separate from authentication. Microsoft's WinRM security guidance states that PowerShell Remoting only allows connections from members of the Administrators group by default, so a valid domain user who is not a local administrator on the destination receives an access-denied result even though the credential authenticated. The local-administrator case is narrower still: the credential must correspond to an account that exists on the destination with the same password, which is why unique local administrator passwords break the hop. Record both the authentication result and the authorization result; only the latter proves remote execution.

*Disproof:* The WinRM access finding fails when the credential authenticates but the principal is not in the target's Administrators group, or when the local administrator account does not exist on the destination with the same password.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.**

Derived from winrm.technique.winrm_remoting_is_the_lateral_execution_channel, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (winrm.technique.winrm_remoting_is_the_lateral_execution_channel) states the full boundary.

## Exploitation

**In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**

ments on Lateral Movement – WinRM 
 
 

 

 

 

 
 WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. Communication is performed via HTTP (5985) or HTTPS SOAP (5986) and support Kerberos and NTLM authentication by default and Basic authentication. Usage of this service requires administrator level credentials. 
 In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. 
 Discovery 
 Hosts with port 5985 open have the WinRM service running. A simple Nmap scan can be used to determine these hosts. 
 
nmap -p 5985 -sV 10.0.0.2 10.0.0.1
 
 WinRM – Port Discovery 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-port-discovery.png?w=722" class="alignnone size-full wp-image-15346" src="https://pentestlab.blog/wp-content/uploads/2018/05/winr

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.

**In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**

ments on Lateral Movement – WinRM 
 
 

 

 

 

 
 WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. Communication is performed via HTTP (5985) or HTTPS SOAP (5986) and support Kerberos and NTLM authentication by default and Basic authentication. Usage of this service requires administrator level credentials. 
 In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. 
 Discovery 
 Hosts with port 5985 open have the WinRM service running. A simple Nmap scan can be used to determine these hosts. 
 
nmap -p 5985 -sV 10.0.0.2 10.0.0.1
 
 WinRM – Port Discovery 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-port-discovery.png?w=722" class="alignnone size-full wp-image-15346" src="https://pentestlab.blog/wp-content/uploads/2018/05/winr

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.

**Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**

of-agents.png?w=760" alt="Empire - List of Agents" srcset="https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png 722w, https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png?w=150&h=65 150w, https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png?w=300&h=130 300w" sizes="(max-width: 722px) 100vw, 722px" /> Empire – List of Agents 
 Post exploitation commands can be executed on the host that has been compromised through the WinRM service. 
 Empire – Command Execution via WinRM 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/empire-command-execution-via-winrm.png?w=723" loading="lazy" class="alignnone size-full wp-image-15364" src="https://pentestlab.blog/wp-content/uploads/2018/05/empire-command-execution-via-winrm.png?w=760" alt="Empire - Command Execution via WinRM" srcset="https://pentestlab.blog/wp-conte

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.

**Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**

of-agents.png?w=760" alt="Empire - List of Agents" srcset="https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png 722w, https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png?w=150&h=65 150w, https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png?w=300&h=130 300w" sizes="(max-width: 722px) 100vw, 722px" /> Empire – List of Agents 
 Post exploitation commands can be executed on the host that has been compromised through the WinRM service. 
 Empire – Command Execution via WinRM 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/empire-command-execution-via-winrm.png?w=723" loading="lazy" class="alignnone size-full wp-image-15364" src="https://pentestlab.blog/wp-content/uploads/2018/05/empire-command-execution-via-winrm.png?w=760" alt="Empire - Command Execution via WinRM" srcset="https://pentestlab.blog/wp-conte

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.

**From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.**

ps://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png?w=760" alt="WinRM - Ports" srcset="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png 724w, https://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png?w=150&h=64 150w, https://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png?w=300&h=128 300w" sizes="(max-width: 724px) 100vw, 724px" /> WinRM – Ports 
 From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. 
 
Invoke-Command -ComputerName TARGET -ScriptBlock { dir c:\ }
 
 WinRM – Command Execution 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-command-execution.png?w=760" loading="lazy" class="alignnone size-full wp-image-15348" src="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-command-execution.png?w=760" alt="WinRM - Command Execution" srcset="https://pen

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.

**From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service.**

ps://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png?w=760" alt="WinRM - Ports" srcset="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png 724w, https://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png?w=150&h=64 150w, https://pentestlab.blog/wp-content/uploads/2018/05/winrm-ports.png?w=300&h=128 300w" sizes="(max-width: 724px) 100vw, 724px" /> WinRM – Ports 
 From a system that has already local administrator access and these privileges are shared with the target system the PowerShell Invoke-Command can be used for command execution over the WinRM service. 
 
Invoke-Command -ComputerName TARGET -ScriptBlock { dir c:\ }
 
 WinRM – Command Execution 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-command-execution.png?w=760" loading="lazy" class="alignnone size-full wp-image-15348" src="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-command-execution.png?w=760" alt="WinRM - Command Execution" srcset="https://pen

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“From a system that has already local administrator access and these privileges a”) does not occur under a test that isolates that control.

**WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**

ies 
 
 Red Teaming 
 
 Credential Access 
 Persistence 
 
 
 
 
 Resources 
 
 Papers 
 
 Web Application 
 
 
 Presentations 
 
 Defcon 
 DerbyCon 
 Tools 
 
 
 Videos 
 
 BSides 
 Defcon 
 DerbyCon 
 Hack In Paris 
 
 
 
 
 Contact 
 
 About Us 
 
 
 
 
 
 
 Posted on May 15, 2018 Lateral Movement – WinRM by Administrator . In Red Team . 6 Comments on Lateral Movement – WinRM 
 
 

 

 

 

 
 WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. Communication is performed via HTTP (5985) or HTTPS SOAP (5986) and support Kerberos and NTLM authentication by default and Basic authentication. Usage of this service requires administrator level credentials. 
 In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of serve

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.

**WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**

ies 
 
 Red Teaming 
 
 Credential Access 
 Persistence 
 
 
 
 
 Resources 
 
 Papers 
 
 Web Application 
 
 
 Presentations 
 
 Defcon 
 DerbyCon 
 Tools 
 
 
 Videos 
 
 BSides 
 Defcon 
 DerbyCon 
 Hack In Paris 
 
 
 
 
 Contact 
 
 About Us 
 
 
 
 
 
 
 Posted on May 15, 2018 Lateral Movement – WinRM by Administrator . In Red Team . 6 Comments on Lateral Movement – WinRM 
 
 

 

 

 

 
 WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. Communication is performed via HTTP (5985) or HTTPS SOAP (5986) and support Kerberos and NTLM authentication by default and Basic authentication. Usage of this service requires administrator level credentials. 
 In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of serve

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.

**WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely.**

ies 
 
 Red Teaming 
 
 Credential Access 
 Persistence 
 
 
 
 
 Resources 
 
 Papers 
 
 Web Application 
 
 
 Presentations 
 
 Defcon 
 DerbyCon 
 Tools 
 
 
 Videos 
 
 BSides 
 Defcon 
 DerbyCon 
 Hack In Paris 
 
 
 
 
 Contact 
 
 About Us 
 
 
 
 
 
 
 Posted on May 15, 2018 Lateral Movement – WinRM by Administrator . In Red Team . 6 Comments on Lateral Movement – WinRM 
 
 

 

 

 

 
 WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. Communication is performed via HTTP (5985) or HTTPS SOAP (5986) and support Kerberos and NTLM authentication by default and Basic authentication. Usage of this service requires administrator level credentials. 
 In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of serve

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.

**Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts.**

nrm-code-execution-module-configuration.png 671w, https://pentestlab.blog/wp-content/uploads/2018/05/metasploit-winrm-code-execution-module-configuration.png?w=150&h=38 150w, https://pentestlab.blog/wp-content/uploads/2018/05/metasploit-winrm-code-execution-module-configuration.png?w=300&h=75 300w" sizes="(max-width: 671px) 100vw, 671px" /> Metasploit – WinRM Code Execution Module Configuration 
 Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts. Then a PowerShell script will be written into disk and executed automatically in order to return a Meterpreter session. The module will also attempt to migrate into a SYSTEM level process to avoid loss of the shell due to time limit restriction of WinRS. 
 Metasploit – WinRM Code Execution 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/metasploit-winrm-code-execution.png?w

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Upon exploitation the module will attempt to modify the PowerShell execution policy to all".

**Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts.**

nrm-code-execution-module-configuration.png 671w, https://pentestlab.blog/wp-content/uploads/2018/05/metasploit-winrm-code-execution-module-configuration.png?w=150&h=38 150w, https://pentestlab.blog/wp-content/uploads/2018/05/metasploit-winrm-code-execution-module-configuration.png?w=300&h=75 300w" sizes="(max-width: 671px) 100vw, 671px" /> Metasploit – WinRM Code Execution Module Configuration 
 Upon exploitation the module will attempt to modify the PowerShell execution policy to allow execution of unsigned scripts. Then a PowerShell script will be written into disk and executed automatically in order to return a Meterpreter session. The module will also attempt to migrate into a SYSTEM level process to avoid loss of the shell due to time limit restriction of WinRS. 
 Metasploit – WinRM Code Execution 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/metasploit-winrm-code-execution.png?w

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Upon exploitation the module will attempt to modify the PowerShell execution policy to all".

**A WSMan listener is a complete authenticated remote-execution channel, so a stolen domain credential is consumed by creating a PowerShell Remoting session on the next host rather than by exploiting anything on that host.**

What the primitive gives you: remote command execution inside the target's security context. Microsoft's Blackbyte case study records the actor using RDP and PowerShell remoting to obtain access to other servers in the environment, including domain controllers, so the WinRM session was the lateral-movement primitive rather than a code-exploit one. The precondition the next link needs is membership of the Administrators group, since PowerShell Remoting only allows connections from members of the Administrators group by default; sessions then run under the user's context so all operating system access controls apply. Observation that proves the segment: a WSMan CreateShell against the target returns a ShellId and the echoed command output is the target host's, not the local one. Note that WinRM encrypts traffic after initial authentication regardless of HTTP or HTTPS, so the observable is the listener exchange, not cleartext commands.

*Disproof:* If the target has no WSMan listener, or the account is not in the local Administrators group and no JEA or group-delegated remoting is configured, CreateShell fails with an authorization error and there is no execution channel, however valid the credential is.

**WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.**

WinRM is the Microsoft implementation of WS-Management, SOAP-based and firewall-friendly, and Microsoft documents it as establishing a session with a remote computer over that protocol rather than over DCOM. That distinction has a security reading: because it is HTTP, it is reachable wherever HTTP is allowed, and because it runs commands rather than only querying, it is an execution surface. Microsoft's own guidance on the protocol notes it supports management data from both Windows and non-Windows implementations, so a permissive listener is not confined to the Windows estate. The detection baseline is the TrustedHosts list plus listener configuration: WinRM configured to accept connections from hosts that should not reach it is the finding. MITRE's mitigations for the technique are correspondingly blunt — disable the service, or confine it to specific enclaves with host firewall rules and separate accounts.

*Disproof:* If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.

## Variations

**A local administrator credential from the source host can be reused for WinRM only when the same local account and password exist on the target; a domain credential is not required, but unique local administrator passwords break the hop.**

Local administrator reuse is a credential-matching condition, not a universal bypass. When the source host's local administrator password is shared with the destination, Invoke-Command can authenticate over WinRM and execute commands on the target. The same test over a target with a different local administrator password fails even though the account name and group membership match. The operator should therefore test the credential on the destination rather than assuming that local administrator on host A implies local administrator on host B, and should record the destination's local account identity in the evidence.

*Disproof:* The reuse finding fails when the destination has a different local administrator password, when the account does not exist on the destination, or when the authentication succeeds only with a domain credential rather than the reused local account.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.winrm.auto.01` — winrm: observe, exercise, confirm (goal: `Establish, exercise and confirm a winrm condition on an authorised target without relying on anyone else's data.`)

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

**An open TCP 5985 or 5986 listener is not a WinRM finding; proof requires a WSMan session that executes a command as the authenticated user and returns target-specific output.**

Port discovery and remote execution are separate observations. A host with 5985 open has the WinRM service listening, but the service can still reject the credential, the principal can lack the required group membership, or the WSMan configuration can disable the session. MITRE describes WinRM as a protocol that lets a user interact with a remote system, including running an executable and modifying services; that interaction is the finding. Use Test-WSMan for protocol reachability, then Invoke-Command or an equivalent client to run a benign command and capture target-specific output such as the hostname or a unique marker. A listener alone is only an exposure signal.

*Disproof:* The WinRM finding fails when the client only opened TCP 5985/5986 or received a protocol banner, and no authenticated WSMan session executed a command on the target.

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
