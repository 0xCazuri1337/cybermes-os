# Methodology — WinRM and PowerShell Remoting

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class winrm --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.

**References.** CWE-200

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**WinRM establishes a SOAP-over-HTTP session to a remote computer that runs commands as the authenticated user, so an exposed WinRM listener is a remote execution surface rather than only a management interface.**

WinRM is the Microsoft implementation of WS-Management, SOAP-based and firewall-friendly, and Microsoft documents it as establishing a session with a remote computer over that protocol rather than over DCOM. That distinction has a security reading: because it is HTTP, it is reachable wherever HTTP is allowed, and because it runs commands rather than only querying, it is an execution surface. Microsoft's own guidance on the protocol notes it supports management data from both Windows and non-Windows implementations, so a permissive listener is not confined to the Windows estate. The detection baseline is the TrustedHosts list plus listener configuration: WinRM configured to accept connections from hosts that should not reach it is the finding. MITRE's mitigations for the technique are correspondingly blunt — disable the service, or confine it to specific enclaves with host firewall rules and separate accounts.

- *Disproof:* If the WinRM listener is disabled, or requires HTTPS with certificate-based authentication and is restricted to an explicit TrustedHosts list that excludes untrusted hosts, then remote command execution over WinRM is not reachable.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1021/006/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/winrm/portal)

**In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers.**

ments on Lateral Movement – WinRM 
 
 

 

 

 

 
 WinRM stands for Windows Remote Management and is a service that allows administrators to perform management tasks on systems remotely. Communication is performed via HTTP (5985) or HTTPS SOAP (5986) and support Kerberos and NTLM authentication by default and Basic authentication. Usage of this service requires administrator level credentials. 
 In a red team scenario if local administrator access has been achieved then these credentials can be used for lateral movement inside the network if  WinRM is used for management of servers. 
 Discovery 
 Hosts with port 5985 open have the WinRM service running. A simple Nmap scan can be used to determine these hosts. 
 
nmap -p 5985 -sV 10.0.0.2 10.0.0.1
 
 WinRM – Port Discovery 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/winrm-port-discovery.png?w=722" class="alignnone size-full wp-image-15346" src="https://pentestlab.blog/wp-content/uploads/2018/05/winr

- *Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“In a red team scenario if local administrator access has been achieved then thes”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/winrm/portal); [pentestlab.blog](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/); [stationx.net](https://www.stationx.net/powershell-remoting/)

**Post exploitation commands can be executed on the host that has been compromised through the WinRM service.**

of-agents.png?w=760" alt="Empire - List of Agents" srcset="https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png 722w, https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png?w=150&h=65 150w, https://pentestlab.blog/wp-content/uploads/2018/05/empire-list-of-agents.png?w=300&h=130 300w" sizes="(max-width: 722px) 100vw, 722px" /> Empire – List of Agents 
 Post exploitation commands can be executed on the host that has been compromised through the WinRM service. 
 Empire – Command Execution via WinRM 
" data-large-file="https://pentestlab.blog/wp-content/uploads/2018/05/empire-command-execution-via-winrm.png?w=723" loading="lazy" class="alignnone size-full wp-image-15364" src="https://pentestlab.blog/wp-content/uploads/2018/05/empire-command-execution-via-winrm.png?w=760" alt="Empire - Command Execution via WinRM" srcset="https://pentestlab.blog/wp-conte

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Post exploitation commands can be executed on the host that has been compromised”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [pentestlab.blog](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/); [stationx.net](https://www.stationx.net/powershell-remoting/)

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

- *Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“WinRM stands for Windows Remote Management and is a service that allows administ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [pentestlab.blog](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/); [stationx.net](https://www.stationx.net/powershell-remoting/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**An open TCP 5985 listener is the PowerShell remoting default, not a WinRM exposure; the finding needs a working remote session.**

Discard when the only observation is that port 5985 answered: the service is enabled as part of normal server administration and the tooling notes that using it requires administrator-level credentials the tester does not hold. It survives when an authenticated remote PowerShell session was established and a command ran as SYSTEM or an administrator.

- *Disproof:* Would be wrong where the listener accepts anonymous or unencrypted Basic authentication, because then no credentials are needed at all.
- *Evidence:* high_confidence — [pentestlab.blog](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/); [stationx.net](https://www.stationx.net/powershell-remoting/)

**WinRM over HTTP is not a cleartext-credential finding, because the session is encrypted after initial authentication.**

Discard when the write-up claims cleartext credentials travel over 5985: per the vendor statement quoted in the research, PowerShell remoting encrypts all communication after initial authentication with a per-session AES-256 symmetric key regardless of transport. It survives when unencrypted channel allowance plus Basic authentication is configured, which does expose the credential itself.

- *Disproof:* Would be wrong for a pre-authentication handler or a third-party module that logs or proxies the Basic header itself.
- *Evidence:* high_confidence — [pentestlab.blog](https://pentestlab.blog/2018/05/15/lateral-movement-winrm/); [stationx.net](https://www.stationx.net/powershell-remoting/)

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
