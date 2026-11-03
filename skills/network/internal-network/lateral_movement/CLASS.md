<!-- GENERATED from db/wks.db — do not edit -->
# Lateral Movement

## Definition

Movement is a choice among protocols available between two hosts, so the choice depends on what is reachable and what each protocol authenticates.

- **CWE:** CWE-284
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["lateral movement", "move laterally", "pivot", "pivoting", "east west movement", "internal movement"]

Canonical home for `lateral_movement`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Lateral movement is only demonstrable when one host is already under control with valid credentials and a reachable second host exists, so observed host-to-host reachability alone is not movement.**

Windows lateral movement means navigating to and controlling remote systems, which is by definition a second step after gaining initial access on a first. Three things must be true before the claim is testable: a foothold on host A, a credential or session on A that authenticates elsewhere, and a reachable target B. Without all three, a network trace showing A talking to B is inventory or management traffic, not movement. The corollary matters for hunting: 'host A authenticated to host B' is a signal, not a finding, and it becomes a finding only once you can show the authentication used material that the operator of A should not have had, or was replayed from A without a legitimate session.

*Disproof:* If the source-to-destination authentication in question is attributable to a scheduled task, a management agent, or an interactive logon by the account's own owner with no replayed credential, then the movement hypothesis for that pair is invalidated and the class should not be raised for it.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement.**

Derived from lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (lateral_movement.fp_rule.remote_admin_session_is_expected_er_activity) states the full boundary.

## Exploitation

**This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**

isn't likely to go anywhere any time soon since Microsoft is improving and blending implementations with Azure AD. Another interesting stat to consider is that just in the last two years, Microsoft has had over 2000 reported vulnerabilities tied to a CVE . AD's many services and main purpose of making information easy to find and access make it a bit of a behemoth to manage and correctly harden. This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these misconfigurations and ease of access with common user and OS vulnerabilities, and you have a perfect storm for an attacker to take advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take advantage of their existence. We will practice enumerating AD utilizing native tools and languages such as Sysintern

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".

**This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.**

n compromise and looking for every possible path to Domain Admin level access within the testing period. Many open-source tools are available to facilitate enumerating and attacking Active Directory. To be most effective, we must understand how to perform as much of this enumeration manually as possible. More importantly, we need to understand the "why" behind certain flaws and misconfigurations. This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. 
 We need to be comfortable enumerating and attacking AD from both Windows and Linux, with a limited toolset or built-in Windows tools, also known as " living off the land ." It is common to run into situations where our tools fail, are being blocked, or we are conducting an assessment where the client has us work from a managed workstation or VDI instance instead of the customized Linux or Windo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".

**SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**

ra and Medusa, and the importance of strong password practices. It covers various attack scenarios, such as targeting SSH, FTP, and web login forms. 
 
 
 
 SQL Injection Fundamentals 
 
 
 Medium 
 
 
 17 Sections 
 
 Reward: +10 
 
 Databases are an important part of web application infrastructure and SQL (Structured Query Language) to store, retrieve, and manipulate information stored in them. SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. 
 
 
 
 SQLMap Essentials 
 
 
 Easy 
 
 
 11 Sections 
 
 Reward: +20 
 
 The SQLMap Essentials module will teach you the basics of using SQLMap to discover various types of SQL Injection vulnerabilities, all the way to the advanced enumeration of databases to retrieve all data of interest. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".

**An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**

SQLMap Essentials module will teach you the basics of using SQLMap to discover various types of SQL Injection vulnerabilities, all the way to the advanced enumeration of databases to retrieve all data of interest. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (XSS) vulnerabilities are among the most common web application vulnerabilities. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 File Inclusion 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web application vulnerability, which can be easily overlooked as part of a web application's functionality. 
 
 
 
 File Upload Attacks 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +20 
 
 Arbitrary file uploads are amo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".

**These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**

y XSS vulnerabilities and exploit them. 
 
 
 
 File Inclusion 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web application vulnerability, which can be easily overlooked as part of a web application's functionality. 
 
 
 
 File Upload Attacks 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +20 
 
 Arbitrary file uploads are among the most critical web vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. 
 
 
 
 Command Injections 
 
 
 Medium 
 
 
 12 Sections 
 
 Reward: +20 
 
 Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Se

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.

**SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**

ra and Medusa, and the importance of strong password practices. It covers various attack scenarios, such as targeting SSH, FTP, and web login forms. 
 
 
 
 SQL Injection Fundamentals 
 
 
 Medium 
 
 
 17 Sections 
 
 Reward: +10 
 
 Databases are an important part of web application infrastructure and SQL (Structured Query Language) to store, retrieve, and manipulate information stored in them. SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. 
 
 
 
 SQLMap Essentials 
 
 
 Easy 
 
 
 11 Sections 
 
 Reward: +20 
 
 The SQLMap Essentials module will teach you the basics of using SQLMap to discover various types of SQL Injection vulnerabilities, all the way to the advanced enumeration of databases to retrieve all data of interest. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".

**This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**

isn't likely to go anywhere any time soon since Microsoft is improving and blending implementations with Azure AD. Another interesting stat to consider is that just in the last two years, Microsoft has had over 2000 reported vulnerabilities tied to a CVE . AD's many services and main purpose of making information easy to find and access make it a bit of a behemoth to manage and correctly harden. This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these misconfigurations and ease of access with common user and OS vulnerabilities, and you have a perfect storm for an attacker to take advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take advantage of their existence. We will practice enumerating AD utilizing native tools and languages such as Sysintern

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".

**These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**

y XSS vulnerabilities and exploit them. 
 
 
 
 File Inclusion 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web application vulnerability, which can be easily overlooked as part of a web application's functionality. 
 
 
 
 File Upload Attacks 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +20 
 
 Arbitrary file uploads are among the most critical web vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. 
 
 
 
 Command Injections 
 
 
 Medium 
 
 
 12 Sections 
 
 Reward: +20 
 
 Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Se

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.

**An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**

SQLMap Essentials module will teach you the basics of using SQLMap to discover various types of SQL Injection vulnerabilities, all the way to the advanced enumeration of databases to retrieve all data of interest. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (XSS) vulnerabilities are among the most common web application vulnerabilities. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 File Inclusion 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web application vulnerability, which can be easily overlooked as part of a web application's functionality. 
 
 
 
 File Upload Attacks 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +20 
 
 Arbitrary file uploads are amo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".

**This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.**

n compromise and looking for every possible path to Domain Admin level access within the testing period. Many open-source tools are available to facilitate enumerating and attacking Active Directory. To be most effective, we must understand how to perform as much of this enumeration manually as possible. More importantly, we need to understand the "why" behind certain flaws and misconfigurations. This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. 
 We need to be comfortable enumerating and attacking AD from both Windows and Linux, with a limited toolset or built-in Windows tools, also known as " living off the land ." It is common to run into situations where our tools fail, are being blocked, or we are conducting an assessment where the client has us work from a managed workstation or VDI instance instead of the customized Linux or Windo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".

**Once a relay is confirmed by the attacker server's default Impacket NTLM challenge, the lateral-movement step is a session against the target's C$ or ADMIN$ share, dumping LSA secrets from Remote Registry including the computer account password.**

The technique has two ordered halves and both must be observed. The first half is confirming the relay server rather than assuming it: indications supporting capture theory include artifacts on the SMB servers pointing towards the use of the open-source Impacket toolkit, identifiable by the default NTLM server challenge of sixteen a characters and the default GUID observed in the traffic, practices uncommon in standard SMB servers. The second half is what the session buys. A successful relay attack against an SMB server establishes a session, so the attacker's next steps depend on the access the relay victim has: they could gain access to the C$ or ADMIN$ share on the relay target, dump LSA secrets from Remote Registry, including the computer account password, or move laterally via the Service Control Manager. The computer account password is the pivot that matters, because it is a domain credential that authenticates as the machine account without a user password. A common higher-order variant coerces authentication from an SCCM site server and relays it to the SCCM database server to take over the entire hierarchy, so the target selection is protocol-shaped rather than address-shaped. Detection should therefore pair the relay fingerprint on the external server with an authenticated admin-share session and a Remote Registry read on the target.

*Disproof:* The relay server shows no default challenge or GUID and no relayed session is established, meaning the coerced Type-3 was dropped by the server and no credential was reusable, so no lateral movement occurred.

**Lateral movement is a selection among the remote access protocols actually reachable between two hosts, so the movement choice is determined by reachability and each protocol's authentication model rather than by attacker preference.**

With a set of valid domain credentials, the set of hosts reachable and the protocols each one offers is what defines the movement surface — remote services including SSH and RDP are the standard carriers. Two properties make the choice non-arbitrary. First, legitimate administrative tooling already uses these same protocols, so a lateral move over SMB, WinRM or SSH is indistinguishable from software deployment at the protocol layer; MITRE notes that using legitimate credentials with native network and OS tools may be stealthier than installing an adversary tool. Second, some remote services also carry execution (WinRM, SMB), which collapses movement and execution into one step. That makes reachability inventory the prerequisite for assessing the whole class, and it makes an unexpected management protocol on a host the finding worth escalating.

*Disproof:* If no remote access protocol is reachable between the credentialed host and any other host in scope, then there is no lateral movement surface and credential reuse cannot extend beyond the current session.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ad-enum-to-kerberoast-to-lateral-execution` — Directory enumeration to SPN enumeration to kerberoasted service account to lateral execution (goal: `domain_wide_lateral_movement`)
- `reachable-admin-service-to-relayed-credential-to-lateral` — Policy-violating administrative service reachability to relayed server credentials to lateral movement (goal: `credential_theft_and_lateral`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Finding a privileged account with an active session on a host you can reach is a lookalike: the session is normally the account owner's own, not evidence of movement.**

The classic false positive is opportunistic reuse. An assessor with a foothold finds a host where their account has local administrative rights, notices a domain administrator already has a session there, and treats that as proof the admin was reached. It is not: administrators log into servers they administer as themselves, and an active session is the expected state of a managed estate. The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication. The session becomes evidence only when the ticket was extracted or replayed from your foothold host rather than issued to the admin interactively.

*Disproof:* If the privileged session's ticket was issued to the account at its normal logon station and logon time with no extraction, theft, or replay from another host, then the session reflects the owner operating their own account and the lateral-movement finding is invalidated.

**A remote logon that authenticates with valid domain or local credentials over SMB, WMI, WinRM, or RDP is expected ER and administration activity; do not file remote code execution as a finding unless the credentials were obtained in the same engagement, since the technique and the artefact are identical whether the operator is an attacker or a responder.**

The observable that triggers this false positive is remote code execution on a target host achieved with valid domain or local credentials over SMB, WMI, WinRM, or RDP, filed as lateral movement. The technique and the artefacts are byte-for-byte identical whether the operator is an attacker or an incident responder who was issued the same credential, and WMI in particular is used routinely for benign purposes, so malicious remote execution blends into legitimate remote execution by construction. The one question that decides the finding is not what was executed but where the credential came from: if it was observed being stolen in the same engagement, this is the second half of a credential-access chain; if it was issued to the tester, it is expected activity. This rule rejects the technique artefact and holds the report to that provenance question.

*Disproof:* The same session is preceded in the same engagement by credential-dumping or credential-access telemetry for that account, or the authenticating account is not one assigned to the source host's operators, which establishes that the credential was obtained by the test rather than issued to the tester.
**Hypothesis:** Lateral movement to a privileged host: a domain admin session was present on a machine my foothold account could reach
- Invalidated by: the session was the account owner operating their own account interactively from their normal station; real operators likewise reuse long-lived legitimate tickets to gain legitimate access rather than minting new authentications
- **Rejection rule:** an existing privileged session on a reachable host is a lookalike; it becomes evidence only when the ticket was extracted or replayed from another host rather than issued interactively to its owner

**Hypothesis:** A remote logon to an administrative share on a peer host is evidence of lateral movement.
- Invalidated by: The logon used valid domain credentials in the approved remote administration tooling and the identical pattern recurs across many source hosts on a scheduled cycle, so it is the sanctioned access path rather than a pivot; no credential was reused from memory or dump.
- **Rejection rule:** A remote administrative session carrying valid credentials in the sanctioned tool is expected ER activity, not lateral movement. Lateral movement requires either a credential the session could not legitimately hold, or a protocol path outside the approved administration profile.

## Validation

**To decide this case, observe: The same logic applies on the attacker side of the argument - a real operator also reuses long-lived legitimate Kerberos tickets to gain legitimate access to target resources rather than creating new authentication.**

Derived from lateral_movement.fp_rule.existing-admin-session-on-reachable-host, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (lateral_movement.fp_rule.existing-admin-session-on-reachable-host) states the full boundary.

**Lateral movement is proven by a successful action on a second host using credentials obtained in the engagement, not by the protocol used; SSH, RDP, SMB, WMI, and WinRM are interchangeable carriers once reachability and credentials exist.**

The protocol is a transport choice, not the finding. MITRE describes the same behavior across remote-access protocols: valid domain credentials let an adversary log in to many machines through SSH or RDP, and the same logic applies to SMB, WMI, and WinRM when those services are reachable. The test therefore records three facts: the source host, the credential's provenance, and the action performed on the destination. A remote logon from an attacker-controlled host using a credential obtained during the engagement is movement. A support console using its own local account is administration even when it uses the same protocol.

*Disproof:* The movement finding fails when the supposed destination action used a pre-existing tester account with no engagement-derived credential, when the action ran only on the original host, or when the destination was never reached and only a protocol banner was observed.

**PsExec-style SMB lateral movement is demonstrated by remote process execution on the destination, not by an SMB session or a share mount; PsExec executes processes on other systems over an authenticated SMB/RPC path.**

Observe a remote process creation on the destination under the engagement credential: a service creation, a scheduled task, or an equivalent SMB/RPC execution primitive. An SMB session to IPC$ or a mounted C$ or ADMIN$ share only proves reachability and share access; it does not show that a process ran. Correlate the destination process-creation event with the source's SMB/RPC session and the service name or command line. A successful PsExec run is evidenced by the remote process and its output, not by the SMB tree connect alone.

*Disproof:* A benign backup, software deployment, or administrative script can create an SMB session and a remote service. Reject the finding unless the remote execution used credentials obtained in the engagement and the action is outside the destination's normal administrative baseline.

**An exposed RDP port is not lateral movement; RDP/RDS expands access only when the service is enabled and allows access to accounts with known credentials, so the finding requires an authenticated remote session or action.**

A TCP 3389 listener or an RDP handshake is reachability, not movement. Establish an authenticated session with the engagement credential and capture a destination-side action: an interactive logon, process start, file transfer, or clipboard or drive redirection. Record the source, destination, account, and session identifier. If only the port is open, classify it as exposed_services or external_recon, not lateral movement.

*Disproof:* RDP is a normal administrative and remote-work service. An open 3389 port, a certificate, or a logon screen is not evidence of unauthorized movement; the authenticated session and the credential provenance are the finding.

**An open WinRM port is not lateral movement; WinRM is a protocol for interacting with a remote system, and the finding requires an authenticated operation that runs a command, modifies the registry, or changes a service on the destination.**

A TCP 5985 or 5986 listener or a successful WS-Management handshake proves only that the service is reachable. To establish movement, capture an authenticated WinRM operation that changes state on the destination: a process start, registry write, service change, or command output. Distinguish the listener from the operation; a port scan result or an HTTP response on /wsman is not execution. Record the source, destination, principal, operation, and any child process on the destination.

*Disproof:* WinRM is a standard Windows management service. A listener on 5985 is common in managed fleets and is not, by itself, evidence of compromise. The operation and its principal must be tied to the engagement and outside the destination baseline.

**WMI lateral movement is demonstrated by remote WMI execution on the destination, not by the presence of the WMI service; WMI is both a local and remote management interface, so remote use is a legitimate administrative pattern as well as an adversary technique.**

Capture a remote WMI operation on the destination, such as Win32_Process.Create, an event subscription, or a service change, and identify the client process and principal. A running Winmgmt service or an open RPC port is not execution. Correlate wmiprvse.exe child processes and the RPC/DCOM or WinRM session with the source. Because WMI is a normal management interface, compare the operation and account with the destination baseline before calling it movement.

*Disproof:* Management tools and endpoint agents routinely use remote WMI. A wmiprvse.exe process or a port 135 or 5985 connection is not a finding without a state-changing operation tied to the engagement.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1021/>
  - <https://attack.mitre.org/techniques/T1021/001/>
  - <https://attack.mitre.org/techniques/T1021/002/>
  - <https://attack.mitre.org/techniques/T1021/006/>
  - <https://attack.mitre.org/techniques/T1047/>
- **helpnetsecurity.com** (news)
  - <https://www.helpnetsecurity.com/2025/07/04/ntlm-relay-attacks/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security/credential-access-and-credential-dumping/network-vs-interactive-logons.md>
  - <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/sysinternals/downloads/psexec>
  - <https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/welcome-to-rds>
  - <https://learn.microsoft.com/en-us/windows/win32/winrm/portal>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4251.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
