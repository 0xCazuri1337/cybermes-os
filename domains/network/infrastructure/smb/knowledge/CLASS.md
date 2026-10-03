# SMB/CIFS Abuse

## Definition

SMB carries authentication, file access and remote execution, and its signing configuration decides whether a captured authentication can be relayed.

- **CWE:** CWE-732
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["smb", "cifs", "null session", "guest session", "smb signing", "smb1", "named pipe coercion", "share enumeration", "psexec"]

Canonical home for `smb`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable that triggers this false positive is a share enumeration against an internal Windows host returning C$, ADMIN$ and IPC$ - names that appear on essentially every domain-joined machine because the Lanman Server enables them so that administrators and management software can drive hosts remotely over SMB.**

Derived from smb.fp_rule.admin_shares_present_is_default_windows, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (smb.fp_rule.admin_shares_present_is_default_windows) states the full boundary.

## Exploitation

**For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.**

ls of the assessment. The tools listed above will be covered in other modules. 
 
 Next Steps 
 During this module, we will target a fictional company called INLANEFREIGHT with the internal domain INLANEFREIGHT.LOCAL . The module sections will build on each other, culminating in a mock penetration testing skills assessment to showcase our skills before moving on to the next module in this series. For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement. 
 
 Module Exercises 
 Throughout this module, you will connect to various target hosts via the Remote Desktop Protocol (RDP) to complete the exercises. Any necessary credentials will be provided with each exercise, and the RDP connection can be made via xfreerdp from the Pwnbox as follows: 
 xfreerdp /v: /u:htb-student /p: 
 
 Any necessary tools can be found in the c:\tools directory after logg

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".

**Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**

his covers common methods while emphasizing real-world misconfigurations and flaws that we may encounter during an assessment. There are many additional "edge-case" possibilities not covered in this module. We will cover both modern and legacy Windows Server and Desktop versions that may be present in a client environment. 
 
 
 
 Kerberos Attacks 
 
 
 Hard 
 
 
 23 Sections 
 
 Reward: +100 
 
 Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. Due to its prevalence throughout an Active Directory environment, it presents us with a significant attack surface when assessing internal networks. This module will explain how Kerberos works thoroughly and examines several scenarios to practice the most common attacks against it from multiple perspectives. 
 
 
 
 NTLM Relay Attacks 
 
 
 Hard 
 
 
 10 Sections 
 
 Reward: +100 
 
 The NTLM aut

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".

**Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**

indows and Active Directory, defining and enforcing access to the various system resources. This mini-module will cover enumerating and attacking common DACL misconfigurations, allowing us to escalate our privileges horizontally and vertically and move laterally across an Active Directory network. 
 
 
 
 Stack-Based Buffer Overflows on Linux x86 
 
 
 Medium 
 
 
 13 Sections 
 
 Reward: +10 
 
 Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. These vulnerabilities are caused by insecure coding, resulting in an attacker being able to overrun a program's buffer and overwrite adjacent memory locations, changing the program's execution path and resulting in unintended actions. 
 
 
 
 Stack-Based Buffer Overflows on Windows x86 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 This module is your first step into Windows Binary Exploitati

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".

**We will discuss how to identify, exploit, and prevent TLS attacks.**

s attack scenarios, such as targeting SSH, FTP, and web login forms. 
 
 
 
 HTTPs/TLS Attacks 
 
 
 Medium 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module covers details on Transport Layer Security (TLS) and how it helps to make HTTP secure with the widely used HTTPS. That includes how TLS works, how TLS sessions are established, common TLS misconfigurations, as well as famous attacks on TLS. We will discuss how to identify, exploit, and prevent TLS attacks. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (XSS) vulnerabilities are among the most common web application vulnerabilities. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. This mo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".

**An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**

widely used HTTPS. That includes how TLS works, how TLS sessions are established, common TLS misconfigurations, as well as famous attacks on TLS. We will discuss how to identify, exploit, and prevent TLS attacks. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (XSS) vulnerabilities are among the most common web application vulnerabilities. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 Session Security 
 
 
 Medium 
 
 
 14 Sections 
 
 Reward: +20 
 
 Maintaining and keeping track of a user's session is an integral part of web applications. It is an area that requires extensive testing to ensure it is set up robustly and securely. This module covers the most common attacks and vulnerabilit

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".

**This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**

compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 Session Security 
 
 
 Medium 
 
 
 14 Sections 
 
 Reward: +20 
 
 Maintaining and keeping track of a user's session is an integral part of web applications. It is an area that requires extensive testing to ensure it is set up robustly and securely. This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. 
 
 
 
 SQL Injection Fundamentals 
 
 
 Medium 
 
 
 17 Sections 
 
 Reward: +10 
 
 Databases are an important part of web application infrastructure and SQL (Structured Query Language) to store, retrieve, and manipulate information stored in them. SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass aut

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".

**Anonymous or guest access to an SMB share, and the enumeration that reveals it, is the usual route to credentials or a file drop on a Windows target.**

In practice on HTB this shows up as: | `crackmapexec smb <FQDN/IP> --shares -u '' -p ''`                              | Enumerating SMB shares using null session authentication.  |
| `enum4linux-ng <FQDN/IP> -A`                                                   | **SMB enumeration using enum4linux-ng in aggressive mode** |
| `smb: \> tarmode`<br>`smb: \> recurse`<br>`smb: \> prompt`<br>`smb: \> mget *` | Download all files in smbclient                            |
| `netexec smb 10.10.11.35 -u 'guest' -p '' --rid-brute`                         | RID Brute (users)                                          |
Mount a SMB server in Linux: `sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance`

Write-up provenance: ajcriado/htb-writeups :: Cheatsheets/Mix-OSCP-CPTS/Footprinting Services.md (2508 words, classified network).

*Disproof:* Refuted when the share requires authentication and rejects guest/anonymous sessions, and no share permits a write, so the share yields neither credentials nor a file drop.

**SMB is not only file transfer: an authenticated SMB session is a remote execution channel, which is why administrative shares are worth more to an adversary than the data on them.**

Because SMB carries file access, remote procedure calls and remote execution over one authenticated session, a share write is a staging step rather than an endpoint — the file lands and something else runs it. ATT&CK names the executions that ride the same authenticated SMB/RPC session: scheduled task, service execution and WMI. That changes the priority order for hunting: a host that writes a file to a remote administrative share and a host that then connects to create a service on that target are one incident, not two. NetBIOS is the naming and transport layer underneath, which is why the original NetBIOS-over-TCP specification still matters for understanding why a name resolution answer can direct a client to the adversary's listener. The practical control is signing: where SMB signing is not required, an intercepted or coerced authentication is reusable; where it is required, the relay and coercion variants close even though the file transfer does not.

*Disproof:* If the target host requires SMB signing and has no administrator shares exposed, then a captured or coerced SMB authentication cannot be relayed or used for remote execution and only ordinary file access is possible.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `reachable-admin-service-to-relayed-credential-to-lateral` — Policy-violating administrative service reachability to relayed server credentials to lateral movement (goal: `credential_theft_and_lateral`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Hidden administrative shares (C$, ADMIN$, IPC$) answering on tcp/445 inside the corporate network are the DEFAULT Windows configuration, not an exposed-share vulnerability; do not file their existence as a finding unless the share is reachable from outside the assessed scope boundary or is created outside the default set (a custom share, a webroot share, or a share added by an operator).**

The observable that triggers this false positive is a share enumeration against an internal Windows host returning C$, ADMIN$ and IPC$ - names that appear on essentially every domain-joined machine because the Lanman Server enables them so that administrators and management software can drive hosts remotely over SMB. Nothing was misconfigured and nothing was disclosed beyond what the host must expose to operate inside a corporate network. The distinction that decides the report is reachability, not existence: an administrative share answered from a host inside the assessed boundary is expected, whereas the same share answered from the public internet, or a share that is not one of the default administrative shares (a custom data share, a webroot such as \\inetpub\\wwwroot, or a share an operator created during deployment), means somebody chose to expose it. So this rule rejects the share-presence observation and asks for the boundary or the non-default name before anything is filed.

*Disproof:* The same share is reachable from a host outside the assessed scope boundary (for example the public internet or a partner network), or the share name is not one of the Windows default administrative shares - a custom data share, an IIS webroot such as \inetpub\wwwroot, or a share created by an operator during deployment - which means somebody chose to expose it.

**SMB traffic originating from a built-in Windows redirection feature or a living-off-the-land tooling pattern is a lookalike and is legitimately not attacker-driven pivoting.**

Two shapes get flagged wrongly. First, netsh interface portproxy is a supported Windows redirection facility: a listen port on one interface forwarding to a different address and port, in the observed case a web port forwarded to 445. That is a documented administrative feature and it produces exactly the traffic shape an assessor reads as an SMB pivot. Second, enumeration and exploitation toolkits deliberately live off the land by abusing built-in AD protocols such as SMB, WMI and WinRM, so an SMB session from a management workstation is often the toolkit doing its job rather than an intruder. Before calling either case lateral movement, establish who configured the redirection, from what management context it was created, and whether the SMB peer is in the tool's documented target list.

*Disproof:* If the portproxy entry is present in the system's own configuration with a documented change owner and a legitimate reason (application load balancer, legacy app redirect), and the SMB peer matches that application's backend, then the traffic is administrative redirection and not attacker pivoting.

**SMB signing not required is only exploitable when a victim that can be coerced also has admin reach to an unsigned target.**

Discard when a scan reported Message signing enabled but not required and nothing was relayed: the BloodHound edge only covers victims with admin access to an unsigned target, and Rapid7 recorded an engagement where signing being not required could not be leveraged at all. It survives when a coerced authentication was actually relayed and authenticated on the second host.

*Disproof:* Would be wrong where the environment has no reachable unsigned target but does expose an unsigned web service such as AD CS enrolment, which gives an equivalent path.

**When the target enforces SMB signing the relay stops at authentication, so a signed-session failure is not a broken-signing finding.**

Discard when the tester reported that authentication succeeded but no session could be used: without the shared session key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default. It survives only when the attacker recovered the session key or the target did not require signing.

*Disproof:* Would be wrong where CVE-2019-1019 style session-key retrieval was possible, since then signing provides no protection against relay.
**Hypothesis:** SMB-based lateral movement: unexpected SMB sessions from a host that was not an admin workstation
- Invalidated by: the portproxy entry was a sanctioned administrative redirect with a documented owner, and the SMB peer was that application's backend; the toolkit was also living off the land by design, using built-in SMB/WMI/WinRM
- **Rejection rule:** an SMB session from a management or tooling host is not lateral movement until the redirection and the protocol abuse are shown to lack a sanctioned administrative owner

## Validation

**A relay finding is bounded by the negotiated signing state, so the validation that separates a real relay path from a non-finding is a differential test of the same request with and without a valid signature, not the mere presence of an SMB listener.**

What the primitive gives you: a candidate relay path. Microsoft's signing documentation states that Windows and Windows Server can require outbound signing only, inbound signing only, both, or neither, and that signature mismatches alert users to possible foul play, helping protect deployments against relay and spoofing attacks. Tenable's force-authentication writeup supplies the other half: the credential the first service leaked is only exploitable where it can be replayed, which is precisely what signing state determines. The precondition the next link needs is therefore a specific, measured combination of outbound and inbound policy on the two hosts in the path. Observation that proves the segment: a session with a correct signature succeeds and the same session with an invalid or absent signature is rejected, confirming signing is enforced; the inverse result confirms the path is live.

*Disproof:* If the server accepts unsigned or wrongly-signed SMB sessions on the relevant share, the differential shows no rejection and the relay ceiling is not established by configuration alone; conversely if the server enforces signing on both ends, the relay link is closed and the finding does not hold regardless of listener exposure.

**To decide this case, observe: Discard when the tester reported that authentication succeeded but no session could be used: without the shared session key the attacker cannot generate valid SMB signatures, and modern Windows hosts require signing by default.**

Derived from smb.fprule.signing_required_ends_relay, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (smb.fprule.signing_required_ends_relay) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1021/002/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security/lateral-movement/lateral-movement-with-psexec.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security-hardening>
  - <https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-signing>
- **mollysec.com** (writeup)
  - <https://mollysec.com/posts/smb-signing-and-ntlm-relay-explained/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/2023/07/13/pentales-old-vulns-new-tricks/>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/04.%20Exploitation/19.%20Attacking%20Common%20Services/Attacking%20Common%20Services.md>
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Cheatsheets/Mix-OSCP-CPTS/Footprinting%20Services.md>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/windows-admin-shares/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1002.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/cve-2024-8260-smb-force-authentication-vulnerability-in-opa-could-lead-to-credential-leakage>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
