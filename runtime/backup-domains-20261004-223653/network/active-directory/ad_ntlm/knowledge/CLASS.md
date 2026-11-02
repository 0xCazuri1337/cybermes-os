# NTLM Authentication Weaknesses

## Definition

An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

- **CWE:** CWE-294
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["ntlm", "ntlmv1", "relay", "ntlm relay", "name piping", "named pipe", "nbns spoofing", "smb relay", "responder"]

Canonical home for `ad_ntlm`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**

NTLM is the default fallback client-server authentication protocol inside Windows networks, so every mixed or downlevel estate produces constant NTLM exchanges that have nothing to do with an adversary. The prerequisite before any NTLM-class assertion is a baseline: which hosts normally speak NTLM, to which services, from which source addresses, and with which accounts. Post-attack work that leans on Kerberos, DNS queries, share access or generic domain-infrastructure protocols is described as virtually indistinguishable from legitimate traffic, and NTLM sits in the same category because the protocol handshake itself carries no adversary marker. Only after the baseline exists does a change - a new NTLM-speaking host, a new target service, a new source for a given host - become testable rather than an artefact of estate age.

*Disproof:* If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**

Derived from ad_ntlm.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ntlm.fp_rule.auto.derived) states the full boundary.

## Exploitation

**This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**

isn't likely to go anywhere any time soon since Microsoft is improving and blending implementations with Azure AD. Another interesting stat to consider is that just in the last two years, Microsoft has had over 2000 reported vulnerabilities tied to a CVE . AD's many services and main purpose of making information easy to find and access make it a bit of a behemoth to manage and correctly harden. This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these misconfigurations and ease of access with common user and OS vulnerabilities, and you have a perfect storm for an attacker to take advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take advantage of their existence. We will practice enumerating AD utilizing native tools and languages such as Sysintern

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".

**The most common way to abuse it is to pass to the icon handler a reference to an attacker-controlled path, which would result in a user authentication attempt as soon as the user browses the folder in which the file is located, even if the user doesn’t even click or highlight the file.**

cated, well-known approach that abuses Windows Shell. Windows Shell is the operating system’s user interface. It has extensions and handlers that enrich the user experience, for example, by generating thumbnails/previews or customizing icons. Specially crafted files can manipulate these mechanisms to access arbitrary paths as soon as the operating system “sees” them, without any user interaction. The most common way to abuse it is to pass to the icon handler a reference to an attacker-controlled path, which would result in a user authentication attempt as soon as the user browses the folder in which the file is located, even if the user doesn’t even click or highlight the file. The most notable file types that support this kind of manipulation are: 
 
 Windows Search Connectors (.searchConnector-ms) 
 URL files (.url) 
 Windows Shortcuts (.lnk) 
 Windows Library Files (.library-ms) 
 
 For example, the following URL file would try to load its icon from the path attackerhosticonsurl.icon from the user’s security context, so it authenticates with the user’s credentials.

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The most common way to abuse it is to pass to the icon handler a reference to an attacker-".

**The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**

ini-module will cover enumerating and attacking common DACL misconfigurations, allowing us to escalate our privileges horizontally and vertically and move laterally across an Active Directory network. 
 
 
 
 Using CrackMapExec 
 
 
 Medium 
 
 
 27 Sections 
 
 Reward: +100 
 
 Active Directory presents a vast attack surface and often requires us to use many different tools during an assessment. The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. It is a versatile and highly customizable tool that should be in any penetration tester's toolbox. 
 
 
 
 Linux Privilege Escalation 
 
 
 Easy 
 
 
 28 Sections 
 
 Reward: +20 
 
 Privilege escalation is a crucial phase during any security assessment. During this phase, we attempt to gain access to additional users, hosts, and resources to move closer to the assessment's overall goal. There ar

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".

**An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2, to recover the password if it is not sufficiently strong .**

as a server. 
 
 Additional settings allow restricting or auditing outgoing or incoming NTLM authentication or requiring session security settings, but we won’t elaborate on those. 
 Password Cracking is a Problem 
 There are different tools for capturing NTLM responses for cracking. Responder is the most well-known and widely used tool, but Inveigh and Farmer deserve an honorable mention, too. 
 An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2, to recover the password if it is not sufficiently strong . In the case of NTLMv1, the NT hash can always be recovered, and it can be abused in a couple of ways. If it is a computer/service account, the attacker can forge an RC4-encrypted Kerberos silver ticket and impersonate a privileged account to the host or the service. The NT hash can also be used for NTLM authentication, without cracking the cleartext password, through the infamous Pass the Hash at

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2,".

**Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack.**

, the mechanics of computer account authentication coercion and user account authentication coercion are different. 
 Computer Account Authentication Coercion 
 Computer account authentication coercion typically involves an RPC call to a vulnerable function on a remote host (the relay victim). Specifically, we’d try to call a function that would attempt to access an arbitrary path we can control. Then, when the remote service attempts to access the specified path, we’d require authentication and kick off a relay attack. The remote service would authenticate as the relay victim computer account if the service runs as SYSTEM or NETWORK SERVICE and if it doesn’t impersonate a different context before attempting to access the resource. 
 The two most notable computer authentication coercion primitives are the Printer Bug and PetitPotam . The Printer Bug abuses the function RpcRemoteFindFirstPrinterChangeNotification

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Then, when the remote service attempts to access the specified path, we’d require authenti".

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

**While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**

real-world deployment settings utilizing intermediary systems such as reverse proxies in front of the web server. We will cover how to identify, exploit, and prevent each of these vulnerabilities. 
 
 
 
 Injection Attacks 
 
 
 Medium 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module covers three injection attacks: XPath injection, LDAP injection, and HTML injection in PDF generation libraries. While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. We will cover how to identify, exploit, and prevent each of these injection attacks. 
 
 
 
 Abusing HTTP Misconfigurations 
 
 
 Hard 
 
 
 20 Sections 
 
 Reward: +100 
 
 This module covers three common HTTP vulnerabilities: Web Cache Poisoning, Host Header Vulnerabilities, and Session Puzzling or Session Variable Overloading. These vulnerabilities can arise on the HTTP level due to web server

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".

**We will cover how to identify, exploit, and prevent each of them through various methods.**

This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 Attacking Common Applications 
 
 
 Medium 
 
 
 33 Sections 
 
 Reward: +20 
 
 Penetration Testers can come across various applications, such as Content Management Systems, custom web applications, internal portals used by developers and sysadmins, and more. It's common to find the same applications across many different environments. While an application may not be vulnerable in one en

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".

**This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**

isn't likely to go anywhere any time soon since Microsoft is improving and blending implementations with Azure AD. Another interesting stat to consider is that just in the last two years, Microsoft has had over 2000 reported vulnerabilities tied to a CVE . AD's many services and main purpose of making information easy to find and access make it a bit of a behemoth to manage and correctly harden. This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these misconfigurations and ease of access with common user and OS vulnerabilities, and you have a perfect storm for an attacker to take advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take advantage of their existence. We will practice enumerating AD utilizing native tools and languages such as Sysintern

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".

**We will cover how to identify, exploit, and prevent each of these injection attacks.**

This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 Attacking Common Applications 
 
 
 Medium 
 
 
 33 Sections 
 
 Reward: +20 
 
 Penetration Testers can come across various applications, such as Content Management Systems, custom web applications, internal portals used by developers and sysadmins, and more. It's common to find the same applications across many different environments. While an application may not be vulnerable in o

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".

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

**We will discuss how to identify, exploit, and prevent each vulnerability.**

ard: +200 
 
 Learn how to improve your JavaScript code's security through Code Review, Static/Dynamic Analysis, Vulnerability Identification, and Patching. 
 
 
 
 Whitebox Attacks 
 
 
 Hard 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module explores several web vulnerabilities from a whitebox approach: Prototype Pollution, Timing Attacks & Race Conditions, and those arising from Type Juggling. We will discuss how to identify, exploit, and prevent each vulnerability. 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Active Directory Penetration Tester 
 
 The Active Directory Penetration Tester Job Role Path is designed for individuals who aim to develop skills in pentesting large Active Directory (AD) networks and the components commonly found in such environments. This path equips students with the skills needed to evaluate the security of AD environments, navigate complex Win

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".

**These techniques result in an immediate authentication attempt from the victim computer account without user interaction.**

tPotam . The Printer Bug abuses the function RpcRemoteFindFirstPrinterChangeNotification[Ex] in the Print Spooler service, which establishes a connection to an arbitrary path to send notifications about print object status changes. PetitPotam abuses several functions in the Encrypting File System (EFS) service, such as EfsRpcOpenFileRaw, which opens a file in an arbitrary path for backup/restore. These techniques result in an immediate authentication attempt from the victim computer account without user interaction. 
 Authenticated Users are permitted to trigger these computer account authentication coercion attack primitives, allowing almost anyone to initiate the relay attack. 
 User Account Authentication Coercion 
 User account authentication coercion is more complicated and, in some cases, somewhat opportunistic. The classic user account authentication coercion primitives involve planting a reference to

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These techniques result in an immediate authentication attempt from the victim computer ac".

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

**We will cover how to identify, exploit, and prevent each of these vulnerabilities.**

This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 Attacking Common Applications 
 
 
 Medium 
 
 
 33 Sections 
 
 Reward: +20 
 
 Penetration Testers can come across various applications, such as Content Management Systems, custom web applications, internal portals used by developers and sysadmins, and more. It's common to find the same applications across many different environments. While an application may not be vulnerable in

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".

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

**Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**

loads are among the most critical web vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. 
 
 
 
 Command Injections 
 
 
 Medium 
 
 
 12 Sections 
 
 Reward: +20 
 
 Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems.

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".

**This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.**

n compromise and looking for every possible path to Domain Admin level access within the testing period. Many open-source tools are available to facilitate enumerating and attacking Active Directory. To be most effective, we must understand how to perform as much of this enumeration manually as possible. More importantly, we need to understand the "why" behind certain flaws and misconfigurations. This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice. 
 We need to be comfortable enumerating and attacking AD from both Windows and Linux, with a limited toolset or built-in Windows tools, also known as " living off the land ." It is common to run into situations where our tools fail, are being blocked, or we are conducting an assessment where the client has us work from a managed workstation or VDI instance instead of the customized Linux or Windo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".

**An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.**

The relay primitive is that NTLM's proof is possession of a response keyed on a shared secret and a server challenge — not a property of the TLS channel the client believes it is on. A client induced to authenticate to an attacker-controlled listener produces a response for a challenge the attacker chose; that response is then presented to a victim service, which validates it because it cannot tell the request did not arrive over the intended channel. Two ways this works in practice: capture-and-relay, where the adversary sits in the authentication path; and coercion, where the adversary induces the outbound authentication. Both are independent of hash cracking. The bound on the whole class is channel binding plus mandatory signing on the target service: if every service that accepts NTLM also requires signing, the relayed response has no valid signature and the exchange fails.

*Disproof:* If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ad_ntlm.auto.01` — ad_ntlm: observe, exercise, confirm (goal: `Establish, exercise and confirm a ad_ntlm condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a ad_ntlm finding until it is distinguished from the adjacent behaviour this class also covers. "An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts..." and "NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts...

Adjacent behaviour that produces the same observable result: NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "NTLM authentication traffic cannot be treated as an anomaly until a pe" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.**

The observation is a single outbound SMB connect from a workstation to an external IP followed by an NTLM negotiate/challenge/authenticate exchange, which is what coercion looks like: a specially crafted malicious script can coerce the victim machine to connect back to the attack system using SMB and authenticate. Because coercion is the whole mechanism, the client-side exchange is identical whether the server harvests the response or merely receives it and drops it, and the server has no obligation to relay anything. A single Type-3 therefore proves the client was made to authenticate, not that the credential material was captured and reused. The benign reading is an Outlook message or Office document containing a UNC path. The discriminating evidence lives on the attacking server, not the client: in a real capture the server shows the open-source Impacket toolkit's default NTLM server challenge of sixteen a characters and the toolkit's default SMB GUID, and practices that are uncommon in standard SMB servers. Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure. Escalate only when the relay fingerprint or a second authenticated session exists.

*Disproof:* The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.

## Validation

**To decide this case, observe: Absent those artifacts, and absent any NTLMv2 challenge/response pair relayed onward to a second service, the correct classification is coercion attempt with unconfirmed credential exposure.**

Derived from ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ntlm.fp_rule.single_outbound_smb_type3_is_unc_coercion_not_hash_theft) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1557/001/>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
- **proofpoint.com** (research)
  - <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
