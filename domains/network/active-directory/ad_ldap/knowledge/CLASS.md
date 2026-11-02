# LDAP as an Attack Surface

## Definition

Directory queries are attacker-reachable structure: an unescaped filter changes the query, and an unsigned bind lets the response be forged.

- **CWE:** CWE-90
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["ldap", "ldap injection", "ldap filter injection", "null bind", "anonymous bind", "ldap signing", "channel binding"]

Canonical home for `ad_ldap`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**An LDAP-based AD change finding is only testable after object-level directory-service auditing is confirmed on, because without it the pre-change state cannot be recovered.**

LDAP is the write and read path for nearly every AD object change, but the objects it exposes are numerous and many are readable by ordinary accounts, so the LDAP channel alone never tells you whether a change was legitimate. Before testing any LDAP-write hypothesis (attribute change, GPC link, msDS-* flag), confirm that object-level directory service auditing is enabled on the DC. If it was off at the time of the suspected change, the directory log holds no record of who changed what, and the only recoverable evidence is the GPC/GPT state in SYSVOL plus Group Policy History on endpoints. A tester who jumps straight to 'LDAP write succeeded' without the audit trail is asserting intent from a state change alone, which is the classic false-positive generator for this class.

*Disproof:* If directory service object-level auditing was enabled and continuous at the time of the change, and the 4662-class record names the modifying principal, then the audit-trail prerequisite is not the limiting factor and the LDAP finding can be attributed without reconstruction.

**Any domain-joined workstation, even without RSAT and without admin rights, can run full LDAP-backed Active Directory enumeration once Microsoft.ActiveDirectory.Management.dll is imported, so the prerequisite for AD discovery is network reachability to a DC rather than a privileged toolchain.**

Absence of RSAT or admin tooling on an endpoint proves nothing, because the enumeration capability arrives as a stock Windows DLL that any domain-joined user can import. A hunter should therefore baseline directory read volume per workstation on the DC side rather than searching for tool presence on hosts, and should treat the AD Web Services and LDAP ports being reachable from a user segment as the condition that decides whether this prerequisite is met. The claim is falsified when a DC blocks or sharply limits ordinary-workstation LDAP directory reads, since then the reachability condition alone would not be sufficient.

*Disproof:* A DC that logs and blocks the underlying LDAP bind/query operations from ordinary user workstations, or an environment where the AD Web Services / LDAP ports are unreachable from user segments, would refute the claim.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass.**

Derived from ad_ldap.fp_rule.anonymous_ldap_read_is_default_ad_configuration, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_ldap.fp_rule.anonymous_ldap_read_is_default_ad_configuration) states the full boundary.

## Exploitation

**Anonymous LDAP bind on a domain controller can expose user accounts, groups, and directory structure without credentials.**

Some LDAP servers allow anonymous read queries. Test with ldapsearch -x -H ldap://DC -s base. If successful, enumerate users with (objectClass=person) and groups with (objectClass=group). Anonymous bind is a common misconfiguration that leaks the entire directory.

*Disproof:* Anonymous bind is disabled and returns insufficientAccessRights.

**If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels.**

configurations, bad practices, or poor administration, such as: 
 
 Kerberoasting / ASREPRoasting 
 NTLM Relaying 
 Network traffic poisoning 
 Password spraying 
 Kerberos delegation abuse 
 Domain trust abuse 
 Credential theft 
 Object control 
 
 Hardening Active Directory, along with a strong patching and configuration management policy, and proper network segmentation should be prioritized. If an environment is tightly managed and an adversary can gain a foothold and bypass EDR or other protections, proper management of AD can prevent them from escalating privileges, moving laterally, and getting to the crown jewels. Proper controls will help slow down an attacker and potentially force them to become noisier and risk detection. 
 
 Active Directory Structure 
 Active Directory is arranged in a hierarchical tree structure, with a forest at the top containing one or more domains, which can themselves contain nested subdomains. A forest is the security boundary within which all objects are under administrative c

*Disproof:* Refuted when: the payload is rejected when the same check runs with the defensive control ENABLED (a strict allowlist, a normalisation pass, or a WAF rule) rather than disabled. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If an environment is tightly managed and an adversary can gain a foothold and by”) does not occur under a test that isolates that control.

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

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facil”) does not occur under a test that isolates that control.

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
 
 
 
 Blind SQL Injection 
 
 
 Hard 
 
 
 16 Sections 
 
 Reward: +100 
 
 In this module, we cover bli

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

**This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment.**

AP 
 
 This module provides an overview of Active Directory (AD), introduces core AD enumeration concepts, and covers enumeration with built-in tools. 
 
 4.59 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Created by mrb3n 
 Co-Authors:
 ippsec 
 
 
 
 Start Module 
 
 
 HTB Academy Business 
 
 
 
 
 
 Summary
 
 
 
 Module
 Overview 
 
 
 
 
 
 
 
 Medium
 
 
 Offensive
 
 
 
 
 
 
 
 
 
 
 
 
 
 Summary 
 This module introduces Active Directory, the LDAP protocol, working with LDAP and AD search filters, and various built-in tools that can be used to "live off the land" when enumerating a Windows AD environment. In this module, we will cover: 
 
 An intro to Active Directory 
 Rights and Privileges in AD 
 LDAP and AD Search Filters 
 Enumerating AD with built-in tools 
 
 
 CREST CCT INF -related Sections: 
 
 All sections 
 
 
 This module is broken down into sections with accompanying hands-on exercises to practice each of the tactics and techniques we cover. The module ends with a practical hands-on

*Disproof:* Refuted when: the resolved path stays inside the permitted base directory after the platform canonicalises it. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This module introduces Active Directory, the LDAP protocol, working with LDAP an”) does not occur under a test that isolates that control.

**We will cover how to identify, exploit, and prevent each of them through various methods.**

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 HTTPs/TLS Attacks 
 
 
 Medium 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module covers details on Transport Layer Security (TLS) and how it helps to make HTTP secure with the widely used HTTPS. That includes how TLS works, how TLS sessions are established, common TLS misconfigurations, as well as famous attacks on TLS. We will discuss how to identify, exploit, and prevent TLS attacks.

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

h examples in Python, PHP, and Node.JS. 
 
 
 
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

*Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.

**We will cover how to identify, exploit, and prevent each of these injection attacks.**

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 HTTPs/TLS Attacks 
 
 
 Medium 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module covers details on Transport Layer Security (TLS) and how it helps to make HTTP secure with the widely used HTTPS. That includes how TLS works, how TLS sessions are established, common TLS misconfigurations, as well as famous attacks on TLS. We will discuss how to identify, exploit, and prevent TLS attac

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".

**Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**

while emphasizing real-world misconfigurations and flaws that we may encounter during an assessment. There are many additional "edge-case" possibilities not covered in this module. We will cover both modern and legacy Windows Server and Desktop versions that may be present in a client environment. 
 
 
 
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

identify, exploit, and prevent each of them through various methods. 
 
 
 
 HTTPs/TLS Attacks 
 
 
 Medium 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module covers details on Transport Layer Security (TLS) and how it helps to make HTTP secure with the widely used HTTPS. That includes how TLS works, how TLS sessions are established, common TLS misconfigurations, as well as famous attacks on TLS. We will discuss how to identify, exploit, and prevent TLS attacks. 
 
 
 
 HTTP Attacks 
 
 
 Hard 
 
 
 18 Sections 
 
 Reward: +100 
 
 This module covers three HTTP vulnerabilities: CRLF Injection, HTTP Request Smuggling, and HTTP/2 Downgrading. These vulnerabilities can arise on the HTTP level in real-world deployment settings utilizing intermediary systems such as reverse proxies in front of the web server. We will cover how to identify, exploit, and preven

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".

**We will cover how to identify, exploit, and prevent each of these vulnerabilities.**

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 HTTPs/TLS Attacks 
 
 
 Medium 
 
 
 15 Sections 
 
 Reward: +100 
 
 This module covers details on Transport Layer Security (TLS) and how it helps to make HTTP secure with the widely used HTTPS. That includes how TLS works, how TLS sessions are established, common TLS misconfigurations, as well as famous attacks on TLS. We will discuss how to identify, exploit, and prevent TLS att

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".

**Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**

be successful as infosec professionals, we must understand AD architectures and how to secure our enterprise environments. As Penetration testers, having a firm grasp of what tools, techniques, and procedures are available to us for enumerating and attacking AD environments and commonly seen AD misconfigurations is a must. 
 
 
 
 Kerberos Attacks 
 
 
 Hard 
 
 
 23 Sections 
 
 Reward: +100 
 
 Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. Due to its prevalence throughout an Active Directory environment, it presents us with a significant attack surface when assessing internal networks. This module will explain how Kerberos works thoroughly and examines several scenarios to practice the most common attacks against it from multiple perspectives. 
 
 
 
 DACL Attacks I 
 
 Mini-Module 
 
 
 
 Hard 
 
 
 7 Sections 
 
 Reward: +100

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".

**An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**

of brute-forcing techniques, including the use of tools like Hydra and Medusa, and the importance of strong password practices. It covers various attack scenarios, such as targeting SSH, FTP, and web login forms. 
 
 
 
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

**LDAP injection occurs when user input is concatenated into an LDAP filter, allowing an attacker to alter query logic and bypass authentication.**

Applications building LDAP filters from user input (e.g., (&(uid=INPUT)(password=INPUT))) are vulnerable. Injecting * or )(uid=*))(& can bypass filters. Special characters like *, (, ), |, & manipulate filter logic similarly to SQL injection but against directory queries.

*Disproof:* Input is escaped per RFC 4515 or parameterized queries are used.

**Nmap LDAP scripts enumerate naming contexts, users, and groups from a domain controller on ports 389 and 636.**

Run nmap -n -sV --script 'ldap* and not brute' -p 389 DC_IP to extract LDAP root DSE and naming contexts. Follow up with ldapsearch -x -H ldap://DC -b 'DC=domain,DC=local' '(objectclass=*)' to dump the directory. Authenticated binds provide full user and group enumeration.

*Disproof:* LDAP ports are filtered or the server requires signing and rejects the query.

**An LDAP search filter is a structured query supplied by the client, so any code path that concatenates unescaped user input into a filter lets the input redefine the query rather than narrow it.**

The LDAP filter is not a value the server looks up — it is the predicate that decides which entries match, and RFC 4511 defines it as a full expression language with and/or/not and comparison matchers. That means the escaping requirements are structural, not cosmetic: an unescaped ')' closes the component the application intended to be a literal, and everything after it is parsed as further filter structure. The test is a differential one — submit a value containing ')' and '*' and compare the entry set returned against the set returned by the same query with those characters escaped. If the response changes shape rather than failing, the filter is being built by concatenation. Related but distinct: unsigned LDAP binds let a response be forged rather than a query be widened, and the two remediations (escaping, and authenticated+integrity-protected binds) do not substitute for each other.

*Disproof:* If a filter containing ')' and '*' returns the identical entry set as the escaped form, or the server rejects unbalanced filter syntax outright, then filter injection is not reachable on this path.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ad_ldap.auto.01` — ad_ldap: observe, exercise, confirm (goal: `Establish, exercise and confirm a ad_ldap condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**An LDAP bind that succeeds without credentials and returns directory objects is the DEFAULT Active Directory configuration for every domain, not an authentication bypass; do not file anonymous LDAP read as a vulnerability unless a WRITE, a credentialed, or a control-plane attribute is reachable on the same connection.**

The observable that triggers this false positive is an LDAP bind that succeeds without credentials and returns directory objects, filed as an authentication bypass. Anonymous read is how every Active Directory domain is configured out of the box - the directory is built to answer authenticated and unauthenticated readers differently depending on ACL, and default ACLs permit broad read - so the observation reproduces the shipped configuration rather than deviating from it. What turns default-configuration read into an actual finding is the same connection reaching something stronger: write access to an object, a credentialed attribute such as unicodePwd or a replication attribute, or the configuration container. This rule rejects the anonymous bind as a bypass claim and redirects the check to those attributes, which is where the finding actually lives.

*Disproof:* The same anonymous connection can write to, or reset a credential on, an AD object, can read a credentialed attribute such as unicodePwd or a replication attribute, or can reach the configuration container and modify it - any of which turns default-configuration read into an actual privilege path.

**An LDAP bind that returns thousands of AD-shaped objects (CN=, OU=, sAMAccountName, memberOf) from a host that does not advertise domainDnsZones or domainController in its rootDSE is a standalone LDAP server, an export, or a read-only replica, not a domain-joined domain controller.**

The observation that triggers this false positive is a directory dump that returns a large, plausible Active Directory object graph from a host an operator assumed was just another LDAP listener on the network. Only a domain controller holds the AD database: a domain is a collection of networked computers that share a common database managed by a central authority, known as a domain controller. A host that answers 389 with AD-shaped content but has no rootDSE attributes naming the domain (domainDnsZones, domainController, configurationNamingContext) is therefore serving a copy, a restored backup, or a third-party directory that merely uses AD-like schemas. There is a second, related shape: ADWS (Active Directory Web Services) on TCP 9389 relays wrapped LDAP queries to the LDAP server located on the same domain controller, so enumeration can succeed against a DC while LDAP itself looks quiet on the wire. The benign explanation for both is that the tool picked a non-DC or used an indirect path. The distinguishing test is a second probe against the SAME host: read the rootDSE for domainDnsZones and domainController, then probe TCP 9389 for ADWS. A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory. Only when all three agree (graph present, domain naming attributes present, ADWS answering on the same host) is the observation a real DC exposure.

*Disproof:* A rootDSE read against the same host returns domainDnsZones and domainController for the forest, or TCP 9389 answers a NetTCPBinding ADWS request with the same object graph, proving the host is a domain controller holding the writable AD database rather than a replica or an export.

## Validation

**To decide this case, observe: A host that returns the AD graph, omits the domain naming attributes, and does not answer ADWS is not the domain's directory.**

Derived from ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_ldap.fp_rule.ldap_directory_shape_without_rootdse_domaindnszones) states the full boundary.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-ldap>
- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/90.html>
- **github.com** (practitioner)
  - <https://github.com/sachinn403/HTB-CPTS-Notes/blob/main/2-initial-access-and-exploitation/attacking-common-applications/7.-miscellaneous-applications/24.attacking-ldap.md>
- **h3ll-ka1ser.gitbook.io** (practitioner)
  - <https://h3ll-ka1ser.gitbook.io/boot2root/active-directory-penetration-testing/enumeration/no-credentials/ldap-enumeration>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2024/02/08/soaphound-open-source-collect-active-directory-data-adws/>
- **horizon3.ai** (writeup)
  - <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/using-dsacls-to-check-ad-object-permissions.md>
- **kayssel.com** (practitioner)
  - <https://www.kayssel.com/newsletter/issue-30/>
- **proofpoint.com** (writeup)
  - <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/windows-management-instrumentation/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4511.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **tryhackme.com** (practitioner)
  - <https://tryhackme.com/room/adbasicenumeration>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
