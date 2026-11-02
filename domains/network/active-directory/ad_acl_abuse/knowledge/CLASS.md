# Active Directory ACL Abuse

## Definition

A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.

- **CWE:** CWE-269
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["acl abuse", "genericwrite", "genericall", "writedacl", "writeowner", "dcsync", "dcsync rights", "object access abuse", "privilege escalation rights", "acl misconfiguration"]

Canonical home for `ad_acl_abuse`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.**

odules can be considered prerequisites for successful completion of this module: 
 
 Introduction to Networking 
 Linux Fundamentals 
 Active Directory LDAP 
 Active Directory PowerView 
 
 
 
 
 BloodHound Overview 
 
 Active Directory Access Management 
 Access management in Active Directory is complex, and it is easy to introduce vulnerabilities or bad practices in day-to-day configurations. 
 Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. 
 Because the attack surface and the amount of data produced in Active Directory environments are highly complex and evolving, and because we needed a way to automate the collection and analysis of this data, @_wald0 , @harmj0y , and @CptJesus created BloodHound . 
 
 
 Note: To understand more about Active Directory, we can look at these modules Introduction to Active Directory and Active Direct

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.

**Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.**

odules can be considered prerequisites for successful completion of this module: 
 
 Introduction to Networking 
 Linux Fundamentals 
 Active Directory LDAP 
 Active Directory PowerView 
 
 
 
 
 BloodHound Overview 
 
 Active Directory Access Management 
 Access management in Active Directory is complex, and it is easy to introduce vulnerabilities or bad practices in day-to-day configurations. 
 Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. 
 Because the attack surface and the amount of data produced in Active Directory environments are highly complex and evolving, and because we needed a way to automate the collection and analysis of this data, @_wald0 , @harmj0y , and @CptJesus created BloodHound . 
 
 
 Note: To understand more about Active Directory, we can look at these modules Introduction to Active Directory and Active Direct

*Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.

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

**A principal holding both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain object can perform DCSync to dump all domain hashes including krbtgt.**

DCSync requires both replication rights on the domain root. The attacker calls impacket-secretsdump -just-dc (or mimikatz lsadump::dcsync) to pull every account hash, including krbtgt for golden tickets. These rights are often mis-granted to non-admin accounts during AD migrations or by third-party sync tools.

*Disproof:* Either replication right is missing, or the principal is not in a position to invoke DRS replication against a DC.

**GenericAll or AddMember on a group lets an attacker add themselves to that group, escalating privileges if the group is privileged.**

GenericAll over a group includes the AddMember right. The attacker runs net group <group> <user> /add or Add-ADGroupMember to join a privileged group such as Domain Admins or Account Operators, immediately inheriting its permissions.

*Disproof:* No AddMember or GenericAll ACE exists on the group, or group membership changes are blocked by Protected Users / managed service accounts.

**GenericAll over a user object lets an attacker reset the password, set an SPN for targeted Kerberoasting, or write msDS-KeyCredentialLink for shadow credentials, gaining control of that account.**

When a low-privilege principal holds GenericAll on a user, it can (1) reset the password via net user / Set-ADAccountPassword, (2) set an SPN with Set-DomainObject and Kerberoast the hash offline, or (3) write msDS-KeyCredentialLink with pywhisker/certipy shadow to obtain a TGT as that user. Each path converts a single ACE into full control of the target account.

*Disproof:* No write access exists on the user object, or the target is a protected admin (AdminSDHolder resets the ACL every 60 minutes).

**An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.**

This is a privilege-escalation primitive, not a data leak. Because access control is itself an object whose access is controlled by the DACL, granting a principal the right to modify the DACL (or to take ownership, which lets you then rewrite it) means the principal can grant itself any right it likes. On a domain object that governs replication or password reset, that is domain compromise. The enumeration approach: for each interesting object, read the access control entries and ask not 'can I write this object' but 'can I rewrite this object's permissions' — the two are different rights and only the second compounds. The Windows utilities that expose this are the same ones an adversary would use (icacls, cacls, takeown), which is useful for validation: confirm with the built-in tool rather than by asserting the permission model from the DACL dump alone.

*Disproof:* If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.

**WriteDACL on any object lets an attacker grant themselves GenericAll on that object, then abuse it as if they already held full control.**

WriteDACL permits modifying the DACL of the target object. The attacker adds an ACE granting themselves GenericAll, then performs any GenericAll action (password reset, group membership, RBCD). This is the universal escalation primitive: any WriteDACL becomes GenericAll in two steps.

*Disproof:* The attacker lacks WriteDACL, or the object is protected by AdminSDHolder/privileged container ACL inheritance.

**WriteOwner on an object lets an attacker take ownership of it, then grant themselves WriteDACL and finally GenericAll, achieving full control.**

WriteOwner allows changing the owner attribute. The attacker sets themselves as owner, which implicitly grants WriteDACL, then adds a GenericAll ACE for themselves. This three-step chain (WriteOwner -> WriteDACL -> GenericAll) is the standard path when only ownership rights are available.

*Disproof:* WriteOwner is absent, or the object's owner cannot be changed by the attacker's principal.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ad_acl_abuse.auto.01` — ad_acl_abuse: observe, exercise, confirm (goal: `Establish, exercise and confirm a ad_acl_abuse condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.**

The most common false positive in this class is escalating a graph edge into an incident. BloodHound represents relationships as edges between objects - member of a group, AdminTo, and similar - and its value is finding attack paths that traditional enumeration cannot see, which is exactly why the edges are a capability map. An edge says the ACL permits the transition. It does not say anyone took it. In a real incident the route taken often cannot be reconstructed at all: privileged-access routes such as DCSync, Kerberoasting of privileged service accounts, or Pass-the-Hash/Pass-the-Ticket may be left genuinely unresolved because the telemetry needed to choose between them was not collected. Therefore report a capability with a severity tied to reachability, and reserve incident language for an edge you have independent execution evidence for.

*Disproof:* If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.

**Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.**

Discard when the ACE report names only those four built-in groups: the DCSync write-up states these are the principals holding the replication rights by default, so no misconfiguration was introduced. It survives when a low-privileged principal, a service account or an unexpected group holds those same rights.

*Disproof:* Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.

**A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.**

Discard when the report stops at the ACE: the abuse catalogue states these abuses can only be carried out while running commands as the principal listed in the ACE, so an ACE the tester cannot exercise is not an escalation path. It survives when the tester actually assumed that principal and wrote msDS-AllowedToActOnBehalfOfOtherIdentity or a forged SPN.

*Disproof:* Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
**Hypothesis:** ACL abuse occurred: BloodHound shows a path from the compromised principal to Domain Admins
- Invalidated by: no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
- **Rejection rule:** an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1222/001/>
- **github.com** (practitioner)
  - <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
- **learn.microsoft.com** (primary)
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups>
  - <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
  - <https://www.thehacker.recipes/ad/movement/dacl/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
