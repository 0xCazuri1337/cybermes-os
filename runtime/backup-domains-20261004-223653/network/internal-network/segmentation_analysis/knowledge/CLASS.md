# Network Segmentation Analysis

## Definition

Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.

- **CWE:** CWE-1188
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["segmentation", "network segmentation", "segmentation analysis", "trust boundary", "firewall analysis", "security boundary", "vlan segmentation"]

Canonical home for `segmentation_analysis`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.**

Treat a finding here as a baseline deviation, not a signature hit. Concretely: establish what a normal RDP or LDAP session looks like per segment -- which source ranges, which hours, which ports, which volumes -- and then alert on the deviation from that specific per-segment baseline. A rule written once against a generic estate profile will either miss a re-routed session on a quiet segment or drown in noise on a busy one. Record the baseline inputs alongside the alert so a reviewer can see which declared fact the deviation was measured against.

*Disproof:* Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.**

Derived from segmentation_analysis.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (segmentation_analysis.fp_rule.auto.derived) states the full boundary.

## Exploitation

**While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them to cyberattacks .**

logy (OT) and cyber-physical systems (CPS), one thing is certain: Things are a lot more interconnected than they used to be. Not long ago, industrial control systems (ICS) were often airgapped and isolated , completely disconnected from the internet—and subsequently, safe from the reach of threat actors.  As OT and CPS assets are being brought online for the first time, it’s a double-edged sword. While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them to cyberattacks . The moment these systems are assigned an IP address, they can put a target on your organization’s back if they’re not properly protected. To make matters worse, cunning threat actors often only need to gain access to one piece of equipment to gain lateral movement through the network of connected devices.  So, if OT and/or CPS infrastructure gets hit, how can organizations take steps to reduce th

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While accessing and managing systems such as programmable logic controllers (PLCs) and hum".

**As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges.**

radius? Understanding Network Segmentation in OT At its core, network segmentation is the process of dividing a network into smaller, isolated subnets or zones that can be managed and secured separately. Effective segmentation creates barriers that an attacker has to overcome. This practice can significantly limit the damage they can do, should they successfully gain access to a connected device. As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. While security is the chief benefit of segmentation, that’s not the end of it. The benefits of network segmentation go far beyond threat containment.  Key Benefits of OT Network Segmentation  Network segmentation for OT and CPS assets can benefit your organization in several ways. It can reduce risk, enhance control, and grant more visibility. Beyond enhanced security, as previously mentioned, he

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".

**While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them to cyberattacks .**

logy (OT) and cyber-physical systems (CPS), one thing is certain: Things are a lot more interconnected than they used to be. Not long ago, industrial control systems (ICS) were often airgapped and isolated , completely disconnected from the internet—and subsequently, safe from the reach of threat actors.  As OT and CPS assets are being brought online for the first time, it’s a double-edged sword. While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them to cyberattacks . The moment these systems are assigned an IP address, they can put a target on your organization’s back if they’re not properly protected. To make matters worse, cunning threat actors often only need to gain access to one piece of equipment to gain lateral movement through the network of connected devices.  So, if OT and/or CPS infrastructure gets hit, how can organizations take steps to reduce th

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While accessing and managing systems such as programmable logic controllers (PLCs) and hum".

**As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges.**

radius? Understanding Network Segmentation in OT At its core, network segmentation is the process of dividing a network into smaller, isolated subnets or zones that can be managed and secured separately. Effective segmentation creates barriers that an attacker has to overcome. This practice can significantly limit the damage they can do, should they successfully gain access to a connected device. As the methods of attackers continue to evolve and become more persistent, network segmentation is a critical strategy for keeping key assets out of harm’s way—even if it can come with some challenges. While security is the chief benefit of segmentation, that’s not the end of it. The benefits of network segmentation go far beyond threat containment.  Key Benefits of OT Network Segmentation  Network segmentation for OT and CPS assets can benefit your organization in several ways. It can reduce risk, enhance control, and grant more visibility. Beyond enhanced security, as previously mentioned, he

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As the methods of attackers continue to evolve and become more persistent, network segment".

**SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**

lication compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
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
 
 
 
 Command Injections 
 
 
 Medium 
 
 
 12 Sections 
 
 Reward: +20 
 
 Command injection vulnerabil

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".

**We will cover how to identify, exploit, and prevent each of them through various methods.**

oader category of Identification and Authentication failures. A vulnerability or misconfiguration at the authentication stage can impact an application's overall security. 
 
 
 
 Web Attacks 
 
 
 Medium 
 
 
 18 Sections 
 
 Reward: +20 
 
 This module covers three common web vulnerabilities, HTTP Verb Tampering, IDOR, and XXE, each of which can have a significant impact on a company's systems. We will cover how to identify, exploit, and prevent each of them through various methods. 
 
 
 
 File Inclusion 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web application vulnerability, which can be easily overlooked as part of a web application's functionality. 
 
 
 
 Attacking GraphQL 
 
 Mini-Module 
 
 
 
 Medium 
 
 
 9 Sections 
 
 Reward: +20 
 
 GraphQL is a query language for APIs as an alternative to REST APIs. Clients are able to request

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".

**These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**

ities can be leveraged to compromise a hosting server and its entire network. This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 File Upload Attacks 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +20 
 
 Arbitrary file uploads are among the most critical web vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. 
 
 
 
 Server-side Attacks 
 
 
 Medium 
 
 
 19 Sections 
 
 Reward: +20 
 
 A backend that handles user-supplied input insecurely can lead to devastating security vulnerabilities such as sensitive information disclosure and remote code execution. This module covers how to identify and exploit server-side bugs, including Server-Side Request Forgery (SSRF), Server-Side Template Injection (SSTI),

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".

**Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**

er with enough know-how to be able to implement simple yet useful pieces of software. 
 
 
 
 Intro to Assembly Language 
 
 
 Medium 
 
 
 24 Sections 
 
 Reward: +20 
 
 This module builds the core foundation for Binary Exploitation by teaching Computer Architecture and Assembly language basics. 
 
 
 
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

**If improperly configured or implemented, common web security vulnerabilities such as Information Disclosure, SQL Injection, and Insecure Direct Object Reference (IDOR) may arise.**

edium 
 
 
 11 Sections 
 
 Reward: +10 
 
 File Inclusion is a common web application vulnerability, which can be easily overlooked as part of a web application's functionality. 
 
 
 
 Attacking GraphQL 
 
 Mini-Module 
 
 
 
 Medium 
 
 
 9 Sections 
 
 Reward: +20 
 
 GraphQL is a query language for APIs as an alternative to REST APIs. Clients are able to request data through GraphQL queries. If improperly configured or implemented, common web security vulnerabilities such as Information Disclosure, SQL Injection, and Insecure Direct Object Reference (IDOR) may arise. 
 
 
 
 API Attacks 
 
 
 Medium 
 
 
 13 Sections 
 
 Reward: +20 
 
 Web APIs serve as crucial connectors across diverse entities in the modern digital landscape. However, their extensive functionality also exposes them to a range of potential attacks. This module introduces API Attacks, with a specific focus on the OWASP API Security Top 10 - 2023. 
 
 
 
 Attacking Common Applications 
 
 
 M

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If improperly configured or implemented, common web security vulnerabilities such as Infor".

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

**Binary exploitation is a core tenet of penetration testing, but learning it can be daunting.**

ernal network, regardless of the size, and be able to work through each phase of the penetration testing process to reach our goal. This module will guide students through a simulated penetration testing engagement, from start to finish, with an emphasis on hands-on testing steps that are directly applicable to real-world engagements. 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Intro to Binary Exploitation 
 
 Binary exploitation is a core tenet of penetration testing, but learning it can be daunting. This is mainly due to the complexity of binary files and their underlying machine code and how binary files interact with computer memory and the processor. To learn the basics of binary exploitation, we must first have a firm grasp of Computer Architecture and the Assembly Language. To move into more advanced binary exploitation, we must have a firm grasp on basic buffer overflow attacks, princi

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Binary exploitation is a core tenet of penetration testing, but learning it can be dauntin".

**An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**

Easy 
 
 
 11 Sections 
 
 Reward: +10 
 
 This module will take you step-by-step through the fundamentals of JavaScript Deobfuscation until you can deobfuscate basic JavaScript code and understand its purpose. 
 
 
 
 Cross-Site Scripting (XSS) 
 
 
 Easy 
 
 
 10 Sections 
 
 Reward: +20 
 
 Cross-Site Scripting (XSS) vulnerabilities are among the most common web application vulnerabilities. An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. This module will teach you how to identify XSS vulnerabilities and exploit them. 
 
 
 
 SQL Injection Fundamentals 
 
 
 Medium 
 
 
 17 Sections 
 
 Reward: +10 
 
 Databases are an important part of web application infrastructure and SQL (Structured Query Language) to store, retrieve, and manipulate information stored in them. SQL injection is a code injection technique used to take advantage

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".

**Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**

on on the underlying server. 
 
 
 
 SQLMap Essentials 
 
 
 Easy 
 
 
 11 Sections 
 
 Reward: +20 
 
 The SQLMap Essentials module will teach you the basics of using SQLMap to discover various types of SQL Injection vulnerabilities, all the way to the advanced enumeration of databases to retrieve all data of interest. 
 
 
 
 Command Injections 
 
 
 Medium 
 
 
 12 Sections 
 
 Reward: +20 
 
 Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. This module will teach you how to identify and exploit command injection vulnerabilities and how to use various filter bypassing techniques to avoid security mitigations. 
 
 
 
 File Upload Attacks 
 
 
 Medium 
 
 
 11 Sections 
 
 Reward: +20 
 
 Arbitrary file uploads are among the most critical web vulnerabilities. These flaws enable attackers to upload malicious files, execute arbitrary com

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".

**Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be running some version of Windows or Linux.**

Reward: +10 
 
 This module covers the fundamentals of penetration testing and an introduction to Hack The Box. 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Local Privilege Escalation 
 
 Privilege escalation is a vital phase of the penetration testing process, one we may revisit multiple times during an engagement. During our assessments, we will encounter a large variety of operating systems and applications. Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be running some version of Windows or Linux. Both present a large attack surface with many tactics and techniques available to us for escalating privileges. This path teaches the core concepts of local privilege escalation necessary for being successful against Windows and Linux systems. The path covers manual enumeration and exploitation and the use of tools to aid in the process. 
 
 
 
 
 
 Medium 
 
 
 61 Sections 
 
 
 Required: 200

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Most often, if we can exploit a vulnerability and gain a foothold on a host, it will be ru".

**In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.**

This converts segmentation review from an architecture diagram exercise into a measured test: pivot from one compromised asset, record which zones accept the traffic, and compare the observed path against the documented boundary. An assumed boundary that a single pivot crosses is a finding regardless of how the diagram is drawn. The claim is falsified when pivot attempts from a single compromised asset are blocked at every zone boundary, which would show the barriers hold in practice.

*Disproof:* Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.

**Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.**

The measurable form of network segmentation is whether packets with private source or destination addresses cross a boundary. RFC 1918 requires that routing information about private networks not be propagated on inter-enterprise links and that packets with private addresses not be forwarded across them, and expects routers not using private space to filter such routing information. That gives a test rather than an assertion: attempt a connection from one segment to a private address in another and observe whether a route exists. A segmentation control that is documented but not enforced at the forwarding layer is not a control — the same applies to NAT and to inter-enterprise links, which is why a private address visible in external DNS or leaked logs is a boundary finding. Note also that private hosts can still reach external services through mediating gateways, so 'cannot route out' and 'cannot be routed to' are two different claims and both need testing.

*Disproof:* If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.segmentation_analysis.auto.01` — segmentation_analysis: observe, exercise, confirm (goal: `Establish, exercise and confirm a segmentation_analysis condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a segmentation_analysis finding until it is distinguished from the adjacent behaviour this class also covers. "While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them..." and "Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them...

Adjacent behaviour that produces the same observable result: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Remote-session segmentation analysis has no single universal indicator" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.**

The variables behind a segmentation rule are lists of addresses, dates, strings and numeric values that name the infrastructure the rule reasons about. Left empty or copied from another estate, they turn the rule into an anomaly generator against whatever happens to be on the wire: an authorised jump host, a new build agent, or a sanctioned vendor address all read as unknown. Before reporting, confirm the inventory was populated for this environment and check the flagged address against it; a finding whose supporting inventory was never filled in is a configuration defect, not an incident.

*Disproof:* Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/catalogue/paths>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1018/>
- **claroty.com** (research)
  - <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
- **elastic.co** (writeup)
  - <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1918.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
