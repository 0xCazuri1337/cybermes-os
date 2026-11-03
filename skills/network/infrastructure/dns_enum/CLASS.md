<!-- GENERATED from db/wks.db — do not edit -->
# DNS Enumeration

## Definition

DNS names hosts and services, so a zone disclosure enumerates the network without touching it.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["dns enumeration", "zone transfer", "axfr", "dns zone", "zone walking", "ad integrated dns", "srv record", "dns records"]

Canonical home for `dns_enum`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the correct behaviour.**

Decide the expectation before reporting. Zone transfer is not an attack primitive in itself: it is the mechanism by which a secondary obtains a copy of the zone, and a secondary will poll the primary to see if the serial number for the zone has increased so it knows to request a new copy of the data for the zone. The precondition for calling an AXFR attempt a finding is therefore an inventory question, not a probe question: does this nameserver have configured secondaries whose legitimate replication traffic you would also see? Enumerate the SOA and NS records for the zone, compare the declared secondaries against the set of hosts you are authorised to test, and only then attempt the transfer. If a transfer succeeds from a nameserver with no declared secondary, or succeeds from a host outside the declared secondary set, that is a genuine disclosure. If it is refused everywhere, that is a closed zone and belongs in validation, not in enumeration. Record which nameservers answered, which refused, and what the SOA serial was before and after, so the report distinguishes a designed configuration from an exposure.

*Disproof:* The claim is wrong, and a refused or silent AXFR is not a clean configuration, if the transfer succeeds from a nameserver that is not in the zone's declared secondary set, or if a secondaries-permitted ACL is missing so any address can pull the whole zone. Success from a non-secondary address is the disproof for the expectation claim; but note that refusal from a genuinely non-secondary server does prove the zone is closed for that host, so the expectation still holds there.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...**

Derived from dns_enum.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (dns_enum.fp_rule.auto.derived) states the full boundary.

## Exploitation

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

**We will cover how to identify, exploit, and prevent each of these vulnerabilities.**

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
 
 GraphQL is a query language for APIs as an alternative to REST APIs. Clients are able to

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".

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

**The value of a zone transfer is proportional to what the zone's NS and SOA records already imply, so enumerate those records first to size the transfer, then use the transfer to recover only the names those records never exposed.**

Order the enumeration so the transfer is interpretable. Passive and active DNS enumeration, web crawling, web archive analysis and HTTP header review together build the candidate name list; from that list pull the NS set for the parent and the SOA for the zone, which names the primary and the responsible mailbox and gives the refresh, retry, expire and minimum timers that describe how secondaries are meant to be served. That gives you the expected answer to every AXFR question before you send one. Then run the transfer and diff: names that appear in the transfer but in no NS, SOA, MX, or service record are exactly the internal names the public surface concealed, and those are the entries worth carrying into asset inventory. A transfer that only returns records already derivable from public queries adds no attack surface and should not be scored as a disclosure.

*Disproof:* The claim is wrong, and the transfer added no enumeration value, if every record it returned was already obtainable from NS, SOA, MX, TXT and service-record queries against the public zone, so no name was concealed by the refusal to transfer; or the transfer returned only the SOA and a single NS RRset matching the authoritative set. In that case the correct finding is a closed zone, not a disclosure, and the enumeration value of the attempt is nil.

**A negative answer from a DNSSEC-signed zone that uses NSEC rather than NSEC3 carries the next existing owner name in its authority section, so an anonymous client can follow that chain and walk the whole zone without an AXFR.**

A DNSSEC-signed zone has to prove that a name which does not exist really does not exist, and it does that with an NSEC record in the authority section of the NXDOMAIN response: the record names its own owner, a type bitmap, and the next owner name in the zone's canonical (lexicographic) ordering. Because that next name is the successor of the name you asked for, an anonymous queryer recovers the zone one successor at a time -- request a random label, read the next-domain field out of the response, then request that name and repeat until the chain wraps back to the apex. No AXFR, no authenticated session and no wordlist are needed: this is the same disclosure a refused zone transfer denies, so a refused AXFR is not evidence that the zone is closed. Two states remove the walk and must be established before it is claimed -- NSEC3 hashes the owner and next-owner names, and minimally covering NSEC records bracket only the queried label. Probe the authoritative nameserver directly rather than a recursive resolver, verify that each recovered name resolves on its own, and compare the recovered set against the public NS/SOA/MX set so only names the public surface concealed are scored.

*Disproof:* Wrong if the zone publishes NSEC3 rather than NSEC, because the owner and next-owner names are salted hashes and no plaintext successor is returned to follow; equally wrong if minimally covering NSEC records are served, since the span then brackets only the queried label and nothing else is disclosed. Also wrong if the authority section of the negative response is empty, which is the unsigned or opt-out case where one name is never linked to the next. A walk that terminates after a single query, or that returns only names already obtainable from NS, SOA, MX and service-record queries, reveals nothing the public surface did not already publish.

**A DNS zone enumerates every host in a namespace without touching it, and an AXFR zone transfer returns the entire zone, so one query against a misconfigured server replaces host discovery.**

DNS is a name-to-address mapping in which the zone is the complete inventory of a namespace, and RFC 1035 defines AXFR as a request for a transfer of an entire zone. That is the whole attack: query the server for a transfer and read the record set. In Windows environments DNS carries additional weight because the DNS Client service uses it to discover domain controllers before authentication even begins — the domain controller location mechanism is a DNS query, so zone contents describe the authentication topology as well as the host list. The control is therefore narrow and checkable: a zone transfer should only be accepted from the secondary servers that need it, and any AXFR answered to an unexpected source is a finding on its own. Note also that SRV records carry service locations, so a zone dump enumerates services, not merely hosts.

*Disproof:* If an AXFR request from an unauthorized source is refused, or the server only answers transfers to configured secondaries, then the zone cannot be enumerated this way and discovery requires per-host probing.

**Zone transfer or a misconfigured DNS service reveals the internal host inventory that no port scan would expose.**

In practice on HTB this shows up as: -   `IXFR` - Incremental Zone Transfer
An `AXFR` is a complete transfer of all entries of the zone file. In contrast to full asynchronous transfer, only the changed and new DNS records of the zone file are transferred for an `IXFR` to the secondary DNS servers.
The problem with DNS servers and zone transfers is that it does not require authentication and can be requested by any client. If the administrator has not set "Trusted Hosts/IP addresses" for the DNS servers, which have permission to receive these zones, we can also query the entire zone file with its contents. This will give us all IP addresses with the respective hosts and significantly increase our attack vector if the agreement does not limit our scope. Even today, it is quite common that the DNS servers are misconfigured and allow this.

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/02. Information Gathering/10b. DNS Enumeration Python/DNS Enumeration Using Python.md (8215 words, classified network).

*Disproof:* Refuted when the authoritative server refuses AXFR and out-of-zone queries, so the internal inventory is never returned.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.dns_enum.auto.01` — dns_enum: observe, exercise, confirm (goal: `Establish, exercise and confirm a dns_enum condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a dns_enum finding until it is distinguished from the adjacent behaviour this class also covers. "A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those..." and "A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the..." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A zone transfer that returns internal hostnames supplies the candidate subdomain list that turns a dangling DNS record into a takeover, because the transfer reveals names that public certificate and archive sources never listed and those...

Adjacent behaviour that produces the same observable result: A zone-transfer attempt is only an unexpected probe when the target nameservers are not meant to serve secondaries; where the SOA declares real secondary nameservers, an AXFR request is the designed replication path and its refusal is the...

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A zone-transfer attempt is only an unexpected probe when the target na" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**An AXFR refused by every authoritative nameserver, returning REFUSED or NOTAUTH with an SOA in the authority section, is a closed zone and not a DNS disclosure, provided the same refusal is observed from an address outside the declared secondary set.**

The transfer request is a transfer of an entire zone, and a properly configured primary answers it only for hosts it is configured to serve secondaries. A zone transfer is UDP-unacceptable by design, and the SOA reply that accompanies a refusal is the normal authoritative signal, not a partial leak. So the discriminator is not whether the probe returned records; it is whether any authoritative server served the zone to an address outside its declared secondary set. Reject when: every authoritative NS returns REFUSED, NOTAUTH, or an empty answer with SOA present; the refusal is consistent from two or more source addresses and over both TCP and the fallback path; and the SOA serial returned matches the serial obtainable by a plain SOA query, which proves the transfer revealed nothing the public surface did not already publish. Report as a validated negative, and do not carry it into the enumeration hit list.

*Disproof:* The rule is wrong, and the zone is exposed, if any authoritative nameserver returns a full RRsets transfer to an address outside its declared secondary set; if the response is a truncated or partial transfer (SOA plus a subset of records) rather than a clean refusal; if the SOA serial in the refusal differs from the publicly queryable serial, indicating the authority is serving different data than the public view; or if a secondaries-permitted ACL is absent and any source address is served. A partial answer is a leak, not a closure.

## Validation

**A refused DNS zone transfer proves the zone is not AXFR-open, not that no records were retrieved; enumeration evidence requires a returned record set from the transfer, an NSEC walk, or a secondary resolver.**

Validation: enumeration tools list an attempt to transfer a DNS zone as a module, and separately list subdomain enumeration by NSEC-walking, TXT record inspection, and reference hunting in page content. These produce very different evidence, and a failed transfer is routinely reported as a successful enumeration because the module simply ran. The validation rule is that a record set must exist before the observation counts. Compare against what a real anonymous retrieval looks like on a device that has one: a single crafted TFTP get request causes a file download, resulting in disclosure of sensitive information, and the attacker can send unauthenticated commands to trigger it. That is the shape of positive evidence: content actually came back, unauthenticated. For DNS the equivalent is a SOA plus NS record set plus the additional records returned, or a proven NSEC chain walked to NXDOMAIN. What a refusal proves is a control: the zone is not AXFR-open, which is a hardening fact worth recording, not an exposure. Two further corrections belong with the finding. A zone transfer that returns only SOA and NS is a misconfigured delegation, not a full enumeration. And subdomain names recovered from certificate transparency, search engines, or other external means are not DNS enumeration against the target at all; label them as passive so the active-path claim stays honest.

*Disproof:* The transfer or an equivalent anonymous read returns an actual record set beyond SOA and NS, or an NSEC chain yields NXDOMAIN proofs for names that resolve elsewhere, showing records were retrieved without authentication.

**A zone-transfer disclosure is validated only by showing a full multi-record answer whose SOA serial is current and whose names exceed the public NS/SOA/MX set, because an empty or serial-stale answer is a replica, not a disclosure.**

Three checks separate a real disclosure from a noisy probe. First, serial: the returned SOA serial must equal or be newer than the serial a plain SOA query returns; if it is older, you are reading a stale replica and your record set is not authoritative. Second, completeness: a genuine transfer returns the SOA plus the full RRset for every zone owner, not a truncated subset; the transfer is of an entire zone by definition, so a partial answer is either a transfer in progress or a deliberately limited reply and neither is a clean copy. Third, delta: subtract every record derivable from NS, SOA, MX, TXT and service-record queries, then count the remainder. Only the remainder is new attack surface. Record the count of names recovered and the sources they came from, because a transfer that returns nothing beyond the public set is a closed zone, and one that returns a current serial plus internal names is a finding that justifies the follow-on takeover and virtual-host work.

*Disproof:* The validation fails, and the transfer is not a disclosure, if the returned SOA serial is older than the publicly queryable serial (stale replica); the answer contains the SOA but no additional owner names; every returned record was already obtainable through normal public queries; or the transfer succeeded only from an address inside the declared secondary set, which is the designed replication path rather than an exposure. A current serial plus at least one name absent from the public set is what the finding requires.

**A wildcard DNS record synthesises an answer for every name under its owner, so a subdomain bruteforce returns a hit for every candidate and the wildcard payload must be probed and subtracted before any discovered hostname is believed.**

A wildcard is an ordinary resource record whose owner name begins with a '*' label, and RFC 1034 treats it as an instruction to synthesise: when the appropriate conditions are met the server creates records whose owner name is the query name and whose contents are copied from the wildcard. A wordlist sweep against such a zone therefore does not discover hosts, it interrogates the wildcard, and every generated label returns the same payload. Probe before believing the sweep: request a random label that cannot exist, and if the server answers, read the wildcard payload out of that response and subtract every candidate that resolves to it. Querying the wildcard owner name directly -- a '*' label in the query -- is the only request that returns a record with the '*' still in its owner name, and it is the request to compare the synthesised answer against. One bare address match is not enough to close the sweep, because a load-balanced wildcard returns several addresses, so verify by repeating the random probe until the address set stops growing and subtract the whole set. Only candidates that still resolve afterwards are records actually held on the nameserver.

*Disproof:* Not a finding when a randomly generated label under the parent comes back NXDOMAIN from every authoritative nameserver, because nothing is being synthesised and the candidate list needs no subtraction at all; likewise not a finding when the parent answers non-existent names with a distinct per-name address, since address-set subtraction then removes nothing and the surviving names are still fabrications. Reject too when the repeated address is shared hosting rather than a catch-all, where unrelated real names coincidentally share one address, and when the candidate was never resolved against the target's own authoritative server at all but taken from a passive certificate or archive list, which is passive discovery and not this test.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/catalogue/paths>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1016/001/>
- **blog.apnic.net** (research)
  - <https://blog.apnic.net/2023/01/17/subdomain-enumeration-with-dnssec/>
- **digi.ninja** (writeup)
  - <https://digi.ninja/blog/dns_wildcard_recon.php>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2025/02/03/baddns-open-source-tool-check-domain-subdomain-takeover/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/networking/dns/dns-top>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/02.%20Information%20Gathering/10b.%20DNS%20Enumeration%20Python/DNS%20Enumeration%20Using%20Python.md>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1034.html>
  - <https://www.rfc-editor.org/rfc/rfc1035.html>
  - <https://www.rfc-editor.org/rfc/rfc1912.html>
  - <https://www.rfc-editor.org/rfc/rfc4034.html>
- **svn.nmap.org** (docs)
  - <https://svn.nmap.org/nmap/scripts/dns-nsec-enum.nse>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2019-0851>
- **unit42.paloaltonetworks.com** (research)
  - <https://unit42.paloaltonetworks.com/wildcard-dns-abuse/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
