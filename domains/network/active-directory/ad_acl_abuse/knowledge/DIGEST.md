# Active Directory ACL Abuse

> surface: `ad` · CWE: CWE-269 · OWASP: —
> maturity: **mature** — 20 items, 20 supported, 4 FP rules, 1 chains

A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.

**Aliases:** acl abuse, genericwrite, genericall, writedacl, writeowner, dcsync, dcsync rights, object access abuse, privilege escalation rights, acl misconfiguration

## Technique

- **An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.**  
  `high_confidence` · score 0.85 · disproved by: If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
- **While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **We will cover how to identify, exploit, and prevent each of these injection attacks.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **We will discuss how to identify, exploit, and prevent each vulnerability.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Fp Rule

- **A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.**  
  `high_confidence` · score 0.844 · disproved by: If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
- **A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
  sources: <https://www.thehacker.recipes/ad/movement/dacl/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>

## False-positive rules

- **Hypothesis:** ACL abuse occurred: BloodHound shows a path from the compromised principal to Domain Admins
  - **Invalidated by:** no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
  - **Rule:** an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration
