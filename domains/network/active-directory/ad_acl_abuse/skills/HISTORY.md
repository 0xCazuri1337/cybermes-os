# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 20 (supported 20), FP rules 4, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 20 (supported 20), FP rules 4, chains 1, state mature

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -91,4 +91,4 @@
   - Rule: an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration
 
 ---
-Full class document: `domains/network/active-directory/ad_acl_abuse/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`
+Full class document: `domains/network/active-directory/ad_acl_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`
```

## 2026-10-02 19:37 — 80 diff lines
- items: 20 (supported 4), FP rules 4, chains 1, state mature

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 20 items, 20 supported, 4 FP rules, 1 chains
+> evidence: 20 items, 4 supported, 4 FP rules, 1 chains
 > maturity: **mature**
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
@@ -20,52 +20,52 @@
 
 ## Techniques (what to change)
 
-- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.
+- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
-- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.
+- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.
+- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
-- We will cover how to identify, exploit, and prevent each of them through various methods.
+- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.
+- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
-- We will cover how to identify, exploit, and prevent each of these injection attacks.
+- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
-- We will discuss how to identify, exploit, and prevent each vulnerability.
+- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- We will discuss how to identify, exploit, and prevent TLS attacks.
+- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.
+- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.
+- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.
```

## 2026-10-03 01:46 — 86 diff lines
- items: 20 (supported 3), FP rules 3, chains 1, state researching
- still missing: supported_items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 20 items, 4 supported, 4 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 20 items, 3 supported, 3 FP rules, 1 chains
+> maturity: **researching** — missing: supported_items
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
 
@@ -25,58 +25,55 @@
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
 - Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 - SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 - While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
 - We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/>
 - We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 - We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
 - We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/>
 - Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.
   - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
 
 ## False-positive rules (when to reject it)
 
-- A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.
+- A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed. _(unverified)_
   - **Disproof:** If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.
   - **Disproof:** Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
```

## 2026-10-04 00:43 — 130 diff lines
- items: 20 (supported 3), FP rules 3, chains 1, state researching
- still missing: supported_items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -20,66 +20,63 @@
 
 ## Techniques (what to change)
 
-- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
-- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. _(unverified)_
+- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
+  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+- An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
+- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
+- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/>
+- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
+- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
-- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
+- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
+  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+- We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
   - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
-- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
+- We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
   - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
+- We will cover how to identify, exploit, and prevent each of these vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
   - Sources: <https://attack.mitre.org/techniques/T1222/001/>
-- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
+- We will discuss how to identify, exploit, and prevent TLS attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
+  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
+- We will discuss how to identify, exploit, and prevent each vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/>
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-- An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.
-  - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
+- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
 
 ## False-positive rules (when to reject it)
 
-- A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed. _(unverified)_
+- A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.
-- Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.
+- A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
+  - Sources: <https://www.thehacker.recipes/ad/movement/dacl/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+- Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.  _(merged 1 duplicate row(s))_
   - **Disproof:** Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
-- A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.
-  - **Disproof:** Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
-  - Sources: <https://www.thehacker.recipes/ad/movement/dacl/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 
 ## Rejected before you report
 
@@ -87,5 +84,20 @@
   - Killed by: no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
   - Rule: an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
... (truncated)
```

## 2026-10-04 00:50 — 14 diff lines
- items: 20 (supported 3), FP rules 3, chains 1, state researching
- still missing: supported_items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -87,10 +87,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Enumerate the ACL on the target object and test only the specific write principal it grants.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 20 (supported 3), FP rules 3, chains 1, state researching
- still missing: supported_items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -98,6 +98,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/ad_acl_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 35 diff lines
- items: 20 (supported 6), FP rules 3, chains 1, state mature

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 20 items, 3 supported, 3 FP rules, 1 chains
-> maturity: **researching** — missing: supported_items
+> evidence: 20 items, 6 supported, 3 FP rules, 1 chains
+> maturity: **mature**
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
 
@@ -26,8 +26,8 @@
 - An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
-- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 2 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Attackers and defenders commonly have difficulty discovering or auditing all the accesses ".
+- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 2 duplicate row(s))_
+  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
@@ -43,8 +43,8 @@
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
+- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
 - This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
```

## 2026-10-28 14:45 — 67 diff lines
- items: 5 (supported 4), FP rules 3, chains 1, state researching
- still missing: items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 20 items, 6 supported, 3 FP rules, 1 chains
-> maturity: **mature**
+> evidence: 5 items, 4 supported, 3 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
 
@@ -20,52 +20,12 @@
 
 ## Techniques (what to change)
 
-- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
-  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
 - An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
-- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 2 duplicate row(s))_
+- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/>
-- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
-- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“These flaws enable attackers to upload malicious files, execute arbitrary comman”) does not occur under a test that isolates that control.
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
-- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
-  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- We will cover how to identify, exploit, and prevent each of them through various methods.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
-  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- We will cover how to identify, exploit, and prevent each of these injection attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
-  - Sources: <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- We will cover how to identify, exploit, and prevent each of these vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/>
-- We will discuss how to identify, exploit, and prevent TLS attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- We will discuss how to identify, exploit, and prevent each vulnerability.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
-  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
-- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-29 14:12 — 11 diff lines
- items: 5 (supported 4), FP rules 3, chains 1, state researching
- still missing: items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -25,7 +25,7 @@
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
 - Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
-  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 
 ## False-positive rules (when to reject it)
 
```

## 2026-10-29 14:28 — 39 diff lines
- items: 10 (supported 5), FP rules 3, chains 1, state researching
- still missing: items

```diff
--- ad_acl_abuse@current
+++ ad_acl_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 5 items, 4 supported, 3 FP rules, 1 chains
+> evidence: 10 items, 5 supported, 3 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.
@@ -20,12 +20,27 @@
 
 ## Techniques (what to change)
 
+- A principal holding both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain object can perform DCSync to dump all domain hashes including krbtgt.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Either replication right is missing, or the principal is not in a position to invoke DRS replication against a DC.
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
 - An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.  _(merged 1 duplicate row(s))_
   - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
 - Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
   - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+- GenericAll or AddMember on a group lets an attacker add themselves to that group, escalating privileges if the group is privileged.  _(merged 1 duplicate row(s))_
+  - **Disproof:** No AddMember or GenericAll ACE exists on the group, or group membership changes are blocked by Protected Users / managed service accounts.
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups>
+- GenericAll over a user object lets an attacker reset the password, set an SPN for targeted Kerberoasting, or write msDS-KeyCredentialLink for shadow credentials, gaining control of that account.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** No write access exists on the user object, or the target is a protected admin (AdminSDHolder resets the ACL every 60 minutes).
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
+- WriteDACL on any object lets an attacker grant themselves GenericAll on that object, then abuse it as if they already held full control.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The attacker lacks WriteDACL, or the object is protected by AdminSDHolder/privileged container ACL inheritance.
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
+- WriteOwner on an object lets an attacker take ownership of it, then grant themselves WriteDACL and finally GenericAll, achieving full control.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** WriteOwner is absent, or the object's owner cannot be changed by the attacker's principal.
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
 
 ## False-positive rules (when to reject it)
 
```
