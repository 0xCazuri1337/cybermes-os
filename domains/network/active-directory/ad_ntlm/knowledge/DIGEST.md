# NTLM Authentication Weaknesses

> surface: `ad` · CWE: CWE-294 · OWASP: —
> maturity: **mature** — 21 items, 21 supported, 2 FP rules, 1 chains

An NTLM challenge can be relayed to a second service, or a captured hash replayed, because NTLM authenticates the connection rather than the channel to it.

**Aliases:** ntlm, ntlmv1, relay, ntlm relay, name piping, named pipe, nbns spoofing, smb relay, responder

## Prerequisite

- **NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host.**  
  `high_confidence` · score 0.8355 · disproved by: If the estate is homogeneous and every domain-joined host is Kerberos-only with NTLM disabled at the DC and on all clients, then any NTLM handshake is by definition outside the baseline and no per-host baseline work is required to call it anomalous.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts NTLM.**  
  `high_confidence` · score 0.9325 · disproved by: If the target service rejects the relayed exchange because message signing or channel binding is mandatory, or if no adversary-controlled authentication can be induced on the path, then NTLM relay cannot succeed and any such report is a false positive.
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/>
- **While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**  
  `high_confidence` · score 0.833 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **We will cover how to identify, exploit, and prevent each of these injection attacks.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **We will discuss how to identify, exploit, and prevent each vulnerability.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>

## Fp Rule

- **Reject a ad_ntlm finding until it is distinguished from the adjacent behaviour this class also covers. "An NTLM authentication exchange can be relayed rather than cracked: because NTLM authenticates the connection and not the channel to it, a captured challenge-response from one service is replayable against a second service that accepts..." and "NTLM authentication traffic cannot be treated as an anomaly until a per-host baseline of legitimate NTLM authentication has been established for that host." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.924 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "NTLM authentication traffic cannot be treated as an anomaly until a pe" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1557/001/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **One outbound SMB session carrying an NTLM Type-3 authenticate message to an external address is the expected result of a UNC link, not evidence that NTLM hashes were stolen; hash theft requires server-side relay artifacts to be present.**  
  `high_confidence` · score 0.8715 · disproved by: The external SMB server emits the Impacket default NTLM challenge and default GUID, or the captured Type-3 response is replayed successfully to a second host or service as an authenticated session, which turns the observation from coercion into confirmed credential theft.
  sources: <https://www.proofpoint.com/us/blog/threat-insight/ta577s-unusual-attack-chain-leads-ntlm-data-theft> · <https://www.helpnetsecurity.com/2025/10/21/cisa-warns-of-windows-smb-flaw-under-active-exploitation-cve-2025-33073/>
