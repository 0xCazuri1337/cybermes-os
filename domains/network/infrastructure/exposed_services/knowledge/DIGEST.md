# Exposed Remote Services

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 21 items, 21 supported, 2 FP rules, 1 chains

An administrative protocol reachable from where it should not be concedes its authentication surface to that reachability.

**Aliases:** exposed service, exposed services, remote services, internet facing service, management interface exposure

## Prerequisite

- **Internet-facing building management and CPS devices commonly ship with unmanaged third-party remote access tooling and open network ports, which is the precondition that turns an exposed-services finding into a lateral-movement entry point.**  
  `high_confidence` · score 0.844 · disproved by: An inventory showing these CPS environments with no third-party remote access agents and no non-essential open ports would refute the claim for that estate.
  sources: <https://labs.watchtowr.com/here-we-go-again-citrix-netscaler-dtls-preauth-memory-overflow-cve-2026-88772/> · <https://www.claroty.com/blog/claroty-team82-state-of-cps-security-2025-report-building-management-system-exposures>

## Signal

- **An RDP session whose destination is a domain controller is a higher-severity signal than the same session to a member server, because the destination can perform directory replication.**  
  `high_confidence` · score 0.844 · disproved by: Proof the claim wrong would be a deployment in which domain controllers are hardened against interactive RDP entirely -- no RDP listener present, or network-level authentication plus a control that blocks interactive sessions -- so that an RDP session to a DC cannot exist and the severity split is vacuous; or evidence that the flagged DC session was an automated management connection with no interactive channel at all.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **An administrative or remote service reachable from where policy forbids it is an initial-access or persistence surface, because attacker leverage is bounded by reachability rather than by the service's own authentication.**  
  `high_confidence` · score 0.814 · disproved by: If every exposed administrative service is reachable only from an explicitly authorized management segment and enforced at the network layer rather than by application configuration, then the reachability that creates the risk is not present.
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://learn.microsoft.com/en-us/windows/win32/termserv/remote-desktop-protocol>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.8055 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **We will cover how to identify, exploit, and prevent each of these injection attacks.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.778 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://attack.mitre.org/techniques/T1133/> · <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **We will discuss how to identify, exploit, and prevent each vulnerability.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Validation

- **A flagged RDP session to a domain controller discriminates from the benign lookalike only when the operator's rights to that controller are read out of the directory rather than inferred from the session alone.**  
  `high_confidence` · score 0.8715 · disproved by: Proof the claim wrong would be a case where the account holds no interactive logon right on the domain controller yet the session succeeded anyway, showing the directory rights model did not predict the outcome and that the rights graph is therefore not a sufficient discriminator for this class; or a domain where interactive logon rights are not represented in the enumerated data at all.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Fp Rule

- **An SSH service answering on an unusual high TCP port on a consumer or edge device is a vendor port-forward feature, not attacker persistence; the discriminator is whether the port serves the vendor's own management tunnel rather than a general-purpose login.**  
  `high_confidence` · score 0.8255 · disproved by: The high-port SSH service hands an interactive shell to an unexpected source, or its host key rotates across scans without a firmware change, showing the daemon is being used as an operator foothold rather than as a vendor management tunnel.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2291> · <https://www.helpnetsecurity.com/2026/03/24/detectify-ip-range-scanning/>

## Chain Link

- **An administrative or remote service reachable from where policy forbids it is initial access rather than a standalone exposure, because the reachable authentication surface is what a relay primitive later supplies with credentials it could not otherwise obtain.**  
  `high_confidence` · score 0.8875 · disproved by: Refuted if the administrative service is not reachable from the untrusted segment, or if the service enforces message signing or channel binding on every inbound authentication such that a relayed response is rejected; with either condition the exposure yields no credential and the chain stops at reconnaissance.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## False-positive rules

- **Hypothesis:** An SSH service listening on an unusual high TCP port is an exposed remote service finding.
  - **Invalidated by:** The listener is a vendor port forward terminating on a managed relay that accepts connections only from the vendor's own management subnet, and no account authenticated from the scanning source; the non-standard port is the vendor's published configuration, not an additional exposure.
  - **Rule:** A non-standard port is not a finding by itself. Establish what the listener terminates on, whether logins are restricted to a vendor relay, and whether authentication succeeded from an untrusted source; only the last of those is an exposed remote service.

## Related classes (via chains)

- `smb` SMB/CIFS Abuse (2 chains)
- `lateral_movement` Lateral Movement (2 chains)
