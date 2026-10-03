# Tunneling and Pivoting

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 24 items, 24 supported, 2 FP rules, 1 chains

A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.

**Aliases:** tunneling, tunnelling, pivoting, socks, socks proxy, port forwarding, proxy, chisel, reverse tunnel

## Signal

- **Continued operator access carried over a legitimate service with no new listening port open is an early observable for tunnelling that no new-port rule will ever fire on.**  
  `high_confidence` · score 0.844 · disproved by: If the remote-access exposure is attributable to an approved corporate tunnel service whose domain is on the sanctioned allowlist and whose client was deployed by the platform team, then the session is sanctioned remote access and the tunnelling hypothesis is invalidated.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Technique

- **A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.**  
  `high_confidence` · score 0.853 · disproved by: If egress from the compromised segment is filtered such that no permitted-protocol channel to an attacker-controlled or third host can carry an inner session, and no dual-homed host bridges the segments, then the tunnel cannot reintroduce the forbidden reachability.
  sources: <https://attack.mitre.org/techniques/T1090/> · <https://www.rfc-editor.org/rfc/rfc4459.html>
- **While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities.**  
  `high_confidence` · score 0.827 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- **Using one compromised machine to access another is called pivoting and allows us to access networks and resources that are not directly accessible to us through the compromised host.**  
  `high_confidence` · score 0.788 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Using one compromised machine to access another is called pivoting and allows us to access".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- **This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects.**  
  `high_confidence` · score 0.7755 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **Tunneling is a technique that allows us to encapsulate traffic within another protocol so that it looks like a benign traffic stream.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Tunneling is a technique that allows us to encapsulate traffic within another protocol so ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **We will discuss how to identify, exploit, and prevent each vulnerability.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- **This is known as pivoting and enables lateral movement through the network.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This is known as pivoting and enables lateral movement through the network.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **This is known as pivoting and enables lateral movement through the network.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This is known as pivoting and enables lateral movement through the network.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **We will cover how to identify, exploit, and prevent each of them through various methods.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **We will cover how to identify, exploit, and prevent each of these injection attacks.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **We will discuss how to identify, exploit, and prevent TLS attacks.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- **We will cover how to identify, exploit, and prevent each of these vulnerabilities.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>

## Fp Rule

- **A port forward or tunnel bound to the loopback interface is not a pivot channel and cannot be reached by the attacker.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where an SSH client-side forward plus a local relay on the tester box chains the loopback listener into an externally reachable proxy.
  sources: <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>
- **An SSH or SOCKS tunnel inside the estate is not attacker ingress unless traffic entered from an address the client does not control.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong when the client's own sanctioned jump host relays to the assessment scope, in which case an external-looking leg may still be in-house.
  sources: <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

## Chain Link

- **A reverse-tunnel implant on a compromised host turns that host into a generic TCP forwarder reachable from attacker infrastructure, so the next link gets reachability to internal-only management services without a credential, because the packet source is the internal host itself.**  
  `high_confidence` · score 0.899 · disproved by: If the internal service authenticates every request regardless of source, or egress filtering blocks the implant's outbound channel, or the tunnel is bound to a fixed destination that excludes the service being attempted, the handoff produces no new reachability and the pivot chain ends at the first host.
  sources: <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
