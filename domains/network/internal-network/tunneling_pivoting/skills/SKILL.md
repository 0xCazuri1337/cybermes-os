---
name: tunneling_pivoting-hunting
description: Use when hunting Tunneling and Pivoting in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Tunneling and Pivoting — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 26 items, 6 supported, 2 FP rules, 1 chains
> maturity: **mature**

A tunnel carries one protocol inside another, so reachability that policy forbids directly can be reintroduced by a host that both sides accept.

**Also called:** tunneling, tunnelling, pivoting, socks, socks proxy, port forwarding, proxy, chisel, reverse tunnel


## Recon signals (where to look)

- Continued operator access carried over a legitimate service with no new listening port open is an early observable for tunnelling that no new-port rule will ever fire on. _(unverified)_
  - **Disproof:** If the remote-access exposure is attributable to an approved corporate tunnel service whose domain is on the sanctioned allowlist and whose client was deployed by the platform team, then the session is sanctioned remote access and the tunnelling hypothesis is invalidated.
  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/>

## Techniques (what to change)

- This is known as pivoting and enables lateral movement through the network. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This is known as pivoting and enables lateral movement through the network.".
  - Sources: <https://attack.mitre.org/techniques/T1090/> · <https://hackertarget.com/ssh-examples-tunnels/>
- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- This is known as pivoting and enables lateral movement through the network. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This is known as pivoting and enables lateral movement through the network.".
  - Sources: <https://attack.mitre.org/techniques/T1090/> · <https://hackertarget.com/ssh-examples-tunnels/>
- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- Tunneling is a technique that allows us to encapsulate traffic within another protocol so that it looks like a benign traffic stream. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Tunneling is a technique that allows us to encapsulate traffic within another protocol so ".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- We will cover how to identify, exploit, and prevent each of them through various methods. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of them through various methods.".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- This module covers the most common attacks and vulnerabilities that can affect web application sessions, such as Session Hijacking, Session Fixation, Cross-Site Request Forgery, Cross-Site Scripting, and Open Redirects. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This module covers the most common attacks and vulnerabilities that can affect web applica".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- We will cover how to identify, exploit, and prevent each of these injection attacks. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these injection attacks.".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- Buffer overflows are common vulnerabilities in software applications that can be exploited to achieve remote code execution (RCE) or perform a Denial-of-Service (DoS) attack. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Buffer overflows are common vulnerabilities in software applications that can be exploited".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- We will discuss how to identify, exploit, and prevent each vulnerability. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent each vulnerability.".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- We will discuss how to identify, exploit, and prevent TLS attacks. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will discuss how to identify, exploit, and prevent TLS attacks.".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- We will cover how to identify, exploit, and prevent each of these vulnerabilities. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover how to identify, exploit, and prevent each of these vulnerabilities.".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://hackertarget.com/ssh-examples-tunnels/>
- For all exercises, we will assume that the target company Inlanefreight has hired us to perform an in-depth penetration test with a heavy focus on AD security, where stealth and bypassing stringent security controls are not a requirement. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "For all exercises, we will assume that the target company Inlanefreight has hired us to pe".
  - Sources: <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  - Sources: <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser and result in complete web application compromise if chained together with other vulnerabilities. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- Using one compromised machine to access another is called pivoting and allows us to access networks and resources that are not directly accessible to us through the compromised host. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Using one compromised machine to access another is called pivoting and allows us to access".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>
- Command injection vulnerabilities can be leveraged to compromise a hosting server and its entire network. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Command injection vulnerabilities can be leveraged to compromise a hosting server and its ".
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/>
- A pivot is established by tunnelling traffic for a second network segment through the already-compromised host, which carries no credentials of its own.
  - **Disproof:** Refuted when the compromised host cannot open outbound connections to the second segment, or no listener can be bound on the far side, so the tunnel never carries traffic.
  - Sources: <https://attack.mitre.org/techniques/T1090/> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/04.%20Exploitation/20.%20Pivoting%2C%20Tunneling%20%26%20Port%20Forwarding/Pivoting%2C%20Tunneling%20%26%20Port%20Forwarding.md>
- A tunnel carries one protocol inside another, so a reachability that policy forbids directly can be reintroduced through a host both sides accept — the boundary that matters is the tunnel endpoint, not the inner protocol.
  - **Disproof:** If egress from the compromised segment is filtered such that no permitted-protocol channel to an attacker-controlled or third host can carry an inner session, and no dual-homed host bridges the segments, then the tunnel cannot reintroduce the forbidden reachability.
  - Sources: <https://attack.mitre.org/techniques/T1090/> · <https://www.rfc-editor.org/rfc/rfc4459.html>

## Tests

- To decide this case, observe: Discard when the tunnel was observed entirely between hosts inside the scoped network: the intrusion report shows the actor's SSH tunnel was built to present RDP access from a public IP address they owned, which is what distinguishes ingress from internal administration.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (tunneling_pivoting.fprule.tunnel_without_ingress) states the full boundary.
  - Sources: <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

## False-positive rules (when to reject it)

- A port forward or tunnel bound to the loopback interface is not a pivot channel and cannot be reached by the attacker.
  - **Disproof:** Would be wrong where an SSH client-side forward plus a local relay on the tester box chains the loopback listener into an externally reachable proxy.
  - Sources: <https://www.nccgroup.com/research/nameless-and-shameless-ransomware-encryption-via-bitlocker/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>
- An SSH or SOCKS tunnel inside the estate is not attacker ingress unless traffic entered from an address the client does not control.
  - **Disproof:** Would be wrong when the client's own sanctioned jump host relays to the assessment scope, in which case an external-looking leg may still be in-house.
  - Sources: <https://www.nccgroup.com/research-blog/is-this-the-real-life-is-this-just-fantasy-caught-in-a-landslide-noescape-from-ncc-group/> · <https://www.thehacker.recipes/infra/pivoting/port-forwarding>

## Chaining opportunities

- A reverse-tunnel implant on a compromised host turns that host into a generic TCP forwarder reachable from attacker infrastructure, so the next link gets reachability to internal-only management services without a credential, because the packet source is the internal host itself.
  - **Disproof:** If the internal service authenticates every request regardless of source, or egress filtering blocks the implant's outbound channel, or the tunnel is bound to a fixed destination that excludes the service being attempted, the handoff produces no new reachability and the pivot chain ends at the first host.
  - Sources: <https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/> · <https://hackertarget.com/ssh-examples-tunnels/>

---
Full class document: `domains/network/internal-network/tunneling_pivoting/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id tunneling_pivoting`
