# Internal Network Reconnaissance

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 8 items, 7 supported, 1 FP rules, 1 chains

An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**Aliases:** internal recon, internal reconnaissance, internal enumeration, host discovery, network mapping, subnet discovery, service enumeration, port scan

## Technique

- **Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**  
  `high_confidence` · score 0.798 · disproved by: If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
  sources: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml> · <https://www.rfc-editor.org/rfc/rfc1918.html>
- **If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“If you need to know which tenant an event came from, this is how. */\n| WHERE us”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Service enumeration with nmap -sV and -sC identifies running services and their versions on discovered internal hosts.**  
  `high_confidence` · score 0.743 · disproved by: All ports are filtered or closed, or service detection returns no version information.
  sources: <https://charlesreid1.com/wiki/Nmap/Short_Course/Lecture_8> · <https://nmap.org/book/man-briefoptions.html>
- **Internal host discovery begins with a ping sweep or ARP scan to enumerate live hosts on adjacent subnets before port scanning.**  
  `supported` · score 0.707 · disproved by: No live hosts respond to ARP/ICMP, or host discovery is blocked by network segmentation and VLAN ACLs.
  sources: <https://charlesreid1.com/wiki/Nmap/Short_Course/Lecture_8> · <https://nmap.org/book/man-briefoptions.html>
- **When direct access is unavailable, a compromised host acts as a pivot point via SOCKS proxy or SSH tunnel to reach internal networks.**  
  `supported` · score 0.707 · disproved by: No egress path exists from the compromised host, or proxying is blocked by egress filtering.
  sources: <https://charlesreid1.com/wiki/Nmap/Short_Course/Lecture_8> · <https://hackersmanifest.com/internal-pentest/02-reconnaissance>

## Fp Rule

- **Reject a internal_recon finding until it is distinguished from the adjacent behaviour this class also covers. "A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never..." and "Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Routing rpcclient enumeration through a Cobalt Strike socks proxy caus" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Bypass

- **Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.**  
  `high_confidence` · score 0.783 · disproved by: If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.
  sources: <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language> · <https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md>

## Chain Link

- **A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never touched.**  
  `high_confidence` · score 0.8875 · disproved by: Refuted if the directory does not expose servicePrincipalName values to the enumerating principal, or if every SPN-bearing account has a password that offline cracking did not recover within the assessment window; without a recovered service-account secret the chain stops at enumeration.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## False-positive rules

- **Hypothesis:** A single native enumeration command observed on a host is evidence of attacker reconnaissance of the internal network.
  - **Invalidated by:** The identical command is part of the documented administrative routine and appears on managed hosts under their own credentials; no enumerated name is referenced by any subsequent authentication event, so nothing downstream consumed the output.
  - **Rule:** One enumeration command is dual use. Before reporting reconnaissance, show the same command in the admin baseline and show a downstream consumer - an authentication event, a connection, or a file access - that references an enumerated name. Absent the consumer you have an unproven telemetry signal.

## Related classes (via chains)

- `lateral_movement` Lateral Movement (1 chains)
- `info_disclosure` Information Disclosure (1 chains)
- `ad_enumeration` Active Directory Enumeration (1 chains)

## Known gaps

Not yet satisfied: `items`, `fp_rules`
