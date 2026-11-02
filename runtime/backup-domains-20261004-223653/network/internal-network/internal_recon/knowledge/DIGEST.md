# Internal Network Reconnaissance

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 6 items, 3 supported, 2 FP rules, 1 chains

An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**Aliases:** internal recon, internal reconnaissance, internal enumeration, host discovery, network mapping, subnet discovery, service enumeration, port scan

## Technique

- **We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).**  
  `under_review` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**  
  `under_review` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**  
  `under_review` · score 0.704 · disproved by: If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
  sources: <https://www.rfc-editor.org/rfc/rfc1918.html>

## Fp Rule

- **Reject a internal_recon finding until it is distinguished from the adjacent behaviour this class also covers. "A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never..." and "Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Routing rpcclient enumeration through a Cobalt Strike socks proxy caus" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
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

Not yet satisfied: `items`, `supported_items`
