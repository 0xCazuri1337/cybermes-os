# Internal Network Reconnaissance

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 4 items, 4 supported, 2 FP rules, 1 chains

An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**Aliases:** internal recon, internal reconnaissance, internal enumeration, host discovery, network mapping, subnet discovery, service enumeration, port scan

## Technique

- **Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**  
  `high_confidence` · score 0.798 · disproved by: If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
  sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>

## Fp Rule

- **A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.**  
  `high_confidence` · score 0.844 · disproved by: The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
  sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>

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

Not yet satisfied: `items`
