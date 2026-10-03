# Internal Network Reconnaissance

> surface: `net` · CWE: CWE-200 · OWASP: —
> maturity: **mature** — 12 items, 12 supported, 2 FP rules, 1 chains

An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**Aliases:** internal recon, internal reconnaissance, internal enumeration, host discovery, network mapping, subnet discovery, service enumeration, port scan

## Technique

- **We are not claiming complete detection of every custom deserializer.\n\n## How this Java deserialization vulnerability differs from Log4Shell\nLog4j 2 can *emit* log events over the network (for example, `SocketAppender`).**  
  `high_confidence` · score 0.7995 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We are not claiming complete detection of every custom deserializer.\n\n## How this Java d".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**  
  `high_confidence` · score 0.798 · disproved by: If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
  sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>
- **If you need to know which tenant an event came from, this is how. */\n| WHERE user.name == \"svc-deploy\" AND event.category == \"authentication\"\n| KEEP _index, @timestamp, event.action, source.ip, host.name\n /* KEEP is not cosmetic.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If you need to know which tenant an event came from, this is how. */\n| WHERE user.name ==".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Apache does not class allowlist bypasses like this one as product vulnerabilities, because Log4j does not deserialize data during normal logging.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Apache does not class allowlist bypasses like this one as product vulnerabilities, because".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Chained together, they let an attacker-controlled object graph deserialize with no filter applied.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Chained together, they let an attacker-controlled object graph deserialize with no filter ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`MarshalledObject.get()` deserializes `objBytes` on an inner `ObjectInputStream` that is not a `FilteredObjectInputStream`.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The receiver can still look healthy and fall back to `SimpleMessage(messageString)`.\n\n`M".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInputStream` both ship in core, so a stock deployment using the built-in socket server is exposed without any leftover or custom receiver. #4255 bypasses the CVE-2017-5645 fix inside the same release that introduced it.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The exception is 2.8.2: there, `TcpSocketServer` and the (log4j-core) `FilteredObjectInput".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-api); we confirmed command execution on 2.8.2 and on 2.11.0–2.26.1. Versions 2.9.1 and 2.10.0 carry the field, but no FOIS, so the specific allowlist bypass does not apply there.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Both coincide at 2.8.2 (FOIS in log4j-core) and at 2.11.0 through 2.26.1 (FOIS in log4j-ap".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that JVM.\n\n## Setting up detection for Java deserialization attacks\n1.**  
  `high_confidence` · score 0.772 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If it does not, the inner `get()` can still run unfiltered code in whatever *is* on that J".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>

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
