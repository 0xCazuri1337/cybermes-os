# Internal Network Reconnaissance

## Definition

An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["internal recon", "internal reconnaissance", "internal enumeration", "host discovery", "network mapping", "subnet discovery", "service enumeration", "port scan"]

Canonical home for `internal_recon`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**

RFC 1918 states the consequence directly: addresses in private space are unique only within the enterprise, or among cooperating enterprises, so a private address identifies a host only relative to a vantage point inside the same space. That is the reason internal recon is inference: a DHCP-assigned address in a segment that conventionally serves a particular role is evidence about what runs there, and the reverse mapping — the address you can reach, the name you can resolve — is what turns reachability into a map. Two operational rules follow. First, private addresses must not be propagated across inter-enterprise links, so a private address appearing in external DNS records or leaked logs is itself an information disclosure. Second, because renumbering is costly, address-to-role mappings are stable, which is exactly what makes them predictive and worth enumerating deliberately rather than by opportunistic scanning.

*Disproof:* If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.

## Variations

**Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.**

A clean process-creation log is therefore not exculpatory, and a hunter who greps command-line telemetry for enumeration arguments will find nothing. Detection has to move to network-side RPC traffic and to the proxy process itself rather than to the command line the operator never typed. The claim is falsified if Sysmon or EDR process telemetry still captures the full argument string for the proxied invocation, which would mean the proxy does not actually strip it from process creation events.

*Disproof:* If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ad-enum-to-kerberoast-to-lateral-execution` — Directory enumeration to SPN enumeration to kerberoasted service account to lateral execution (goal: `domain_wide_lateral_movement`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.**

The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance. Each of these is a documented day-one administration action, and nltest in particular exists so administrators can enumerate domain controllers and trust status; the adversary reuses the binary rather than shipping a tool. The signal that distinguishes reconnaissance from administration is not the command but the temporal cluster: several of these commands inside a short window from a single process tree, a shape no administration workflow produces because an administrator queries one thing at a time. Without this rule the per-command alert fires on every domain query, the SOC tunes it away, and the real cluster is lost with it.

*Disproof:* The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
**Hypothesis:** A single native enumeration command observed on a host is evidence of attacker reconnaissance of the internal network.
- Invalidated by: The identical command is part of the documented administrative routine and appears on managed hosts under their own credentials; no enumerated name is referenced by any subsequent authentication event, so nothing downstream consumed the output.
- **Rejection rule:** One enumeration command is dual use. Before reporting reconnaissance, show the same command in the admin baseline and show a downstream consumer - an authentication event, a connection, or a file access - that references an enumerated name. Absent the consumer you have an unproven telemetry signal.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1018/>
- **elastic.co** (writeup)
  - <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md>
  - <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1918.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
