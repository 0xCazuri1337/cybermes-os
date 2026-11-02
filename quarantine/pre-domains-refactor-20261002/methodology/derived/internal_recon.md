# Methodology — Internal Network Reconnaissance

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class internal_recon --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**References.** CWE-200

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Private address space is only unique within an enterprise, so addresses observed on an internal network carry local rather than global meaning and inference about host role is drawn from naming and addressing conventions rather than from any global registry.**

RFC 1918 states the consequence directly: addresses in private space are unique only within the enterprise, or among cooperating enterprises, so a private address identifies a host only relative to a vantage point inside the same space. That is the reason internal recon is inference: a DHCP-assigned address in a segment that conventionally serves a particular role is evidence about what runs there, and the reverse mapping — the address you can reach, the name you can resolve — is what turns reachability into a map. Two operational rules follow. First, private addresses must not be propagated across inter-enterprise links, so a private address appearing in external DNS records or leaked logs is itself an information disclosure. Second, because renumbering is costly, address-to-role mappings are stable, which is exactly what makes them predictive and worth enumerating deliberately rather than by opportunistic scanning.

- *Disproof:* If the internal network assigns addresses with no role convention and no name service correlates them, then there is no predictive mapping to exploit and host role must be determined by direct service identification instead.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1018/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1918.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.**

The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance. Each of these is a documented day-one administration action, and nltest in particular exists so administrators can enumerate domain controllers and trust status; the adversary reuses the binary rather than shipping a tool. The signal that distinguishes reconnaissance from administration is not the command but the temporal cluster: several of these commands inside a short window from a single process tree, a shape no administration workflow produces because an administrator queries one thing at a time. Without this rule the per-command alert fires on every domain query, the SOC tunes it away, and the real cluster is lost with it.

- *Disproof:* The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md); [redcanary.com](https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/)

## 3. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.**

A clean process-creation log is therefore not exculpatory, and a hunter who greps command-line telemetry for enumeration arguments will find nothing. Detection has to move to network-side RPC traffic and to the proxy process itself rather than to the command line the operator never typed. The claim is falsified if Sysmon or EDR process telemetry still captures the full argument string for the proxied invocation, which would mean the proxy does not actually strip it from process creation events.

- *Disproof:* If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language); [ired.team](https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md)

## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never touched.**

The chain is three published mechanisms composed, and each handoff is observable. Link one: enumeration returns the account list, and the filter for servicePrincipalName selects the subset that matters - the PowerView course material names exactly this join, describing the tools as useful for finding quick wins such as users that can be attacked via Kerberoasting or ASREPRoasting. Link two: with a low-privileged account and a valid TGT, the adversary requests TGS tickets with weakened encryption for the service accounts carrying SPNs, which does not require any access permission on those services, and cracks the tickets offline with no network activity - the credential that emerges is the service account's plaintext password. Link three: that password is an ordinary credential for every service that authenticates it, so SMB, WinRM, or RDP become authenticated remote-execution channels on hosts the enumeration never listed. This is why directory read access is graded above information disclosure: the enumeration output is not the finding, it is the ammunition. The ceiling on the chain is password policy - accounts generated automatically with complex passwords are not the target, accounts created manually by infrastructure administrators are.

- *Disproof:* Refuted if the directory does not expose servicePrincipalName values to the enumerating principal, or if every SPN-bearing account has a password that offline cracking did not recover within the assessment window; without a recovered service-account secret the chain stops at enumeration.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
