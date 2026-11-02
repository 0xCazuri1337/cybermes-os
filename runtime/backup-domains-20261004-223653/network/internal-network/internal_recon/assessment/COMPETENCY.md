# Methodology — Internal Network Reconnaissance

> Derived from 3 verified items. Regenerate with `python -m wks.methodgen --class internal_recon --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** An internal network is not uniform: naming and addressing patterns predict what a host runs, so enumeration is inference as much as probing.

**References.** CWE-200

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a internal_recon finding until it is distinguished from the adjacent behaviour this class also covers. "A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never..." and "Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never...

Adjacent behaviour that produces the same observable result: Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Routing rpcclient enumeration through a Cobalt Strike socks proxy caus" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 2. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Routing rpcclient enumeration through a Cobalt Strike socks proxy causes the enumeration arguments to never appear in the host's process-creation command line, so command-line based detection of internal domain recon returns nothing.**

A clean process-creation log is therefore not exculpatory, and a hunter who greps command-line telemetry for enumeration arguments will find nothing. Detection has to move to network-side RPC traffic and to the proxy process itself rather than to the command line the operator never typed. The claim is falsified if Sysmon or EDR process telemetry still captures the full argument string for the proxied invocation, which would mean the proxy does not actually strip it from process creation events.

- *Disproof:* If Sysmon or EDR process telemetry still captures the full rpcclient argument string when invoked through a socks proxy, the claim would be refuted.
- *Evidence:* high_confidence — [elastic.co](https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language); [ired.team](https://www.ired.team/offensive-security/enumeration-and-discovery/enumerating-windows-domains-using-rpcclient-through-socksproxy-bypassing-command-line-logging.md)

## 3. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A directory enumeration filtered to SPN-bearing accounts hands the next link exactly the input kerberoasting consumes, and the recovered service-account password is an authenticated remote-execution channel on hosts the enumeration never touched.**

The chain is three published mechanisms composed, and each handoff is observable. Link one: enumeration returns the account list, and the filter for servicePrincipalName selects the subset that matters - the PowerView course material names exactly this join, describing the tools as useful for finding quick wins such as users that can be attacked via Kerberoasting or ASREPRoasting. Link two: with a low-privileged account and a valid TGT, the adversary requests TGS tickets with weakened encryption for the service accounts carrying SPNs, which does not require any access permission on those services, and cracks the tickets offline with no network activity - the credential that emerges is the service account's plaintext password. Link three: that password is an ordinary credential for every service that authenticates it, so SMB, WinRM, or RDP become authenticated remote-execution channels on hosts the enumeration never listed. This is why directory read access is graded above information disclosure: the enumeration output is not the finding, it is the ammunition. The ceiling on the chain is password policy - accounts generated automatically with complex passwords are not the target, accounts created manually by infrastructure administrators are.

- *Disproof:* Refuted if the directory does not expose servicePrincipalName values to the enumerating principal, or if every SPN-bearing account has a password that offline cracking did not recover within the assessment window; without a recovered service-account secret the chain stops at enumeration.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Test sequence, Validation, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
