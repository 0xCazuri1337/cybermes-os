# Methodology — Network Segmentation Analysis

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class segmentation_analysis --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.

**References.** CWE-1188

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.**

Treat a finding here as a baseline deviation, not a signature hit. Concretely: establish what a normal RDP or LDAP session looks like per segment -- which source ranges, which hours, which ports, which volumes -- and then alert on the deviation from that specific per-segment baseline. A rule written once against a generic estate profile will either miss a re-routed session on a quiet segment or drown in noise on a busy one. Record the baseline inputs alongside the alert so a reviewer can see which declared fact the deviation was measured against.

- *Disproof:* Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/catalogue/paths); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.**

This converts segmentation review from an architecture diagram exercise into a measured test: pivot from one compromised asset, record which zones accept the traffic, and compare the observed path against the documented boundary. An assumed boundary that a single pivot crosses is a finding regardless of how the diagram is drawn. The claim is falsified when pivot attempts from a single compromised asset are blocked at every zone boundary, which would show the barriers hold in practice.

- *Disproof:* Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.
- *Evidence:* high_confidence — [claroty.com](https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security); [elastic.co](https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a segmentation_analysis finding until it is distinguished from the adjacent behaviour this class also covers. "While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them..." and "Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: While accessing and managing systems such as programmable logic controllers (PLCs) and human-machine interfaces (HMIs) on the internet might mean added convenience, such as real-time monitoring and in-depth analysis, it also exposes them...

Adjacent behaviour that produces the same observable result: Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Remote-session segmentation analysis has no single universal indicator" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1018/); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

**A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.**

The variables behind a segmentation rule are lists of addresses, dates, strings and numeric values that name the infrastructure the rule reasons about. Left empty or copied from another estate, they turn the rule into an anomaly generator against whatever happens to be on the wire: an authorised jump host, a new build agent, or a sanctioned vendor address all read as unknown. Before reporting, confirm the inventory was populated for this environment and check the flagged address against it; a finding whose supporting inventory was never filled in is a configuration defect, not an incident.

- *Disproof:* Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
- *Evidence:* high_confidence — [claroty.com](https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
