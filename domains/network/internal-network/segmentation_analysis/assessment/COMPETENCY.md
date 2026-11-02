# Methodology — Network Segmentation Analysis

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class segmentation_analysis --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.**

The measurable form of network segmentation is whether packets with private source or destination addresses cross a boundary. RFC 1918 requires that routing information about private networks not be propagated on inter-enterprise links and that packets with private addresses not be forwarded across them, and expects routers not using private space to filter such routing information. That gives a test rather than an assertion: attempt a connection from one segment to a private address in another and observe whether a route exists. A segmentation control that is documented but not enforced at the forwarding layer is not a control — the same applies to NAT and to inter-enterprise links, which is why a private address visible in external DNS or leaked logs is a boundary finding. Note also that private hosts can still reach external services through mediating gateways, so 'cannot route out' and 'cannot be routed to' are two different claims and both need testing.

- *Disproof:* If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.
- *Evidence:* high_confidence — [iana.org](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc1918.html)

**Attackers chain pivots through compromised hosts to reach segments that are not directly accessible from the initial foothold.**

A compromised DMZ host may reach the internal LAN but not the database segment. The attacker pivots through the LAN host to reach the database segment, then onward to management VLANs. Network segmentation is effective only when no route exists between segments, forcing the attacker to compromise a new host in each segment.

- *Disproof:* No route exists between segments and firewall rules deny cross-segment traffic by default.
- *Evidence:* high_confidence — [alexsusanu.com](https://alexsusanu.com/kb/pentesting/pentest_network_pivoting_guide/); [hive.blog](https://hive.blog/hive-196387/@scipio/learn-ethical-hacking-34-pivoting-and-lateral-movement-spreading-through-networks)

**VLAN hopping via switch spoofing or double-tagging lets an attacker escape a restricted VLAN and reach other segments.**

Switch spoofing abuses DTP auto-trunking to make an access port become a trunk, granting access to all VLANs. Double-tagging nests an 802.1Q tag inside another to escape the native VLAN. Both are mitigated by disabling DTP, hardcoding access ports, and moving the native VLAN off VLAN 1.

- *Disproof:* DTP is disabled and ports are hardcoded as access, or VLAN hopping attempts are detected and blocked.
- *Evidence:* supported — [a7.de](https://a7.de/en/services/penetration-testing/network/); [primethreat.com](https://primethreat.com/network-security/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

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
