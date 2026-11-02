# Network Segmentation Analysis

## Definition

Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.

- **CWE:** CWE-1188
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["segmentation", "network segmentation", "segmentation analysis", "trust boundary", "firewall analysis", "security boundary", "vlan segmentation"]

Canonical home for `segmentation_analysis`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.**

Treat a finding here as a baseline deviation, not a signature hit. Concretely: establish what a normal RDP or LDAP session looks like per segment -- which source ranges, which hours, which ports, which volumes -- and then alert on the deviation from that specific per-segment baseline. A rule written once against a generic estate profile will either miss a re-routed session on a quiet segment or drown in noise on a busy one. Record the baseline inputs alongside the alert so a reviewer can see which declared fact the deviation was measured against.

*Disproof:* Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.

## Exploitation

**In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.**

This converts segmentation review from an architecture diagram exercise into a measured test: pivot from one compromised asset, record which zones accept the traffic, and compare the observed path against the documented boundary. An assumed boundary that a single pivot crosses is a finding regardless of how the diagram is drawn. The claim is falsified when pivot attempts from a single compromised asset are blocked at every zone boundary, which would show the barriers hold in practice.

*Disproof:* Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.

**Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.**

The measurable form of network segmentation is whether packets with private source or destination addresses cross a boundary. RFC 1918 requires that routing information about private networks not be propagated on inter-enterprise links and that packets with private addresses not be forwarded across them, and expects routers not using private space to filter such routing information. That gives a test rather than an assertion: attempt a connection from one segment to a private address in another and observe whether a route exists. A segmentation control that is documented but not enforced at the forwarding layer is not a control — the same applies to NAT and to inter-enterprise links, which is why a private address visible in external DNS or leaked logs is a boundary finding. Note also that private hosts can still reach external services through mediating gateways, so 'cannot route out' and 'cannot be routed to' are two different claims and both need testing.

*Disproof:* If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.**

The variables behind a segmentation rule are lists of addresses, dates, strings and numeric values that name the infrastructure the rule reasons about. Left empty or copied from another estate, they turn the rule into an anomaly generator against whatever happens to be on the wire: an authorised jump host, a new build agent, or a sanctioned vendor address all read as unknown. Before reporting, confirm the inventory was populated for this environment and check the flagged address against it; a finding whose supporting inventory was never filled in is a configuration defect, not an incident.

*Disproof:* Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/catalogue/paths>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1018/>
- **claroty.com** (research)
  - <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>
- **elastic.co** (writeup)
  - <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc1918.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
