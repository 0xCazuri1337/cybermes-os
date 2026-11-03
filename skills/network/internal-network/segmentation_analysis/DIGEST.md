<!-- GENERATED from db/wks.db — do not edit -->
# Network Segmentation Analysis

> surface: `net` · CWE: CWE-1188 · OWASP: —
> maturity: **researching** — 9 items, 7 supported, 1 FP rules, 1 chains

Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.

**Aliases:** segmentation, network segmentation, segmentation analysis, trust boundary, firewall analysis, security boundary, vlan segmentation

## Signal

- **Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.**  
  `high_confidence` · score 0.7995 · disproved by: Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.
  sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.**  
  `high_confidence` · score 0.8715 · disproved by: Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.
  sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- **Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.**  
  `high_confidence` · score 0.798 · disproved by: If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.
  sources: <https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml> · <https://www.rfc-editor.org/rfc/rfc1918.html>
- **Attackers chain pivots through compromised hosts to reach segments that are not directly accessible from the initial foothold.**  
  `high_confidence` · score 0.743 · disproved by: No route exists between segments and firewall rules deny cross-segment traffic by default.
  sources: <https://alexsusanu.com/kb/pentesting/pentest_network_pivoting_guide/> · <https://hive.blog/hive-196387/@scipio/learn-ethical-hacking-34-pivoting-and-lateral-movement-spreading-through-networks>
- **VLAN hopping via switch spoofing or double-tagging lets an attacker escape a restricted VLAN and reach other segments.**  
  `supported` · score 0.707 · disproved by: DTP is disabled and ports are hardcoded as access, or VLAN hopping attempts are detected and blocked.
  sources: <https://a7.de/en/services/penetration-testing/network/> · <https://primethreat.com/network-security/>

## Fp Rule

- **A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.**  
  `high_confidence` · score 0.772 · disproved by: Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
  sources: <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/> · <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security>

## Concept

- **Classic perimeter firewalls only inspect north-south traffic, leaving east-west lateral movement largely unfiltered.**  
  `supported` · score 0.707 · disproved by: East-west traffic is inspected by internal firewalls or microsegmentation policy.
  sources: <https://primethreat.com/network-security/> · <https://www.elisity.com/blog/microsegmentation-in-manufacturing-omdia-survey-findings-1>

## Known gaps

Not yet satisfied: `items`, `fp_rules`
