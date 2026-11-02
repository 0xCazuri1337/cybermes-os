---
name: segmentation_analysis-hunting
description: Use when hunting Network Segmentation Analysis in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Network Segmentation Analysis — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-1188 · OWASP —
> evidence: 4 items, 4 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.

**Also called:** segmentation, network segmentation, segmentation analysis, trust boundary, firewall analysis, security boundary, vlan segmentation


## Recon signals (where to look)

- Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.
  - **Disproof:** Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.
  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Techniques (what to change)

- In an inadequately segmented network, compromising a single interlinked device is sufficient to reach lateral movement across connected devices, so segmentation analysis must test whether one foothold actually crosses a barrier.
  - **Disproof:** Pivot attempts from a single compromised asset that are blocked at every zone boundary would refute the claim for that network.
  - Sources: <https://www.claroty.com/blog/why-network-segmentation-matters-for-ot-security> · <https://www.elastic.co/security-labs/blog/hunting-for-lateral-movement-using-event-query-language>
- Private address space defines the internal boundary as a routing property — private addresses must not be propagated across inter-enterprise links — so segmentation claims are testable against forwarding behaviour rather than against policy documents.
  - **Disproof:** If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.
  - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>

## False-positive rules (when to reject it)

- A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.
  - **Disproof:** Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

---
Full class document: `skills/Network + AD/segmentation_analysis/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
