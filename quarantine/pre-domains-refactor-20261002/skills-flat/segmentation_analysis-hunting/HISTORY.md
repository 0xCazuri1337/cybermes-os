# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 2 (supported 2), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 2 (supported 2), FP rules 0, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-1188 · OWASP —
 > evidence: 2 items, 2 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.
 
```

## 2026-10-02 12:21 — 36 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-1188 · OWASP —
-> evidence: 2 items, 2 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, fp_rules, chain
+> evidence: 4 items, 4 supported, 1 FP rules, 0 chains
+> maturity: **researching** — missing: items, fp_rules, chain
 
 Segmentation is a claim about which pairs of hosts may communicate; the claim is only as good as the paths actually available.
 
 **Also called:** segmentation, network segmentation, segmentation analysis, trust boundary, firewall analysis, security boundary, vlan segmentation
 
+
+## Recon signals (where to look)
+
+- Remote-session segmentation analysis has no single universal indicator set; each detection must be tailored to the protocol, the host's typical behaviour and its deviation from that baseline.
+  - **Disproof:** Proof the claim wrong would be a segmentation detection that generalises across estates without per-environment input -- a rule that fires on a real re-routed RDP session in an environment where it was never tuned and suppresses nothing else; or documentation showing the underlying protocol itself yields a fixed indicator that identifies the attack without baseline comparison.
+  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ## Techniques (what to change)
 
@@ -27,5 +33,11 @@
   - **Disproof:** If forwarding between segments is verifiably blocked at the routing layer and no dual-homed host bridges the boundary, then the segmentation control holds for the paths tested and the claim of a segmentation gap is not supported.
   - Sources: <https://attack.mitre.org/techniques/T1018/> · <https://www.rfc-editor.org/rfc/rfc1918.html>
 
+## False-positive rules (when to reject it)
+
+- A segmentation finding is a false positive unless the known-infrastructure inventory behind it -- domain controllers, DNS servers, time ranges, critical segments -- was actually populated for that environment.
+  - **Disproof:** Proof the rule wrong would be an environment where a properly populated inventory still produces a finding on a peer that is in fact sanctioned, showing the inventory was incomplete rather than the rule too strict; or evidence that the rule flagged a peer absent from the inventory but authorised by an out-of-band process, which would mean the inventory itself must be reconciled before any of its findings are trusted.
+  - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
+
 ---
 Full class document: `classes/segmentation_analysis.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- segmentation_analysis@current
+++ segmentation_analysis@new
@@ -40,4 +40,4 @@
   - Sources: <https://academy.hackthebox.com/catalogue/paths> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
 
 ---
-Full class document: `classes/segmentation_analysis.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
+Full class document: `skills/Network + AD/segmentation_analysis/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id segmentation_analysis`
```
