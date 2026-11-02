# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 2 (supported 2), FP rules 1, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 2 (supported 2), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- misconfig@current
+++ misconfig@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 16 · OWASP A05:2021
 > evidence: 2 items, 2 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 A deployable default or an absent hardening control leaves a capability the design assumed was closed.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 2 (supported 2), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- misconfig@current
+++ misconfig@new
@@ -31,4 +31,4 @@
   - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163> · <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>
 
 ---
-Full class document: `classes/misconfig.md` · retrieve more with `python -m wks.cli search "<query>" --class-id misconfig`
+Full class document: `skills/Web/misconfig/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id misconfig`
```
