# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 1, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 5 (supported 5), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -11,7 +11,7 @@
 
 > surface `infra` · CWE 404 · OWASP A10:2021
 > evidence: 5 items, 5 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 A DNS record still points at a de-provisioned service that anyone can now claim.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- subdomain_takeover@current
+++ subdomain_takeover@new
@@ -46,4 +46,4 @@
   - Sources: <https://httpwg.org/specs/rfc6265.html> · <https://blog.qualys.com/product-tech/2024/01/11/totalcloud-insights-crafting-effective-indicators-of-compromise-iocs-for-sub-domain-takeover-risk-detection>
 
 ---
-Full class document: `classes/subdomain_takeover.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`
+Full class document: `skills/Web/subdomain_takeover/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id subdomain_takeover`
```
