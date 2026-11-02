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
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-16 · OWASP —
 > evidence: 2 items, 2 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> maturity: **researching** — missing: items, supported_items, fp_rules, chain
 
 A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 2 (supported 2), FP rules 1, chains 0, state researching
- still missing: items, supported_items, fp_rules, chain

```diff
--- service_enumeration_detail@current
+++ service_enumeration_detail@new
@@ -31,4 +31,4 @@
   - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>
 
 ---
-Full class document: `classes/service_enumeration_detail.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
+Full class document: `skills/Network + AD/service_enumeration_detail/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
```
