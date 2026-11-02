# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 1321 · OWASP A08:2021
 > evidence: 7 items, 7 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 Caller input reaches a property write path that mutates a shared prototype.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- prototype_pollution@current
+++ prototype_pollution@new
@@ -58,4 +58,4 @@
   - Sources: <https://blog.sonarsource.com/blitzjs-prototype-pollution/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
 ---
-Full class document: `classes/prototype_pollution.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`
+Full class document: `skills/Web/prototype_pollution/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id prototype_pollution`
```
