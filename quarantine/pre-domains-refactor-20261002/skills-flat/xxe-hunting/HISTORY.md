# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- xxe@current
+++ xxe@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 611 · OWASP A05:2021
 > evidence: 4 items, 4 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 An XML parser resolves external or entity-expanded content the attacker controls.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- xxe@current
+++ xxe@new
@@ -43,4 +43,4 @@
   - Sources: <https://www.w3.org/TR/2008/REC-xml-20081126/> · <https://bishopfox.com/blog/phpspreadsheet-versions1.5.0-xxe-advisory>
 
 ---
-Full class document: `classes/xxe.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xxe`
+Full class document: `skills/Web/xxe/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xxe`
```
