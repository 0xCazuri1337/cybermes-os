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
--- nosql@current
+++ nosql@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 943 · OWASP A03:2021
 > evidence: 7 items, 7 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 A document query is built from a parsed structure so type and operator semantics become attacker-controlled.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- nosql@current
+++ nosql@new
@@ -58,4 +58,4 @@
   - Sources: <https://blog.sonarsource.com/nosql-injections-in-rocket-chat/> · <https://blog.orange.tw/posts/2023-08-2023-webconf-the-evolution-of-web-security/>
 
 ---
-Full class document: `classes/nosql.md` · retrieve more with `python -m wks.cli search "<query>" --class-id nosql`
+Full class document: `skills/Web/nosql/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id nosql`
```
