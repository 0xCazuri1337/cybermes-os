# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 4), FP rules 0, chains 1, state researching
- still missing: methodology, items, fp_rules

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 4 (supported 4), FP rules 0, chains 1, state researching
- still missing: items, fp_rules

```diff
--- api_trust@current
+++ api_trust@new
@@ -11,7 +11,7 @@
 
 > surface `api` · CWE 918 · OWASP API8:2023
 > evidence: 4 items, 4 supported, 0 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, items, fp_rules
+> maturity: **researching** — missing: items, fp_rules
 
 A backend assumes its caller is trusted because the caller is internal, and the boundary is never enforced.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 0, chains 1, state researching
- still missing: items, fp_rules

```diff
--- api_trust@current
+++ api_trust@new
@@ -47,4 +47,4 @@
 - `ssrf` (3 shared chain(s))
 
 ---
-Full class document: `classes/api_trust.md` · retrieve more with `python -m wks.cli search "<query>" --class-id api_trust`
+Full class document: `skills/Web/api_trust/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id api_trust`
```
