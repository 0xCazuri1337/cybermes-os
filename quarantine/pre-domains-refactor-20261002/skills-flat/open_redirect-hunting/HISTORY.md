# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- open_redirect@current
+++ open_redirect@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 601 · OWASP A01:2021
 > evidence: 5 items, 5 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 A redirect target is not constrained to a trusted destination.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- open_redirect@current
+++ open_redirect@new
@@ -46,4 +46,4 @@
   - Sources: <https://httpwg.org/specs/rfc7231.html> · <https://blog.qualys.com/product-tech/2019/12/11/cve-2019-11016-open-redirect-vulnerability>
 
 ---
-Full class document: `classes/open_redirect.md` · retrieve more with `python -m wks.cli search "<query>" --class-id open_redirect`
+Full class document: `skills/Web/open_redirect/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id open_redirect`
```
