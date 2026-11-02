# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- session@current
+++ session@new
@@ -11,7 +11,7 @@
 
 > surface `identity` · CWE 384 · OWASP A07:2021
 > evidence: 6 items, 6 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 Session identity, lifetime or binding is weaker than the operation's risk requires.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- session@current
+++ session@new
@@ -52,4 +52,4 @@
   - Sources: <https://capec.mitre.org/data/definitions/61.html> · <https://www.zaproxy.org/docs/alerts/40013-4/>
 
 ---
-Full class document: `classes/session.md` · retrieve more with `python -m wks.cli search "<query>" --class-id session`
+Full class document: `skills/Web/session/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id session`
```
