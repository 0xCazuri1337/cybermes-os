# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: methodology, items, supported_items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -11,7 +11,7 @@
 
 > surface `ad` · CWE CWE-521 · OWASP —
 > evidence: 3 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, chain
+> maturity: **researching** — missing: items, supported_items, chain
 
 Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 3 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- password_attacks@current
+++ password_attacks@new
@@ -34,4 +34,4 @@
   - Sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
 
 ---
-Full class document: `classes/password_attacks.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
+Full class document: `skills/Network + AD/password_attacks/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
```
