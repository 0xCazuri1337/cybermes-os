# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 444 · OWASP A04:2021
 > evidence: 4 items, 4 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 Unkeyed attacker input is reflected into a response the cache stores and serves to others.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- cache_poisoning@current
+++ cache_poisoning@new
@@ -40,4 +40,4 @@
   - Sources: <https://www.proofpoint.com/us/blog/cloud-security/new-vulnerabilities-bypass-multi-factor-authentication-microsoft-365> · <https://www.helpnetsecurity.com/2025/01/23/web-cache-vulnerability-scanner-detecting-web-cache-poisoning/>
 
 ---
-Full class document: `classes/cache_poisoning.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
+Full class document: `skills/Web/cache_poisoning/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cache_poisoning`
```
