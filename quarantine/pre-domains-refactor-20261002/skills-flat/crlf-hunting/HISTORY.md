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
--- crlf@current
+++ crlf@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 93 · OWASP A03:2021
 > evidence: 7 items, 7 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 User input reaches a header or line boundary the protocol treats as a delimiter.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- crlf@current
+++ crlf@new
@@ -61,4 +61,4 @@
   - Sources: <https://blog.cloudflare.com/resolving-a-request-smuggling-vulnerability-in-pingora> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
 
 ---
-Full class document: `classes/crlf.md` · retrieve more with `python -m wks.cli search "<query>" --class-id crlf`
+Full class document: `skills/Web/crlf/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id crlf`
```
