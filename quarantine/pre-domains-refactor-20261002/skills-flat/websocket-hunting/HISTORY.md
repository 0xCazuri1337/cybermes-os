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
--- websocket@current
+++ websocket@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 1004 · OWASP A04:2021
 > evidence: 6 items, 6 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 The persistent channel inherits origin, authorisation and message-validation weaknesses of its upgrade request.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- websocket@current
+++ websocket@new
@@ -52,4 +52,4 @@
   - Sources: <https://developer.okta.com/docs/concepts/session/> · <https://auth0.com/blog/confused-deputy-the-old-bug-that-ai-agents-keep-reintroducing/> · <https://auth0.com/blog/cross-site-request-forgery-csrf/>
 
 ---
-Full class document: `classes/websocket.md` · retrieve more with `python -m wks.cli search "<query>" --class-id websocket`
+Full class document: `skills/Web/websocket/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id websocket`
```
