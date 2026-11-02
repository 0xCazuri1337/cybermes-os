# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 3), FP rules 2, chains 0, state researching
- still missing: methodology, items, supported_items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 4 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- winrm@current
+++ winrm@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 4 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, chain
+> maturity: **researching** — missing: items, supported_items, chain
 
 PowerShell remoting authenticates over WinRM and commonly runs as the target's local context, so it is both a movement and a privilege mechanism.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- winrm@current
+++ winrm@new
@@ -37,4 +37,4 @@
   - Sources: <https://pentestlab.blog/2018/05/15/lateral-movement-winrm/> · <https://www.stationx.net/powershell-remoting/>
 
 ---
-Full class document: `classes/winrm.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
+Full class document: `skills/Network + AD/winrm/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id winrm`
```
