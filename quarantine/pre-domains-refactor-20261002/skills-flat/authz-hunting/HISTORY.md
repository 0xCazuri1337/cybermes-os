# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 13:38 — 30 diff lines
- items: 5 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- authz@current
+++ authz@new
@@ -10,13 +10,19 @@
      python -m wks.skillgen -->
 
 > surface `api` · CWE CWE-862 · OWASP API5:2023
-> evidence: 4 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: items, supported_items, chain
+> evidence: 5 items, 4 supported, 2 FP rules, 0 chains
+> maturity: **researching** — missing: items, chain
 
 An endpoint checks that a caller is authenticated but not that they hold the role or permission the operation requires.
 
 **Also called:** missing function level authorization, bfla, admin endpoint exposure, unauthorized access to administrative function
 
+
+## Techniques (what to change)
+
+- The product does not perform an authorization check when an actor attempts to access a resource or perform an action.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
+  - Sources: <https://cwe.mitre.org/data/definitions/862.html> · <https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/>
 
 ## False-positive rules (when to reject it)
 
@@ -40,4 +46,4 @@
   - Sources: <https://learn.microsoft.com/en-us/aspnet/core/security/authorization> · <https://www.microsoft.com/en-us/security/blog/2026/09/09/threat-matrix-mapping-threats-across-cloud-web-applications/>
 
 ---
-Full class document: `classes/authz.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authz`
+Full class document: `skills/Web/authz/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id authz`
```
