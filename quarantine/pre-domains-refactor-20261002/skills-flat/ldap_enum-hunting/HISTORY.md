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
--- ldap_enum@current
+++ ldap_enum@new
@@ -11,7 +11,7 @@
 
 > surface `net` · CWE CWE-200 · OWASP —
 > evidence: 4 items, 3 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, chain
+> maturity: **researching** — missing: items, supported_items, chain
 
 LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 4 (supported 3), FP rules 2, chains 0, state researching
- still missing: items, supported_items, chain

```diff
--- ldap_enum@current
+++ ldap_enum@new
@@ -40,4 +40,4 @@
   - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://www.thehacker.recipes/ad/recon/ldap>
 
 ---
-Full class document: `classes/ldap_enum.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap_enum`
+Full class document: `skills/Network + AD/ldap_enum/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap_enum`
```
