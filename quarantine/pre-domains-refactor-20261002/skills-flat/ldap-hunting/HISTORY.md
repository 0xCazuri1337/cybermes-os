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
--- ldap@current
+++ ldap@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 90 · OWASP A03:2021
 > evidence: 7 items, 7 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 A filter or path expression is built from attacker input, changing the query structure.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- ldap@current
+++ ldap@new
@@ -61,4 +61,4 @@
   - Sources: <https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc> · <https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-3>
 
 ---
-Full class document: `classes/ldap.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap`
+Full class document: `skills/Web/ldap/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap`
```
