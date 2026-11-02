# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 14 (supported 14), FP rules 1, chains 1, state researching
- still missing: methodology, fp_rules

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 14 (supported 14), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 200 · OWASP A01:2021
 > evidence: 14 items, 14 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: methodology, fp_rules
+> maturity: **researching** — missing: fp_rules
 
 Error output, directory listings or metadata reveal more about the system than the caller should learn.
 
```

## 2026-10-02 12:21 — 21 diff lines
- items: 14 (supported 14), FP rules 1, chains 2, state researching
- still missing: fp_rules

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 200 · OWASP A01:2021
-> evidence: 14 items, 14 supported, 1 FP rules, 1 chains
+> evidence: 14 items, 14 supported, 1 FP rules, 2 chains
 > maturity: **researching** — missing: fp_rules
 
 Error output, directory listings or metadata reveal more about the system than the caller should learn.
@@ -87,6 +87,9 @@
 ## Chains to
 
 - `sqli` (3 shared chain(s))
+- `lateral_movement` (1 shared chain(s))
+- `internal_recon` (1 shared chain(s))
+- `ad_enumeration` (1 shared chain(s))
 
 ---
 Full class document: `classes/info_disclosure.md` · retrieve more with `python -m wks.cli search "<query>" --class-id info_disclosure`
```

## 2026-10-02 13:38 — 8 diff lines
- items: 14 (supported 14), FP rules 1, chains 2, state researching
- still missing: fp_rules

```diff
--- info_disclosure@current
+++ info_disclosure@new
@@ -92,4 +92,4 @@
 - `ad_enumeration` (1 shared chain(s))
 
 ---
-Full class document: `classes/info_disclosure.md` · retrieve more with `python -m wks.cli search "<query>" --class-id info_disclosure`
+Full class document: `skills/Web/info_disclosure/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id info_disclosure`
```
