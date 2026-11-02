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
--- cmd@current
+++ cmd@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 78 · OWASP A03:2021
 > evidence: 7 items, 7 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 Attacker input reaches a shell or process launcher and becomes part of the executed command.
 
```

## 2026-10-02 13:38 — 8 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- cmd@current
+++ cmd@new
@@ -55,4 +55,4 @@
   - Sources: <https://cloud.google.com/blog/topics/threat-intelligence/staying-ahead-of-adversarial-ai-through-agentic-source-code-review> · <https://www.blackhillsinfosec.com/os-command-injection-pain-gain>
 
 ---
-Full class document: `classes/cmd.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
+Full class document: `skills/Web/cmd/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cmd`
```
