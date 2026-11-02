# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 13:38 — 30 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- path_traversal@current
+++ path_traversal@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-22 · OWASP A01:2021
-> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
+> evidence: 6 items, 6 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 A filename or path built from user input escapes its intended directory.
@@ -23,6 +23,12 @@
 - Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.
   - **Disproof:** If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
   - Sources: <https://bishopfox.com/blog/looting-unifi-controllers-detecting-and-weaponizing-cve-2026-22557> · <https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/>
+
+## Techniques (what to change)
+
+- In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".
+  - Sources: <https://cwe.mitre.org/data/definitions/22.html> · <https://owasp.org/www-community/attacks/Path_Traversal>
 
 ## Validation bar (how to prove it)
 
@@ -46,4 +52,4 @@
   - Sources: <https://httpwg.org/specs/rfc9110.html> · <https://blog.qualys.com/vulnerabilities-threat-research/2021/10/27/apache-http-server-path-traversal-remote-code-execution-cve-2021-41773-cve-2021-42013>
 
 ---
-Full class document: `classes/path_traversal.md` · retrieve more with `python -m wks.cli search "<query>" --class-id path_traversal`
+Full class document: `skills/Web/path_traversal/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id path_traversal`
```
