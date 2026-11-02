# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 4 (supported 4), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 13:38 — 33 diff lines
- items: 7 (supported 7), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- ssti@current
+++ ssti@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE CWE-1336 · OWASP A03:2021
-> evidence: 4 items, 4 supported, 2 FP rules, 0 chains
+> evidence: 7 items, 7 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 Untrusted input is compiled by the template engine rather than treated as data, so the engine's expression language executes.
@@ -26,6 +26,15 @@
 
 ## Techniques (what to change)
 
+- If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".
+  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
+- Template engines can be used on the server or client, so both "sides" could be affected by injection.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Template engines can be used on the server or client, so both "sides" could be affected by".
+  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
+- The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
+  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/server-side-template-injection>
 - A template sandbox that pre-checks a dangerous keyword followed by a single space is bypassed by sending a tab in place of that space.
   - **Disproof:** If the tab variant is rejected by the same pre-check as the space variant, or is rejected by the downstream type blocklist, the filter is not the weak separator described here.
   - Sources: <https://snyk.io/blog/thymeleaf-injection/> · <https://www.nccgroup.com/research/technical-advisory-pulse-connect-secure-rce-via-template-injection-cve-2020-8243/>
@@ -40,4 +49,4 @@
   - Sources: <https://blog.qualys.com/vulnerabilities-threat-research/2016/08/31/thwarting-sql-injection-defense-in-depth> · <https://projectdiscovery.io/blog/crafting-dast-nuclei-templates-for-oob-template-engines-injection-a-practical-guide> · <https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught>
 
 ---
-Full class document: `classes/ssti.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssti`
+Full class document: `skills/Web/ssti/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ssti`
```
