# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 02:41 — 1 diff lines
- items: 5 (supported 5), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-03)
```

## 2026-10-03 05:00 — 28 diff lines
- items: 7 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- linux_privesc@current
+++ linux_privesc@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-269 · OWASP A01:2021
-> evidence: 5 items, 5 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.
 
@@ -43,5 +43,14 @@
   - **Disproof:** The resolved object list is identical with and without the cache, so no cache-based selection occurred.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+
 ---
 Full class document: `domains/network/internal-network/linux_privesc/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id linux_privesc`
```
