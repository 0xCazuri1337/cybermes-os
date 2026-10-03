# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 02:41 — 1 diff lines
- items: 3 (supported 3), FP rules 0, chains 0, state researching
- still missing: methodology, items, supported_items, fp_rules, chain

```diff
(initial generation, 2026-10-03)
```

## 2026-10-03 05:00 — 28 diff lines
- items: 5 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-427 · OWASP A08:2021
-> evidence: 3 items, 3 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, supported_items, fp_rules, chain
+> evidence: 5 items, 5 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A writable directory on the executable search path lets an attacker-controlled binary load in place of a trusted one, so a normal program launch becomes privileged code execution.
 
@@ -31,5 +31,14 @@
   - **Disproof:** No Machine PATH entry is user-writable, or no service attempts to load a DLL that is missing from all earlier search locations.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
+- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
+
 ---
 Full class document: `domains/network/active-directory/windows_privesc_hijack/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_hijack`
```
