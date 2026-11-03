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

## 2026-10-04 00:43 — 50 diff lines
- items: 5 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -18,27 +18,42 @@
 
 ## Prerequisites (do not start without these)
 
-- For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.
+- For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.  _(merged 1 duplicate row(s))_
   - **Disproof:** The target is a packaged application using redirection or API sets, so the system PATH is never reached.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
-- The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.
+- The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.  _(merged 1 duplicate row(s))_
   - **Disproof:** The DLL resolves in an earlier search location, or the system PATH contains no user-writable directory.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
 
 ## Tests
 
-- Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.
+- Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.  _(merged 1 duplicate row(s))_
   - **Disproof:** No Machine PATH entry is user-writable, or no service attempts to load a DLL that is missing from all earlier search locations.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
 
 ## False-positive rules (when to reject it)
 
-- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
-- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/windows_privesc_hijack/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_hijack`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 5 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -43,10 +43,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Look for a writable directory on the executable search order, then confirm the target binary is actually started that way.
 
 ### What counts as proof
 
```

## 2026-10-04 19:46 — 9 diff lines
- items: 5 (supported 5), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -54,6 +54,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/windows_privesc_hijack/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_hijack`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-29 14:37 — 30 diff lines
- items: 8 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-427 · OWASP A08:2021
-> evidence: 5 items, 5 supported, 2 FP rules, 1 chains
+> evidence: 8 items, 7 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 A writable directory on the executable search path lets an attacker-controlled binary load in place of a trusted one, so a normal program launch becomes privileged code execution.
@@ -24,6 +24,18 @@
 - The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.  _(merged 1 duplicate row(s))_
   - **Disproof:** The DLL resolves in an earlier search location, or the system PATH contains no user-writable directory.
   - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
+
+## Techniques (what to change)
+
+- A privileged service loading a non-existent DLL from a writable PATH directory can be hijacked by placing a malicious DLL with the missing name.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The missing DLL is loaded from an absolute path or a non-writable directory, or the service does not run as SYSTEM.
+  - Sources: <https://datafield.dev/ethical-hacking/part-03/chapter-16/> · <https://sec-consult.com/blog/detail/windows-privilege-escalation-an-approach-for-penetration-testers/>
+- An unquoted service path containing spaces lets an attacker place a malicious executable at an earlier search location to gain SYSTEM privileges.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** The service path is fully quoted, or no writable directory exists in the resolution chain.
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/windows-privilege-escalation/SKILL.md> · <https://sec-consult.com/blog/detail/windows-privilege-escalation-an-approach-for-penetration-testers/>
+- Windows resolves DLLs in a fixed search order, so a writable directory earlier in the order can be abused to hijack a privileged process.  _(merged 1 duplicate row(s))_
+  - **Disproof:** All directories in the search order are non-writable by the attacker, or DLL Safe Search / KnownDLLs prevents the hijack.
+  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/windows-privilege-escalation/SKILL.md> · <https://sec-consult.com/blog/detail/windows-privilege-escalation-an-approach-for-penetration-testers/>
 
 ## Tests
 
```

## 2026-10-31 12:37 — 35 diff lines
- items: 8 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -20,10 +20,10 @@
 
 - For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.  _(merged 1 duplicate row(s))_
   - **Disproof:** The target is a packaged application using redirection or API sets, so the system PATH is never reached.
-  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
 - The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.  _(merged 1 duplicate row(s))_
   - **Disproof:** The DLL resolves in an earlier search location, or the system PATH contains no user-writable directory.
-  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
 
 ## Techniques (what to change)
 
@@ -41,16 +41,16 @@
 
 - Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.  _(merged 1 duplicate row(s))_
   - **Disproof:** No Machine PATH entry is user-writable, or no service attempts to load a DLL that is missing from all earlier search locations.
-  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
 
 ## False-positive rules (when to reject it)
 
 - Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
 - Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
+  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
 
 
 ## Hunt procedure
```

## 2026-11-02 23:13 — 11 diff lines
- items: 8 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -65,7 +65,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/network/active-directory/windows_privesc_hijack/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_hijack`
+Full class document: `skills/network/active-directory/windows_privesc_hijack/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_hijack`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 8 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- windows_privesc_hijack@current
+++ windows_privesc_hijack@new
@@ -5,7 +5,8 @@
 
 # Windows Privilege Escalation via Load-Path Hijacking — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
