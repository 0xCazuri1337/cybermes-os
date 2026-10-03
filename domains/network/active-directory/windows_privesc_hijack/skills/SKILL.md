---
name: windows_privesc_hijack-hunting
description: Use when hunting Windows Privilege Escalation via Load-Path Hijacking in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Windows Privilege Escalation via Load-Path Hijacking — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-427 · OWASP A08:2021
> evidence: 5 items, 5 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

A writable directory on the executable search path lets an attacker-controlled binary load in place of a trusted one, so a normal program launch becomes privileged code execution.


## Prerequisites (do not start without these)

- For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.
  - **Disproof:** The target is a packaged application using redirection or API sets, so the system PATH is never reached.
  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
- The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.
  - **Disproof:** The DLL resolves in an earlier search location, or the system PATH contains no user-writable directory.
  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>

## Tests

- Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.
  - **Disproof:** No Machine PATH entry is user-writable, or no service attempts to load a DLL that is missing from all earlier search locations.
  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>

## False-positive rules (when to reject it)

- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>
- Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://man7.org/linux/man-pages/man8/ld.so.8.html>

---
Full class document: `domains/network/active-directory/windows_privesc_hijack/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id windows_privesc_hijack`
