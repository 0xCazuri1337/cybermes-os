<!-- GENERATED from db/wks.db — do not edit -->
# Windows Privilege Escalation via Load-Path Hijacking

> surface: `ad` · CWE: CWE-427 · OWASP: A08:2021
> maturity: **researching** — 8 items, 7 supported, 2 FP rules, 1 chains

A writable directory on the executable search path lets an attacker-controlled binary load in place of a trusted one, so a normal program launch becomes privileged code execution.

## Prerequisite

- **For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.**  
  `high_confidence` · score 0.824 · disproved by: The target is a packaged application using redirection or API sets, so the system PATH is never reached.
  sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>
- **The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.**  
  `high_confidence` · score 0.824 · disproved by: The DLL resolves in an earlier search location, or the system PATH contains no user-writable directory.
  sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>

## Technique

- **A privileged service loading a non-existent DLL from a writable PATH directory can be hijacked by placing a malicious DLL with the missing name.**  
  `high_confidence` · score 0.779 · disproved by: The missing DLL is loaded from an absolute path or a non-writable directory, or the service does not run as SYSTEM.
  sources: <https://datafield.dev/ethical-hacking/part-03/chapter-16/> · <https://sec-consult.com/blog/detail/windows-privilege-escalation-an-approach-for-penetration-testers/>
- **Windows resolves DLLs in a fixed search order, so a writable directory earlier in the order can be abused to hijack a privileged process.**  
  `high_confidence` · score 0.743 · disproved by: All directories in the search order are non-writable by the attacker, or DLL Safe Search / KnownDLLs prevents the hijack.
  sources: <https://github.com/yaklang/hack-skills/blob/main/skills/windows-privilege-escalation/SKILL.md> · <https://sec-consult.com/blog/detail/windows-privilege-escalation-an-approach-for-penetration-testers/>

## Test

- **Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.**  
  `high_confidence` · score 0.824 · disproved by: No Machine PATH entry is user-writable, or no service attempts to load a DLL that is missing from all earlier search locations.
  sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>

## Fp Rule

- **Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>
- **Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/427.html> · <https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order>

## Known gaps

Not yet satisfied: `items`
