# Windows Privilege Escalation via Load-Path Hijacking

## Definition

A writable directory on the executable search path lets an attacker-controlled binary load in place of a trusted one, so a normal program launch becomes privileged code execution.

- **CWE:** CWE-427
- **OWASP:** A08:2021
- **Surface:** ad
- **Aliases:** []

Canonical home for `windows_privesc_hijack`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.**

For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows hijack candidates to DLLs absent from every earlier location.

HackTricks reference: writable sys path dll hijacking privesc (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md)

*Disproof:* The target is a packaged application using redirection or API sets, so the system PATH is never reached.

**The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.**

The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.

HackTricks reference: writable sys path dll hijacking privesc (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md)

*Disproof:* The DLL resolves in an earlier search location, or the system PATH contains no user-writable directory.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

Not yet researched.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.windows_privesc_hijack.auto.01` — windows_privesc_hijack: observe, exercise, confirm (goal: `Establish, exercise and confirm a windows_privesc_hijack condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail..." and "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail...

Adjacent behaviour that produces the same observable result: Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition." and "The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.

Adjacent behaviour that produces the same observable result: The hijack condition is a more-privileged process failing to find a DLL in all its earlier search locations and then falling through to a writable directory in the system PATH.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

**Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.**

Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the Machine PATH; that pair is the hijack condition.

HackTricks reference: writable sys path dll hijacking privesc (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md)

*Disproof:* No Machine PATH entry is user-writable, or no service attempts to load a DLL that is missing from all earlier search locations.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (research)
  - <https://cwe.mitre.org/data/definitions/427.html>
- **man7.org** (research)
  - <https://man7.org/linux/man-pages/man8/ld.so.8.html>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/windows-hardening/windows-local-privilege-escalation/dll-hijacking/writable-sys-path-dll-hijacking-privesc.md>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
