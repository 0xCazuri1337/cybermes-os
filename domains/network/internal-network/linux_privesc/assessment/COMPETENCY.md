# Methodology — Linux Privilege Escalation

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class linux_privesc --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.

**References.** CWE-269 · A01:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.**

The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

- *Disproof:* The running sudo version is outside the vulnerable range or has chroot support compiled out.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man2/execve.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.**

A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.

HackTricks reference: euid ruid suid (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md)

- *Disproof:* Every process shows euid equal to ruid, meaning no set-user-ID transition occurred.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man2/execve.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.**

Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

- *Disproof:* The sudo version is unaffected, or no sudoers rule is qualified by a specific host.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man2/execve.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

**If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.**

If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

- *Disproof:* The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man2/execve.2.html); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.

Adjacent behaviour that produces the same observable result: If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man2/execve.2.html)

**Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

Adjacent behaviour that produces the same observable result: A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man2/execve.2.html)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
