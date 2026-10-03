---
name: linux_privesc-hunting
description: Use when hunting Linux Privilege Escalation in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Linux Privilege Escalation — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-269 · OWASP A01:2021
> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: items

A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.


## Prerequisites (do not start without these)

- The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.
  - **Disproof:** The running sudo version is outside the vulnerable range or has chroot support compiled out.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>

## Recon signals (where to look)

- A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.
  - **Disproof:** Every process shows euid equal to ruid, meaning no set-user-ID transition occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md>

## Techniques (what to change)

- Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.
  - **Disproof:** The sudo version is unaffected, or no sudoers rule is qualified by a specific host.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
- If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.
  - **Disproof:** The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>

## Tests

- Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.
  - **Disproof:** The resolved object list is identical with and without the cache, so no cache-based selection occurred.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>

## False-positive rules (when to reject it)

- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>

---
Full class document: `domains/network/internal-network/linux_privesc/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id linux_privesc`
