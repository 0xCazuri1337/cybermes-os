<!-- GENERATED from db/wks.db — do not edit -->
# Linux Privilege Escalation

> surface: `net` · CWE: CWE-269 · OWASP: A01:2021
> maturity: **researching** — 12 items, 10 supported, 0 FP rules, 1 chains

A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.

## Prerequisite

- **The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.**  
  `high_confidence` · score 0.854 · disproved by: The running sudo version is outside the vulnerable range or has chroot support compiled out.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>

## Signal

- **A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.**  
  `high_confidence` · score 0.854 · disproved by: Every process shows euid equal to ruid, meaning no set-user-ID transition occurred.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md>

## Technique

- **Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.**  
  `high_confidence` · score 0.854 · disproved by: The sudo version is unaffected, or no sudoers rule is qualified by a specific host.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
- **If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.**  
  `high_confidence` · score 0.854 · disproved by: The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
- **An executable whose security.capability extended attribute is non-empty has that capability set placed in the thread's permitted set at execve even when the real and effective UID are unprivileged, so an attacker who can replace or plant a capability-bearing binary gets those capabilities with no setuid bit set.**  
  `high_confidence` · score 0.8415 · disproved by: The claim is wrong on a kernel built without file-capability support (the capability bits are treated as notionally all ones only for real uid 0, so nothing is conferred), on any filesystem mounted nosuid where the attribute is ignored, when the xattr is a revision 3 namespaced capability and the executing thread's user namespace root does not own the file's namespace, when LSM policy (SELinux/AppArmor) denies the exec or the capability transition, and whenever the permitted set actually granted is harmless - a binary carrying only cap_net_bind_service or cap_net_raw is not root and the escalation does not exist. It is also wrong as an ATTACKER-CONTROLLED path if the low-privilege user cannot write the binary or its parent directory: the capability then belongs to a trusted helper and merely widens the blast radius of a separate bug, which is a different finding.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man7/capabilities.7.html>
- **CVE-2021-3560 is a polkit authorization bypass: an unprivileged local user can trick polkit into skipping D-Bus credential checks and create a local administrator or otherwise run code as root.**  
  `high_confidence` · score 0.8295 · disproved by: The finding fails when polkit is patched, the method is not reachable to the unprivileged user, or the D-Bus request does not produce a root-owned action.
  sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560>
- **When /proc/sys/kernel/core_pattern starts with a pipe character the kernel treats the remainder of the line as a command line and runs that program as user and group root the next time any process dumps core, so write access to that one sysctl is a root execution primitive requiring no memory-corruption bug at all.**  
  `high_confidence` · score 0.814 · disproved by: The claim fails when /proc/sys/kernel/core_pattern is root-owned mode 0644 inside a read-only or correctly restricted /proc/sys (the ordinary case - the write returns EACCES and nothing happens), when the pipe program is resolved in the INITIAL mount namespace so a helper planted only inside the current mount namespace or chroot is never found, when no core dump can be produced at all (RLIMIT_CORE 0 for every process you can influence, PR_SET_DUMPABLE cleared so the dump is skipped, or a kernel without CONFIG_COREDUMP), when an LSM or container runtime blocks the handler (the handler runs as root but LSMs are still active and can deny its access to /proc/<pid> of the crashed process, and a seccomp/AppArmor profile may refuse the exec outright), and when the sysctl is already set to a legitimate root-owned handler the attacker cannot replace - then the finding is configuration review, not privilege escalation.
  sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://man7.org/linux/man-pages/man5/core.5.html>
- **CVE-2019-14287 is a sudo policy bypass before 1.8.28: a user with a Runas ALL sudoer entry can invoke sudo with a crafted user ID to bypass blacklists and run commands as root.**  
  `high_confidence` · score 0.802 · disproved by: The finding fails when sudo is 1.8.28 or later, the user's sudoers entry does not include Runas ALL, or the crafted user ID is rejected by the policy.
  sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
- **CVE-2018-14665 is an incorrect permission check in Xorg before 1.20.3; a user who can log in at the physical console can use the -modulepath and -logfile options to run code as root.**  
  `high_confidence` · score 0.802 · disproved by: The finding fails when Xorg is 1.20.3 or later, the user cannot start an X server at the console, or the crafted -modulepath/-logfile invocation does not execute code as root.
  sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>

## Test

- **Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.**  
  `high_confidence` · score 0.854 · disproved by: The resolved object list is identical with and without the cache, so no cache-based selection occurred.
  sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>

## Known gaps

Not yet satisfied: `fp_rules`
