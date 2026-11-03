# Methodology — Linux Privilege Escalation

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class linux_privesc --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

**An executable whose security.capability extended attribute is non-empty has that capability set placed in the thread's permitted set at execve even when the real and effective UID are unprivileged, so an attacker who can replace or plant a capability-bearing binary gets those capabilities with no setuid bit set.**

Mechanism: the kernel stores a capability set in an xattr named security.capability on the executable; at execve the file's Permitted set is added to the thread's permitted set, so a binary that is not setuid-root still starts with the capabilities named in its xattr. Enumerate them with `getcap -r / 2>/dev/null` (or read the xattr directly with `getfattr -n security.capability -d <path>`). Triage: any file-capability binary whose contents the low-privilege user can write, replace via a writable parent directory, or influence through a library/search-path argument is an immediate privesc - the classic payloads are cap_dac_override and cap_dac_read_search (read/write any file, read /etc/shadow), cap_sys_admin (mount, namespace and cgroup escape), cap_setuid/cap_setgid (spawn a root shell), and cap_chown/cap_fowner. Detection does not require guessing: the xattr is a plain filesystem attribute, so `getcap -r` on the whole filesystem enumerates every candidate, and the ones that matter are those whose file mode or parent directory is writable by the attacker. Two chokepoints bound the technique: writing the xattr in the first place needs CAP_SETFCAP, and the exec must reach the kernel's file-capability code at all (nosuid mounts, user namespaces and LSM policy can each block it). The weakness class this instantiates is an actor operating in a privilege sphere it was never assigned.

- *Disproof:* The claim is wrong on a kernel built without file-capability support (the capability bits are treated as notionally all ones only for real uid 0, so nothing is conferred), on any filesystem mounted nosuid where the attribute is ignored, when the xattr is a revision 3 namespaced capability and the executing thread's user namespace root does not own the file's namespace, when LSM policy (SELinux/AppArmor) denies the exec or the capability transition, and whenever the permitted set actually granted is harmless - a binary carrying only cap_net_bind_service or cap_net_raw is not root and the escalation does not exist. It is also wrong as an ATTACKER-CONTROLLED path if the low-privilege user cannot write the binary or its parent directory: the capability then belongs to a trusted helper and merely widens the blast radius of a separate bug, which is a different finding.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/269.html); [man7.org](https://man7.org/linux/man-pages/man7/capabilities.7.html)

**CVE-2021-3560 is a polkit authorization bypass: an unprivileged local user can trick polkit into skipping D-Bus credential checks and create a local administrator or otherwise run code as root.**

The vulnerable surface is the local polkit/D-Bus service. NVD states that polkit could be tricked into bypassing credential checks for D-Bus requests, elevating the requestor to root, and that an unprivileged local attacker could create a new local administrator. CWE-863 describes the underlying authorization-check failure. The test should confirm the polkit version, the reachable D-Bus method, and the resulting root action; a polkit version string alone is not proof.

- *Disproof:* The finding fails when polkit is patched, the method is not reachable to the unprivileged user, or the D-Bus request does not produce a root-owned action.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/863.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560)

**When /proc/sys/kernel/core_pattern starts with a pipe character the kernel treats the remainder of the line as a command line and runs that program as user and group root the next time any process dumps core, so write access to that one sysctl is a root execution primitive requiring no memory-corruption bug at all.**

Mechanism: core_pattern accepts an alternate syntax since Linux 2.6.19 - if the first character is a pipe symbol, the rest of the line is the command line of a user-space program or script that the kernel executes, and that handler runs as uid 0 and gid 0. The attack is therefore a two-step chain with no exploit in it: (1) write `|/path/to/attacker/helper %p` (or a program you already control) into /proc/sys/kernel/core_pattern; (2) cause a core dump - crash your own process, or send a fatal signal to any process you can signal. The kernel does the rest, at root, with the initial mount namespace as cwd resolution base. Triage command: `cat /proc/sys/kernel/core_pattern` - a leading `|` means the box is already configured this way (systemd-coredump and Ubuntu apport both do it legitimately), and the value is what tells you whether the helper path is writable. Realistic exposure is containers and CI images that bind-mount /proc/sys writable, hosts where the sysctl was set once by an operator and the file mode was never tightened, and any sudo/NOPASSWD rule that permits `sysctl -w` or `tee /proc/sys/kernel/core_pattern`. Because the handler receives the crash context (pid, uid, gid, signal, and depending on the template the executable name and core file), the input reaching the command line is externally influenced, which is exactly the shape of OS command injection - mitigations are allowlisting the handler path and refusing to let a writable value reach the command.

- *Disproof:* The claim fails when /proc/sys/kernel/core_pattern is root-owned mode 0644 inside a read-only or correctly restricted /proc/sys (the ordinary case - the write returns EACCES and nothing happens), when the pipe program is resolved in the INITIAL mount namespace so a helper planted only inside the current mount namespace or chroot is never found, when no core dump can be produced at all (RLIMIT_CORE 0 for every process you can influence, PR_SET_DUMPABLE cleared so the dump is skipped, or a kernel without CONFIG_COREDUMP), when an LSM or container runtime blocks the handler (the handler runs as root but LSMs are still active and can deny its access to /proc/<pid> of the crashed process, and a seccomp/AppArmor profile may refuse the exec outright), and when the sysctl is already set to a legitimate root-owned handler the attacker cannot replace - then the finding is configuration review, not privilege escalation.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/78.html); [man7.org](https://man7.org/linux/man-pages/man5/core.5.html)

**CVE-2019-14287 is a sudo policy bypass before 1.8.28: a user with a Runas ALL sudoer entry can invoke sudo with a crafted user ID to bypass blacklists and run commands as root.**

The vulnerable surface is a local sudo configuration that grants a Runas ALL sudoer entry. NVD states that sudo before 1.8.28 allows a crafted user ID to bypass policy blacklists and session PAM modules, including bypass of a !root configuration, and to run commands as root. CWE-863 describes the underlying authorization-check failure. The test should read the sudoers policy, confirm the sudo version, and run the crafted user-ID command as the restricted user; a sudo version banner alone is not proof.

- *Disproof:* The finding fails when sudo is 1.8.28 or later, the user's sudoers entry does not include Runas ALL, or the crafted user ID is rejected by the policy.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/863.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287)

**CVE-2018-14665 is an incorrect permission check in Xorg before 1.20.3; a user who can log in at the physical console can use the -modulepath and -logfile options to run code as root.**

The vulnerable surface is a local Xorg server started with the affected version. NVD states that Xorg before 1.20.3 performs an incorrect permission check for the -modulepath and -logfile options, allowing an unprivileged user with physical-console login to escalate to root. CWE-863 describes the authorization-check failure. The test should confirm the Xorg version, the ability to start an X server from the console, and the crafted options; a remote X port alone does not prove this local path.

- *Disproof:* The finding fails when Xorg is 1.20.3 or later, the user cannot start an X server at the console, or the crafted -modulepath/-logfile invocation does not execute code as root.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/863.html); [services.nvd.nist.gov](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, False-positive rejection, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
