<!-- GENERATED from db/wks.db — do not edit -->
# Linux Privilege Escalation

## Definition

A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.

- **CWE:** CWE-269
- **OWASP:** A01:2021
- **Surface:** net
- **Aliases:** []

Canonical home for `linux_privesc`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.**

The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

*Disproof:* The running sudo version is outside the vulnerable range or has chroot support compiled out.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.**

A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.

HackTricks reference: euid ruid suid (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md)

*Disproof:* Every process shows euid equal to ruid, meaning no set-user-ID transition occurred.

## Exploitation

**Academy documents CVE-2018-15133 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Academy (official write-up, doc 297, 14484 chars, sha1 14299dce829c) describes CVE-2018-15133. Mechanism as documented on the machine: $payload = $this->getJsonPayload($payload); $iv = base64_decode($payload['iv']); $decrypted = \openssl_decrypt(

Authoritative record: In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur,

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-15133) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**CVE-2019-14287 is a sudo policy bypass before 1.8.28: a user with a Runas ALL sudoer entry can invoke sudo with a crafted user ID to bypass blacklists and run commands as root.**

The vulnerable surface is a local sudo configuration that grants a Runas ALL sudoer entry. NVD states that sudo before 1.8.28 allows a crafted user ID to bypass policy blacklists and session PAM modules, including bypass of a !root configuration, and to run commands as root. CWE-863 describes the underlying authorization-check failure. The test should read the sudoers policy, confirm the sudo version, and run the crafted user-ID command as the restricted user; a sudo version banner alone is not proof.

*Disproof:* The finding fails when sudo is 1.8.28 or later, the user's sudoers entry does not include Runas ALL, or the crafted user ID is rejected by the policy.

**Compromised documents CVE-2018-12256 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Compromised (official write-up, doc 276, 33064 chars, sha1 bde6aef3ebdd) describes CVE-2018-12256. Mechanism as documented on the machine: A Google search for this specific version reveals that it is vulnerable to an Authenticated Arbitrary File Upload exploit, which is assigned CVE-2018-12256. The vulnerability can be exploited through the usage of the LiteCart admin panel that was identified in the downloaded backup. We do not currently possess valid credentials for the panel.

Authoritative record: admin/vqmods.app/vqmods.inc.php in LiteCart before 2.1.3 allows remote authenticated attackers to upload a malicious file (resulting in remote code execution) by using the text/xml or application/xml Content-Type in a public_html/admin/?app=vqmods&doc=vqmods request.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-12256) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**An executable whose security.capability extended attribute is non-empty has that capability set placed in the thread's permitted set at execve even when the real and effective UID are unprivileged, so an attacker who can replace or plant a capability-bearing binary gets those capabilities with no setuid bit set.**

Mechanism: the kernel stores a capability set in an xattr named security.capability on the executable; at execve the file's Permitted set is added to the thread's permitted set, so a binary that is not setuid-root still starts with the capabilities named in its xattr. Enumerate them with `getcap -r / 2>/dev/null` (or read the xattr directly with `getfattr -n security.capability -d <path>`). Triage: any file-capability binary whose contents the low-privilege user can write, replace via a writable parent directory, or influence through a library/search-path argument is an immediate privesc - the classic payloads are cap_dac_override and cap_dac_read_search (read/write any file, read /etc/shadow), cap_sys_admin (mount, namespace and cgroup escape), cap_setuid/cap_setgid (spawn a root shell), and cap_chown/cap_fowner. Detection does not require guessing: the xattr is a plain filesystem attribute, so `getcap -r` on the whole filesystem enumerates every candidate, and the ones that matter are those whose file mode or parent directory is writable by the attacker. Two chokepoints bound the technique: writing the xattr in the first place needs CAP_SETFCAP, and the exec must reach the kernel's file-capability code at all (nosuid mounts, user namespaces and LSM policy can each block it). The weakness class this instantiates is an actor operating in a privilege sphere it was never assigned.

*Disproof:* The claim is wrong on a kernel built without file-capability support (the capability bits are treated as notionally all ones only for real uid 0, so nothing is conferred), on any filesystem mounted nosuid where the attribute is ignored, when the xattr is a revision 3 namespaced capability and the executing thread's user namespace root does not own the file's namespace, when LSM policy (SELinux/AppArmor) denies the exec or the capability transition, and whenever the permitted set actually granted is harmless - a binary carrying only cap_net_bind_service or cap_net_raw is not root and the escalation does not exist. It is also wrong as an ATTACKER-CONTROLLED path if the low-privilege user cannot write the binary or its parent directory: the capability then belongs to a trusted helper and merely widens the blast radius of a separate bug, which is a different finding.

**Paper documents CVE-2019-17671 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.**

HTB machine Paper (official write-up, doc 432, 9468 chars, sha1 ef3dcbe676b7) describes CVE-2019-17671. Mechanism as documented on the machine: Upon running a quick Google search along with the keywords "wordpress 5.2.3 exploits", we can identify CVE-2019-17671 which allows a user to view private/draft posts without authentication. This vulnerability aligns perfectly with the suspicious comment that we found earlier. Let us exploit this vulnerability to view the secret content present in the draft posts. To do so, we can add ?static=1 to the WordPress URL as mentioned in the PoC.

Authoritative record: In WordPress before 5.2.4, unauthenticated viewing of certain content is possible because the static query property is mishandled.

*Disproof:* Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-17671) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.

**CVE-2021-3560 is a polkit authorization bypass: an unprivileged local user can trick polkit into skipping D-Bus credential checks and create a local administrator or otherwise run code as root.**

The vulnerable surface is the local polkit/D-Bus service. NVD states that polkit could be tricked into bypassing credential checks for D-Bus requests, elevating the requestor to root, and that an unprivileged local attacker could create a new local administrator. CWE-863 describes the underlying authorization-check failure. The test should confirm the polkit version, the reachable D-Bus method, and the resulting root action; a polkit version string alone is not proof.

*Disproof:* The finding fails when polkit is patched, the method is not reachable to the unprivileged user, or the D-Bus request does not produce a root-owned action.

**Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.**

Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

*Disproof:* The sudo version is unaffected, or no sudoers rule is qualified by a specific host.

**If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.**

If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md)

*Disproof:* The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.

**When /proc/sys/kernel/core_pattern starts with a pipe character the kernel treats the remainder of the line as a command line and runs that program as user and group root the next time any process dumps core, so write access to that one sysctl is a root execution primitive requiring no memory-corruption bug at all.**

Mechanism: core_pattern accepts an alternate syntax since Linux 2.6.19 - if the first character is a pipe symbol, the rest of the line is the command line of a user-space program or script that the kernel executes, and that handler runs as uid 0 and gid 0. The attack is therefore a two-step chain with no exploit in it: (1) write `|/path/to/attacker/helper %p` (or a program you already control) into /proc/sys/kernel/core_pattern; (2) cause a core dump - crash your own process, or send a fatal signal to any process you can signal. The kernel does the rest, at root, with the initial mount namespace as cwd resolution base. Triage command: `cat /proc/sys/kernel/core_pattern` - a leading `|` means the box is already configured this way (systemd-coredump and Ubuntu apport both do it legitimately), and the value is what tells you whether the helper path is writable. Realistic exposure is containers and CI images that bind-mount /proc/sys writable, hosts where the sysctl was set once by an operator and the file mode was never tightened, and any sudo/NOPASSWD rule that permits `sysctl -w` or `tee /proc/sys/kernel/core_pattern`. Because the handler receives the crash context (pid, uid, gid, signal, and depending on the template the executable name and core file), the input reaching the command line is externally influenced, which is exactly the shape of OS command injection - mitigations are allowlisting the handler path and refusing to let a writable value reach the command.

*Disproof:* The claim fails when /proc/sys/kernel/core_pattern is root-owned mode 0644 inside a read-only or correctly restricted /proc/sys (the ordinary case - the write returns EACCES and nothing happens), when the pipe program is resolved in the INITIAL mount namespace so a helper planted only inside the current mount namespace or chroot is never found, when no core dump can be produced at all (RLIMIT_CORE 0 for every process you can influence, PR_SET_DUMPABLE cleared so the dump is skipped, or a kernel without CONFIG_COREDUMP), when an LSM or container runtime blocks the handler (the handler runs as root but LSMs are still active and can deny its access to /proc/<pid> of the crashed process, and a seccomp/AppArmor profile may refuse the exec outright), and when the sysctl is already set to a legitimate root-owned handler the attacker cannot replace - then the finding is configuration review, not privilege escalation.

**CVE-2018-14665 is an incorrect permission check in Xorg before 1.20.3; a user who can log in at the physical console can use the -modulepath and -logfile options to run code as root.**

The vulnerable surface is a local Xorg server started with the affected version. NVD states that Xorg before 1.20.3 performs an incorrect permission check for the -modulepath and -logfile options, allowing an unprivileged user with physical-console login to escalate to root. CWE-863 describes the authorization-check failure. The test should confirm the Xorg version, the ability to start an X server from the console, and the crafted options; a remote X port alone does not prove this local path.

*Disproof:* The finding fails when Xorg is 1.20.3 or later, the user cannot start an X server at the console, or the crafted -modulepath/-logfile invocation does not execute code as root.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.linux_privesc.auto.01` — linux_privesc: observe, exercise, confirm (goal: `Establish, exercise and confirm a linux_privesc condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.

Adjacent behaviour that produces the same observable result: If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.

Adjacent behaviour that produces the same observable result: A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

**Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.**

Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.

HackTricks reference: ld.so.conf example (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md)

*Disproof:* The resolved object list is identical with and without the cache, so no cache-based selection occurred.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (cwe)
  - <https://cwe.mitre.org/data/definitions/200.html>
  - <https://cwe.mitre.org/data/definitions/269.html>
  - <https://cwe.mitre.org/data/definitions/434.html>
  - <https://cwe.mitre.org/data/definitions/502.html>
  - <https://cwe.mitre.org/data/definitions/78.html>
  - <https://cwe.mitre.org/data/definitions/863.html>
- **man7.org** (research)
  - <https://man7.org/linux/man-pages/man2/execve.2.html>
  - <https://man7.org/linux/man-pages/man5/core.5.html>
  - <https://man7.org/linux/man-pages/man7/capabilities.7.html>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md>
- **services.nvd.nist.gov** (research)
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-12256>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-14665>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-15133>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-14287>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-17671>
  - <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
