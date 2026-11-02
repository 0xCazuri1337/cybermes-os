# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-03 02:41 — 1 diff lines
- items: 5 (supported 5), FP rules 0, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-03)
```

## 2026-10-03 05:00 — 28 diff lines
- items: 7 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- linux_privesc@current
+++ linux_privesc@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-269 · OWASP A01:2021
-> evidence: 5 items, 5 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.
 
@@ -43,5 +43,14 @@
   - **Disproof:** The resolved object list is identical with and without the cache, so no cache-based selection occurred.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
+
 ---
 Full class document: `domains/network/internal-network/linux_privesc/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id linux_privesc`
```

## 2026-10-04 00:38 — 30 diff lines
- items: 11 (supported 11), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- linux_privesc@current
+++ linux_privesc@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-269 · OWASP A01:2021
-> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
+> evidence: 11 items, 11 supported, 2 FP rules, 1 chains
 > maturity: **researching** — missing: items
 
 A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.
@@ -30,6 +30,18 @@
 
 ## Techniques (what to change)
 
+- Academy documents CVE-2018-15133 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-15133) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-15133>
+- Compromised documents CVE-2018-12256 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-12256) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-12256>
+- Paper documents CVE-2019-17671 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-17671) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/200.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-17671>
+- Paper documents CVE-2021-3560 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+  - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3560) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
+  - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560>
 - Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.
   - **Disproof:** The sudo version is unaffected, or no sudoers rule is qualified by a specific host.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
```

## 2026-10-04 00:43 — 84 diff lines
- items: 11 (supported 11), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- linux_privesc@current
+++ linux_privesc@new
@@ -18,51 +18,66 @@
 
 ## Prerequisites (do not start without these)
 
-- The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.
+- The sudo chroot escalation is only reachable when the installed sudo version is actually vulnerable and supports the chroot feature.  _(merged 1 duplicate row(s))_
   - **Disproof:** The running sudo version is outside the vulnerable range or has chroot support compiled out.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
 
 ## Recon signals (where to look)
 
-- A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.
+- A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity.  _(merged 1 duplicate row(s))_
   - **Disproof:** Every process shows euid equal to ruid, meaning no set-user-ID transition occurred.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/user-information/euid-ruid-suid.md>
 
 ## Techniques (what to change)
 
-- Academy documents CVE-2018-15133 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+- Academy documents CVE-2018-15133 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-15133) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-15133>
-- Compromised documents CVE-2018-12256 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+- Compromised documents CVE-2018-12256 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-12256) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-12256>
-- Paper documents CVE-2019-17671 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+- Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The sudo version is unaffected, or no sudoers rule is qualified by a specific host.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
+- If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
+- Paper documents CVE-2019-17671 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2019-17671) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/200.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-17671>
-- Paper documents CVE-2021-3560 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.
+- Paper documents CVE-2021-3560 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3560) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560>
-- Host-qualified sudoers rules are evaluated against the hostname passed to sudo -h, so the client's -h value selects which rule set applies.
-  - **Disproof:** The sudo version is unaffected, or no sudoers rule is qualified by a specific host.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
-- If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h.
-  - **Disproof:** The sudoers rules use ALL, or only name the machine's real hostname, or the sudo version is not vulnerable.
-  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/linux-basics/linux-privilege-escalation/README.md>
 
 ## Tests
 
-- Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.
+- Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.  _(merged 1 duplicate row(s))_
   - **Disproof:** The resolved object list is identical with and without the cache, so no cache-based selection occurred.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/interesting-files-permissions/ld.so.conf-example.md>
 
 ## False-positive rules (when to reject it)
 
-- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object." and "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
-- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with sudo -h." and "A process whose euid differs from its ruid is evidence that a set-user-ID binary was executed and picked up the file owner's identity." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man2/execve.2.html>
 
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
 Full class document: `domains/network/internal-network/linux_privesc/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id linux_privesc`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 11 (supported 11), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- linux_privesc@current
+++ linux_privesc@new
@@ -67,10 +67,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Enumerate SUID binaries, sudo -l, cron and writable service files, then test only the specific weakness found.
 
 ### What counts as proof
 
```

## 2026-10-04 17:13 — 33 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
--- linux_privesc@current
+++ linux_privesc@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-269 · OWASP A01:2021
-> evidence: 11 items, 11 supported, 2 FP rules, 1 chains
-> maturity: **researching** — missing: items
+> evidence: 13 items, 13 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 A local foothold becomes root through a misconfigured permission, a permissive interpreter path, or an over-privileged group membership, so the escalation needs no exploit at all.
 
@@ -33,6 +33,9 @@
 - Academy documents CVE-2018-15133 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-15133) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/502.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-15133>
+- An executable whose security.capability extended attribute is non-empty has that capability set placed in the thread's permitted set at execve even when the real and effective UID are unprivileged, so an attacker who can replace or plant a capability-bearing binary gets those capabilities with no setuid bit set.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong on a kernel built without file-capability support (the capability bits are treated as notionally all ones only for real uid 0, so nothing is conferred), on any filesystem mounted nosuid where the attribute is ignored, when the xattr is a revision 3 namespaced capability and the executing thread's user namespace root does not own the file's namespace, when LSM policy (SELinux/AppArmor) denies the exec or the capability transition, and whenever the permitted set actually granted is harmless - a binary carrying only cap_net_bind_service or cap_net_raw is not root and the escalation does not exist. It is also wrong as an ATTACKER-CONTROLLED path if the low-privilege user cannot write the binary or its parent directory: the capability then belongs to a trusted helper and merely widens the blast radius of a separate bug, which is a different finding.
+  - Sources: <https://cwe.mitre.org/data/definitions/269.html> · <https://man7.org/linux/man-pages/man7/capabilities.7.html>
 - Compromised documents CVE-2018-12256 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2018-12256) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/434.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2018-12256>
@@ -48,6 +51,9 @@
 - Paper documents CVE-2021-3560 as a route from an authenticated user to elevated privileges, and the authoritative record confirms the same weakness in the affected product.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the running product is outside the affected version range, or when the specific weakness (CVE-2021-3560) is patched on the target: the documented escalation then does not exist, whatever the advisory still says.
   - Sources: <https://cwe.mitre.org/data/definitions/863.html> · <https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-3560>
+- When /proc/sys/kernel/core_pattern starts with a pipe character the kernel treats the remainder of the line as a command line and runs that program as user and group root the next time any process dumps core, so write access to that one sysctl is a root execution primitive requiring no memory-corruption bug at all.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim fails when /proc/sys/kernel/core_pattern is root-owned mode 0644 inside a read-only or correctly restricted /proc/sys (the ordinary case - the write returns EACCES and nothing happens), when the pipe program is resolved in the INITIAL mount namespace so a helper planted only inside the current mount namespace or chroot is never found, when no core dump can be produced at all (RLIMIT_CORE 0 for every process you can influence, PR_SET_DUMPABLE cleared so the dump is skipped, or a kernel without CONFIG_COREDUMP), when an LSM or container runtime blocks the handler (the handler runs as root but LSMs are still active and can deny its access to /proc/<pid> of the crashed process, and a seccomp/AppArmor profile may refuse the exec outright), and when the sysctl is already set to a legitimate root-owned handler the attacker cannot replace - then the finding is configuration review, not privilege escalation.
+  - Sources: <https://cwe.mitre.org/data/definitions/78.html> · <https://man7.org/linux/man-pages/man5/core.5.html>
 
 ## Tests
 
```
