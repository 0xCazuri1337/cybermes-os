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
--- container_escape@current
+++ container_escape@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `net` · CWE CWE-269 · OWASP A05:2021
-> evidence: 5 items, 5 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> evidence: 7 items, 7 supported, 2 FP rules, 1 chains
+> maturity: **researching** — missing: items
 
 The boundary is the container runtime rather than the host kernel directly: an over-privileged socket, a writable mount, or a permissive runtime flag lets a container act on the host.
 
@@ -40,5 +40,14 @@
   - **Disproof:** The daemon refuses the privileged exec request after an unconfined container is already running.
   - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
 
+## False-positive rules (when to reject it)
+
+- Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints." and "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A Docker authorization policy that filters container creation but igno" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>
+- Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." and "Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>
+
 ---
 Full class document: `domains/network/internal-network/container_escape/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id container_escape`
```

## 2026-10-04 00:43 — 65 diff lines
- items: 7 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- container_escape@current
+++ container_escape@new
@@ -18,36 +18,51 @@
 
 ## Prerequisites (do not start without these)
 
-- When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.
+- When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.  _(merged 1 duplicate row(s))_
   - **Disproof:** The container runs with a user namespace active and container root maps to an unprivileged or unmapped host UID.
   - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md>
 
 ## Recon signals (where to look)
 
-- A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.
+- A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.  _(merged 1 duplicate row(s))_
   - **Disproof:** The daemon rejects privileged docker exec, honors Binds restrictions, and blocks plugin management endpoints.
   - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
-- A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.
+- A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.  _(merged 1 duplicate row(s))_
   - **Disproof:** Inspection shows an active user namespace that maps container root to a non-zero or unmapped host UID.
   - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md>
 
 ## Tests
 
-- The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.
+- Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The daemon refuses the privileged exec request after an unconfined container is already running.
+  - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
+- The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.  _(merged 1 duplicate row(s))_
   - **Disproof:** Every one of those endpoints and HostConfig fields is validated against the policy and rejects out-of-model runtime actions.
-  - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
-- Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.
-  - **Disproof:** The daemon refuses the privileged exec request after an unconfined container is already running.
   - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
 
 ## False-positive rules (when to reject it)
 
-- Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints." and "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
+- Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." and "Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>
+- Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints." and "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A Docker authorization policy that filters container creation but igno" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>
-- Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." and "Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
-  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>
 
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
 Full class document: `domains/network/internal-network/container_escape/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id container_escape`
```

## 2026-10-04 00:50 — 14 diff lines
- items: 7 (supported 7), FP rules 2, chains 1, state researching
- still missing: items

```diff
--- container_escape@current
+++ container_escape@new
@@ -52,10 +52,7 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Enumerate the mount and capability surface first, then test only the escape primitive the configuration actually exposes.
 
 ### What counts as proof
 
```
