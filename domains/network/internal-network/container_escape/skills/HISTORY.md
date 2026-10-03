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
