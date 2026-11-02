# Container Escape and Runtime Privilege Escalation

> surface: `net` · CWE: CWE-269 · OWASP: A05:2021
> maturity: **researching** — 10 items, 6 supported, 0 FP rules, 1 chains

The boundary is the container runtime rather than the host kernel directly: an over-privileged socket, a writable mount, or a permissive runtime flag lets a container act on the host.

## Prerequisite

- **When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.**  
  `high_confidence` · score 0.824 · disproved by: The container runs with a user namespace active and container root maps to an unprivileged or unmapped host UID.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md>

## Signal

- **A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.**  
  `high_confidence` · score 0.824 · disproved by: The daemon rejects privileged docker exec, honors Binds restrictions, and blocks plugin management endpoints.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
- **A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.**  
  `high_confidence` · score 0.824 · disproved by: Inspection shows an active user namespace that maps container root to a non-zero or unmapped host UID.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md>

## Technique

- **A privileged container has near-full host access, allowing an attacker to mount the host filesystem and gain a root shell.**  
  `high_confidence` · score 0.819 · disproved by: Privileged containers are denied by policy, or the container runtime blocks device access.
  sources: <https://github.com/TeamStarWolf/TeamStarWolf/blob/main/KUBERNETES_SECURITY_REFERENCE.md> · <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **A mounted Docker socket inside a container lets an attacker spawn a privileged container with the host filesystem mounted, gaining host root.**  
  `under_review` · score 0.779 · disproved by: The Docker socket is not mounted, or the container lacks permission to use it.
  sources: <https://github.com/TeamStarWolf/TeamStarWolf/blob/main/KUBERNETES_SECURITY_REFERENCE.md> · <https://github.com/armourinfosec/Offensive-Linux-Privilege-Escalation/blob/main/Container-and-Docker-Escape.md>
- **The cgroups release_agent technique escapes a container by writing a release_agent script that executes on the host when the cgroup empties.**  
  `under_review` · score 0.743 · disproved by: Seccomp or AppArmor blocks cgroup manipulation, or the kernel is patched against this technique.
  sources: <https://github.com/armourinfosec/Offensive-Linux-Privilege-Escalation/blob/main/Container-and-Docker-Escape.md> · <https://github.com/trilwu/secskills/blob/main/secskills-offense/skills/exploiting-containers/SKILL.md>

## Test

- **The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.**  
  `high_confidence` · score 0.879 · disproved by: Every one of those endpoints and HostConfig fields is validated against the policy and rejects out-of-model runtime actions.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>
- **Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.**  
  `high_confidence` · score 0.8515 · disproved by: The daemon refuses the privileged exec request after an unconfined container is already running.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>

## Fp Rule

- **Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints." and "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.918 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A Docker authorization policy that filters container creation but igno" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>
- **Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." and "Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.863 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://cwe.mitre.org/data/definitions/250.html> · <https://docs.docker.com/engine/security/>

## Known gaps

Not yet satisfied: `items`, `fp_rules`
