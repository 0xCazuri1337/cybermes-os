# Container Escape and Runtime Privilege Escalation

## Definition

The boundary is the container runtime rather than the host kernel directly: an over-privileged socket, a writable mount, or a permissive runtime flag lets a container act on the host.

- **CWE:** CWE-269
- **OWASP:** A05:2021
- **Surface:** net
- **Aliases:** []

Canonical home for `container_escape`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.**

When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md)

*Disproof:* The container runs with a user namespace active and container root maps to an unprivileged or unmapped host UID.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.**

A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.

HackTricks reference: authorization plugins (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md)

*Disproof:* The daemon rejects privileged docker exec, honors Binds restrictions, and blocks plugin management endpoints.

**A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.**

A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md)

*Disproof:* Inspection shows an active user namespace that maps container root to a non-zero or unmapped host UID.

## Exploitation

**The cgroups release_agent technique escapes a container by writing a release_agent script that executes on the host when the cgroup empties.**

The attacker mounts a cgroup, sets notify_on_release, writes a release_agent path pointing to a host-executable script, then triggers cgroup process exit. The kernel runs the script on the host, allowing command execution outside the container. This works on older kernels without seccomp/AppArmor restrictions.

*Disproof:* Seccomp or AppArmor blocks cgroup manipulation, or the kernel is patched against this technique.

**A mounted Docker socket inside a container lets an attacker spawn a privileged container with the host filesystem mounted, gaining host root.**

If /var/run/docker.sock is available inside the container, the attacker runs docker -H unix:///var/run/docker.sock run -v /:/host --privileged ubuntu chroot /host bash. This creates a new privileged container with the entire host filesystem, granting full root access to the node.

*Disproof:* The Docker socket is not mounted, or the container lacks permission to use it.

**A privileged container has near-full host access, allowing an attacker to mount the host filesystem and gain a root shell.**

When securityContext.privileged is true, the container can access host devices. The attacker lists devices with fdisk -l, mounts the host root partition, and chroots into it for a full host shell. Pod Security Standards and admission controllers should deny privileged containers.

*Disproof:* Privileged containers are denied by policy, or the container runtime blocks device access.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.container_escape.auto.01` — container_escape: observe, exercise, confirm (goal: `Establish, exercise and confirm a container_escape condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints." and "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.

Adjacent behaviour that produces the same observable result: A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A Docker authorization policy that filters container creation but igno" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." and "Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.

Adjacent behaviour that produces the same observable result: Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

## Validation

**The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.**

The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.

HackTricks reference: authorization plugins (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md)

*Disproof:* Every one of those endpoints and HostConfig fields is validated against the policy and rejects out-of-model runtime actions.

**Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.**

Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.

HackTricks reference: authorization plugins (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md)

*Disproof:* The daemon refuses the privileged exec request after an unconfined container is already running.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **cwe.mitre.org** (research)
  - <https://cwe.mitre.org/data/definitions/250.html>
- **docs.docker.com** (research)
  - <https://docs.docker.com/engine/security/>
- **github.com** (practitioner)
  - <https://github.com/TeamStarWolf/TeamStarWolf/blob/main/KUBERNETES_SECURITY_REFERENCE.md>
  - <https://github.com/armourinfosec/Offensive-Linux-Privilege-Escalation/blob/main/Container-and-Docker-Escape.md>
  - <https://github.com/trilwu/secskills/blob/main/secskills-offense/skills/exploiting-containers/SKILL.md>
- **kubernetes.io** (writeup)
  - <https://kubernetes.io/docs/concepts/security/pod-security-standards/>
- **raw.githubusercontent.com** (reference)
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
