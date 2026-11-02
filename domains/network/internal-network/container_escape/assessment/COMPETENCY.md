# Methodology — Container Escape and Runtime Privilege Escalation

> Derived from 6 verified items. Regenerate with `python -m wks.methodgen --class container_escape --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The boundary is the container runtime rather than the host kernel directly: an over-privileged socket, a writable mount, or a permissive runtime flag lets a container act on the host.

**References.** CWE-269 · A05:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.**

When the container has no user namespace or it is disabled, a root shell inside it is close to host root and the escape severity is much higher.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md)

- *Disproof:* The container runs with a user namespace active and container root maps to an unprivileged or unmapped host UID.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/250.html); [docs.docker.com](https://docs.docker.com/engine/security/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.**

A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.

HackTricks reference: authorization plugins (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md)

- *Disproof:* The daemon rejects privileged docker exec, honors Binds restrictions, and blocks plugin management endpoints.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/250.html); [docs.docker.com](https://docs.docker.com/engine/security/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/authorization-plugins.md)

**A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.**

A process reporting PID 1, its own network stack, hostname and IPC while running as root should be assumed namespaced, not host root, until the user namespace is checked.

HackTricks reference: README (https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md)

- *Disproof:* Inspection shows an active user namespace that maps container root to a non-zero or unmapped host UID.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/250.html); [docs.docker.com](https://docs.docker.com/engine/security/); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/linux-hardening/containers-namespaces/container-security/README.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A privileged container has near-full host access, allowing an attacker to mount the host filesystem and gain a root shell.**

When securityContext.privileged is true, the container can access host devices. The attacker lists devices with fdisk -l, mounts the host root partition, and chroots into it for a full host shell. Pod Security Standards and admission controllers should deny privileged containers.

- *Disproof:* Privileged containers are denied by policy, or the container runtime blocks device access.
- *Evidence:* high_confidence — [github.com](https://github.com/TeamStarWolf/TeamStarWolf/blob/main/KUBERNETES_SECURITY_REFERENCE.md); [kubernetes.io](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

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
