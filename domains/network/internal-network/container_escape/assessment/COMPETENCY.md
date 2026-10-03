# Methodology — Container Escape and Runtime Privilege Escalation

> Derived from 7 verified items. Regenerate with `python -m wks.methodgen --class container_escape --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints." and "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.

Adjacent behaviour that produces the same observable result: A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A Docker authorization policy that filters container creation but igno" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/250.html); [docs.docker.com](https://docs.docker.com/engine/security/)

**Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind." and "Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin administration leaves working privilege-escalation paths behind.

Adjacent behaviour that produces the same observable result: Creating an unconfined container and then requesting a privileged exec is a valid bypass test against policies that only block privileged container creation.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/250.html); [docs.docker.com](https://docs.docker.com/engine/security/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Test sequence, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
