# Methodology — Security Misconfiguration

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class misconfig --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**References.** CWE-16 · A05:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A workload misconfiguration finding must be proved by the effective runtime configuration, not by the manifest alone, because whether host namespaces are actually shared is what the control is stated to disallow.**

Mechanism: A workload misconfiguration finding must be proved by the effective runtime configuration, not by the manifest alone, because whether host namespaces are actually shared is what the control is stated to disallow. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The finding holds when the effective spec sets the host-namespace flags or a privileged container context and that is what runs; it is void when the manifest requests it but a policy or admission controller rewrites the effective spec before it runs, in which case the observable configuration is compliant and the manifest alone proves nothing.

- *Disproof:* The finding holds when the effective spec sets the host-namespace flags or a privileged container context and that is what runs; it is void when the manifest requests it but a policy or admission controller rewrites the effective spec before it runs, in which case the observable configuration is compliant and the manifest alone proves nothing.
- *Evidence:* high_confidence — [docs.docker.com](https://docs.docker.com/engine/security/); [kubernetes.io](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**

The observation is an unauthenticated administrative interface on a device in the field, which is usually filed as authentication removed or a backdoor web shell installed. On a large class of consumer and SOHO devices it is simply the shipping behaviour: notably missing from the initial setup wizard is any sort of web portal username and login, and there is also no subsequent window requiring these to be set, so the router will fully function and will login anyone on the local network who can talk to it on the LAN side, giving them full administrative access. The setting of a web portal password requires extra configuration in an Administration tab and no warning is ever given to the owners. That means an asset-management or vulnerability scan that reports 'no authentication on admin interface' on such a device is reporting the default, not a change in state. Scanner output is even weaker evidence here than usual, because template-based tools run a lighter detection mode that only verifies the presence of services without conducting deeper security assessments, so a hit may mean only that an endpoint answered. The distinguishing test is provenance: check the device's setup flow and provisioning record for whether a portal credential was ever requested. If the wizard never asked, the finding is an inventory and hardening item (change the default, restrict LAN reachability), not an incident.

- *Disproof:* The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163)

**A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes.**

Mechanism: A workload running under the open-ended permissive security profile is not a defect on its own, because that profile is defined as entirely unrestricted and is intended for infrastructure workloads managed by trusted users; the report must identify what the openness actually exposes. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.

- *Disproof:* It IS a finding when the permissive profile applies to a workload reachable by untrusted input, for example one exposed through an application API; it is NOT a finding when the workload is genuinely infrastructure managed by privileged trusted operators, in which case the permissive profile is the documented intent and reporting it is noise.
- *Evidence:* high_confidence — [docs.docker.com](https://docs.docker.com/engine/security/); [kubernetes.io](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## 3. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**Mounting the container runtime control socket into an application container nullifies the rest of the hardening around it, because the socket grants the same authority as the daemon and the shared-directory primitive is reachable through it.**

Mechanism: Mounting the container runtime control socket into an application container nullifies the rest of the hardening around it, because the socket grants the same authority as the daemon and the shared-directory primitive is reachable through it. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is a genuine bypass when the application process can reach the socket and issue provisioning calls, since that restores daemon-equivalent privilege; it is not when the socket is present but unreachable to the untrusted process, the runtime runs rootless, or a proxy mediates the API with its own authorisation — in those cases the daemon privilege is not actually delegated.

- *Disproof:* It is a genuine bypass when the application process can reach the socket and issue provisioning calls, since that restores daemon-equivalent privilege; it is not when the socket is present but unreachable to the untrusted process, the runtime runs rootless, or a proxy mediates the API with its own authorisation — in those cases the daemon privilege is not actually delegated.
- *Evidence:* high_confidence — [docs.docker.com](https://docs.docker.com/engine/security/); [kubernetes.io](https://kubernetes.io/docs/concepts/security/pod-security-standards/)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Test sequence, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
