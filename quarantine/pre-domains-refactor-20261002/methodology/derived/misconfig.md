# Methodology — Security Misconfiguration

> Derived from 2 verified items. Regenerate with `python -m wks.methodgen --class misconfig --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**References.** CWE-16 · A05:2021

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.**

Where appliances sit on the public edge, patch state is the first question to answer because the same products appear repeatedly in exploited-in-the-wild advisories. For a hunter this makes fingerprinting versions and patch state a primary signal: it identifies reachable weakness before any payload is attempted, and it lets a mundane patch-gap outrank a novel finding on the same asset when remediation is the goal. Published exploitation references also confirm the attack surface is real, which raises confidence that a similar exposure on a sibling asset is worth reporting.

- *Disproof:* If the appliance version is demonstrably patched, or no exploitation of the product has been published, patch state is not the deciding factor for this asset.
- *Evidence:* high_confidence — [blog.trailofbits.com](https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/)

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**

The observation is an unauthenticated administrative interface on a device in the field, which is usually filed as authentication removed or a backdoor web shell installed. On a large class of consumer and SOHO devices it is simply the shipping behaviour: notably missing from the initial setup wizard is any sort of web portal username and login, and there is also no subsequent window requiring these to be set, so the router will fully function and will login anyone on the local network who can talk to it on the LAN side, giving them full administrative access. The setting of a web portal password requires extra configuration in an Administration tab and no warning is ever given to the owners. That means an asset-management or vulnerability scan that reports 'no authentication on admin interface' on such a device is reporting the default, not a change in state. Scanner output is even weaker evidence here than usual, because template-based tools run a lighter detection mode that only verifies the presence of services without conducting deeper security assessments, so a hit may mean only that an endpoint answered. The distinguishing test is provenance: check the device's setup flow and provisioning record for whether a portal credential was ever requested. If the wizard never asked, the finding is an inventory and hardening item (change the default, restrict LAN reachability), not an incident.

- *Disproof:* The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Test sequence, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
