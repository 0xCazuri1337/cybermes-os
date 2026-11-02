# Security Misconfiguration

## Definition

A deployable default or an absent hardening control leaves a capability the design assumed was closed.

- **CWE:** 16
- **OWASP:** A05:2021
- **Surface:** web
- **Aliases:** ["misconfiguration", "security headers", "debug mode", "default credentials"]

Canonical home for `misconfig`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.**

Where appliances sit on the public edge, patch state is the first question to answer because the same products appear repeatedly in exploited-in-the-wild advisories. For a hunter this makes fingerprinting versions and patch state a primary signal: it identifies reachable weakness before any payload is attempted, and it lets a mundane patch-gap outrank a novel finding on the same asset when remediation is the goal. Published exploitation references also confirm the attack surface is real, which raises confidence that a similar exposure on a sibling asset is worth reporting.

*Disproof:* If the appliance version is demonstrably patched, or no exploitation of the product has been published, patch state is not the deciding factor for this asset.

## Exploitation

Not yet researched.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**

The observation is an unauthenticated administrative interface on a device in the field, which is usually filed as authentication removed or a backdoor web shell installed. On a large class of consumer and SOHO devices it is simply the shipping behaviour: notably missing from the initial setup wizard is any sort of web portal username and login, and there is also no subsequent window requiring these to be set, so the router will fully function and will login anyone on the local network who can talk to it on the LAN side, giving them full administrative access. The setting of a web portal password requires extra configuration in an Administration tab and no warning is ever given to the owners. That means an asset-management or vulnerability scan that reports 'no authentication on admin interface' on such a device is reporting the default, not a change in state. Scanner output is even weaker evidence here than usual, because template-based tools run a lighter detection mode that only verifies the presence of services without conducting deeper security assessments, so a hit may mean only that an endpoint answered. The distinguishing test is provenance: check the device's setup flow and provisioning record for whether a portal credential was ever requested. If the wizard never asked, the finding is an inventory and hardening item (change the default, restrict LAN reachability), not an incident.

*Disproof:* The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.trailofbits.com** (writeup)
  - <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163>
- **unit42.paloaltonetworks.com** (writeup)
  - <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
