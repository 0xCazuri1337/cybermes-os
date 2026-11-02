# Security Misconfiguration

> surface: `web` · CWE: 16 · OWASP: A05:2021
> maturity: **researching** — 2 items, 2 supported, 1 FP rules, 0 chains

A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**Aliases:** misconfiguration, security headers, debug mode, default credentials

## Signal

- **Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.**  
  `high_confidence` · score 0.8105 · disproved by: If the appliance version is demonstrably patched, or no exploitation of the product has been published, patch state is not the deciding factor for this asset.
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Fp Rule

- **A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.**  
  `high_confidence` · score 0.893 · disproved by: The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163> · <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>

## Known gaps

Not yet satisfied: `items`, `supported_items`, `fp_rules`, `chain`
