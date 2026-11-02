---
name: misconfig-hunting
description: Use when hunting Security Misconfiguration in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Security Misconfiguration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 16 · OWASP A05:2021
> evidence: 2 items, 2 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, fp_rules, chain

A deployable default or an absent hardening control leaves a capability the design assumed was closed.

**Also called:** misconfiguration, security headers, debug mode, default credentials


## Recon signals (where to look)

- Unpatched internet-facing appliances are exploited at scale, and published exploitation of a vendor edge product confirms the vulnerability class is actively used against exposed infrastructure rather than theoretical.
  - **Disproof:** If the appliance version is demonstrably patched, or no exploitation of the product has been published, patch state is not the deciding factor for this asset.
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## False-positive rules (when to reject it)

- A consumer device web interface reachable with no credential on a freshly imaged host is the documented factory default, not evidence that an attacker disabled authentication; the discriminator is whether the setup wizard ever prompts for a portal credential.
  - **Disproof:** The device's setup flow or provisioning record shows an administrator credential was previously configured and later removed, or the interface accepts a credential that no provisioning system ever issued, which makes the unauthenticated state a change rather than a default.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2025-2163> · <https://www.helpnetsecurity.com/2025/02/24/misconfig-mapper-open-source-tool-uncover-security-misconfigurations/>

---
Full class document: `skills/Web/misconfig/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id misconfig`
