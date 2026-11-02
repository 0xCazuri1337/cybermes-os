---
name: service_enumeration_detail-hunting
description: Use when hunting Service-Specific Configuration Assessment in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Service-Specific Configuration Assessment — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-16 · OWASP —
> evidence: 2 items, 2 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, fp_rules, chain

A service's own configuration — signing, binding, authentication method — determines whether its protocol weaknesses are reachable.

**Also called:** service configuration, configuration assessment, service hardening, protocol configuration, misconfigured service


## Techniques (what to change)

- Whether a service's protocol weaknesses are reachable is decided by that service's own configuration — signing requirements, binding, authentication method and lockout policy — so service identification must be followed by configuration assessment before any weakness is asserted.
  - **Disproof:** If the service enforces signing and strong authentication with lockout applied, then the protocol weaknesses that enumeration would suggest are not reachable and the class yields no finding for that service.
  - Sources: <https://attack.mitre.org/techniques/T1046/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## False-positive rules (when to reject it)

- A TCP banner that reveals the service name and version is information disclosure and is not an authorization bypass, an authentication weakness, or a remote-code-execution finding; file it under information disclosure only, and only when the version actually maps to a known-vulnerable build.
  - **Disproof:** The disclosed version maps to a published CVE with a working exploit path, or the banner itself carries a credential or internal hostname that was not already known to the assessment scope - in which case the disclosure is materially different from a routine version string.
  - Sources: <https://capec.mitre.org/data/definitions/300.html> · <https://claroty.com/blog/a-comprehensive-guide-to-exposure-management-for-cyber-physical-systems>

---
Full class document: `skills/Network + AD/service_enumeration_detail/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id service_enumeration_detail`
