---
name: redteam
description: Use when conducting authorized red-team, adversary emulation, or full-scope offensive operations. Routes to nested AD, C2, network, cloud, mobile, CI/CD, and supply-chain sub-skills and scripts.
---

# Redteam

## 1. Identity and purpose

`redteam` is the canonical umbrella capability for authorized red-team operations, adversary emulation, and full-scope offensive assessments. It is intentionally broader than `offensive-testing`: it coordinates multi-stage campaigns across identity, network, infrastructure, cloud, mobile, CI/CD, and supply-chain targets.

## 2. Scope

In scope:
- Active Directory and identity compromise
- Network and infrastructure penetration testing
- Command-and-control and adversary emulation
- Cloud, container, and Kubernetes attack paths
- Mobile application and device testing
- CI/CD and supply-chain attack surface
- Detection engineering and purple-team validation

Out of scope:
- Unauthorized access or exploitation
- Production-impacting denial-of-service
- Destructive actions without explicit authorization

## 3. Invocation and routing

Start here when the engagement spans multiple systems or requires campaign coordination. Route to nested sub-skills for technique-specific work:

- `ad/` — Active Directory, identity, credential access, persistence, lateral movement
- `network/` — network protocols, VPN, wireless, ICS/OT, TLS/DNS
- `infra/` — Kubernetes, etcd, VMware vCenter
- `cloud/` — cloud identity and infrastructure attack paths (where present in nested content)
- `mobile/` — Android and iOS red-team pipelines
- `cicd/` — CI/CD pipeline attacks
- `supply-chain/` — dependency and build-chain compromise
- `linux/` — Linux persistence and binary exploitation
- `misc/` — engagement planning, phishing simulation, exceptional conditions

Use `offensive-testing` for focused web, mobile, or thick-client penetration testing of a single application.

## 4. Inputs and outputs

Inputs:
- Written authorization and scope
- Target inventory and credentials provided for testing
- Engagement objectives and rules of engagement

Outputs:
- Campaign plan
- Technique-specific findings
- Evidence and replay notes
- Detection and hardening recommendations

## 5. Preconditions and authorization

All red-team activity requires explicit, written authorization. Confirm scope, prohibited actions, data-handling requirements, and emergency contacts before execution. Stop immediately if scope is exceeded.

## 6. Reconnaissance

Use the nested sub-skills and their scripts for target-specific reconnaissance. Preserve evidence and avoid destructive scanning unless authorized.

## 7. Detection methodology

Red-team work must include detection validation:
- Map actions to MITRE ATT&CK where possible
- Record timestamps, commands, and artifacts
- Validate whether defensive controls detected the activity
- Document false negatives and detection gaps

## 8. Technique selection

Select techniques based on authorization, target architecture, and engagement goals. Do not run the full technique catalog by default. Prefer the least invasive technique that proves the objective.

## 9. Execution steps

1. Confirm authorization and scope.
2. Build target and identity inventory.
3. Select campaign objectives.
4. Route to nested sub-skills.
5. Execute approved techniques.
6. Collect evidence.
7. Validate detections.
8. Report findings and remediation.

## 10. Tool usage

The 225 scripts under `ad/`, `network/`, `infra/`, `mobile/`, `cicd/`, `supply-chain/`, `linux/`, and `misc/` remain independent executable tools. Invoke them directly according to their own CLI help. They are intentionally not inlined into this skill.

## 11. Payloads and test cases

Payloads and operational test cases remain in their nested sub-skill and script directories. This canonical skill does not duplicate them.

## 12. Evidence

Evidence must include authorization, commands executed, outputs, timestamps, affected assets, and detection results. Do not fabricate or backfill evidence.

## 13. Reproduction and validation

Reproduce findings only in authorized environments. Validate that each finding is exploitable and not an artifact of tooling or environment.

## 14. False-positive rejection

Reject findings that cannot be reproduced, lack impact, or depend on unsupported assumptions. Distinguish simulated, attempted, and confirmed results.

## 15. Impact

Impact is assessed per finding based on confidentiality, integrity, availability, and business risk. Campaign-level impact must account for chained techniques.

## 16. Reporting

Report per-finding details plus campaign-level attack paths, detection gaps, and remediation priorities.

## 17. Failure modes

- Missing authorization
- Stale or incomplete target inventory
- Tool dependency failures
- Detection evasion assumptions not validated
- Overstated impact

## 18. References

Nested sub-skills under this directory are the detailed technical references. `offensive-testing` remains a separate focused capability.

## 19. Testing and mastery

Behavioral coverage for this capability is provided by `tests/test_redteam_capability.py` and syntax checks for nested scripts. Mastery requires repeated authorized exercise and validation.
PY


## Knowledge sources

- WKS bug classes: ad_acl_abuse, ad_delegation, ad_enumeration, ad_group_policy, ad_kerberos, ad_ldap, ad_ntlm, ad_trust_abuse, adcs_abuse, credential_access, pass_the_hash, password_attacks, windows_privesc_hijack, windows_privesc_service, windows_privesc_token, container_escape, internal_recon, lateral_movement, linux_privesc, segmentation_analysis, service_enumeration, tunneling_pivoting, dns_enum, exposed_rmm, exposed_services, ldap_enum, rdp, smb, winrm, service_enumeration_detail
- Domain knowledge: none mapped
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
