<!-- GENERATED from db/wks.db — do not edit -->
# Active Directory Enumeration

> surface: `ad` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 13 items, 4 supported, 0 FP rules, 1 chains

Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.

**Aliases:** ad enumeration, domain enumeration, ldap enumeration of ad, cldap, trust enumeration, domain trust enumeration

## Prerequisite

- **Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.**  
  `high_confidence` · score 0.929 · disproved by: The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625> · <https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/>
- **In an Active Directory environment a non-privileged domain user can enumerate the domain forest, domain controllers, group membership and domain trust relationships, and that enumeration is the prerequisite for kerberoasting and ACL abuse rather than an end in itself.**  
  `high_confidence` · score 0.89 · disproved by: If the same enumeration queries fail for a standard domain user and only succeed with an explicit administrative credential or a host-specific privilege, then low-privilege enumeration is not available in that domain and this prerequisite does not hold.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md>

## Signal

- **An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.**  
  `high_confidence` · score 0.863 · disproved by: If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance.**  
  `high_confidence` · score 0.854 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.admin_enumeration_command_is_dual_use) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>

## Related classes (via chains)

- `lateral_movement` Lateral Movement (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `info_disclosure` Information Disclosure (1 chains)

## Known gaps

Not yet satisfied: `fp_rules`
