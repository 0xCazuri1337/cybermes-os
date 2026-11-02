# Active Directory Enumeration

> surface: `ad` · CWE: CWE-200 · OWASP: —
> maturity: **researching** — 5 items, 5 supported, 1 FP rules, 1 chains

Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.

**Aliases:** ad enumeration, domain enumeration, ldap enumeration of ad, cldap, trust enumeration, domain trust enumeration

## Prerequisite

- **Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.**  
  `high_confidence` · score 0.929 · disproved by: The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625> · <https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/>

## Signal

- **An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.**  
  `high_confidence` · score 0.863 · disproved by: If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.**  
  `high_confidence` · score 0.8615 · disproved by: If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>

## Validation

- **Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating whether an environment would actually detect reconnaissance.**  
  `high_confidence` · score 0.8105 · disproved by: If the decoy accounts receive no alerts during a controlled adversary-emulation run while events 4625/4768/4769/4771 are confirmed present in the log pipeline, the validation premise fails.
  sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Fp Rule

- **AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool is living-off-the-land tradecraft, not a distinct vulnerability; do not file the absence of a command-line alert as a control failure, because the same module an administrator uses for routine domain queries is the one an attacker reuses.**  
  `high_confidence` · score 0.8715 · disproved by: The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.
  sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Related classes (via chains)

- `lateral_movement` Lateral Movement (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `info_disclosure` Information Disclosure (1 chains)

## Known gaps

Not yet satisfied: `items`, `fp_rules`
