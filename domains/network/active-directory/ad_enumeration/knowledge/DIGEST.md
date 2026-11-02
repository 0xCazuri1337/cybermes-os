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

## Technique

- **Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.**  
  `under_review` · score 0.8615 · disproved by: If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>

## Test

- **To decide this case, observe: Both framings are wrong: the same module an administrator uses for routine domain queries is the one an attacker reuses, so its presence is not evidence either way, and an attacker who proxies requests through a beacon rather than a local shell produces no command line to alert on in the first place.**  
  `under_review` · score 0.909 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_enumeration.fp_rule.living_off_the_land_ad_enumeration_is_dual_use) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **To decide this case, observe: This is a detection-validation instrument rather than an alert: seeding unprivileged decoy accounts lets a team measure, before an incident, whether its log pipeline actually carries the events that distinguish reconnaissance from normal administration.**  
  `under_review` · score 0.8655 · disproved by: This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_enumeration.validation.tripwire_accounts_as_deterministic_probe) states the full boundary.
  sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Validation

- **Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating whether an environment would actually detect reconnaissance.**  
  `under_review` · score 0.8105 · disproved by: If the decoy accounts receive no alerts during a controlled adversary-emulation run while events 4625/4768/4769/4771 are confirmed present in the log pipeline, the validation premise fails.
  sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Fp Rule

- **AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool is living-off-the-land tradecraft, not a distinct vulnerability; do not file the absence of a command-line alert as a control failure, because the same module an administrator uses for routine domain queries is the one an attacker reuses.**  
  `under_review` · score 0.9015 · disproved by: The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **Reject a ad_enumeration finding until it is distinguished from the adjacent behaviour this class also covers. "Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating..." and "Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `under_review` · score 0.893 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Domain account names, group memberships and privilege are discoverable" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/>
- **A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.**  
  `under_review` · score 0.748 · disproved by: The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
  sources: <https://attack.mitre.org/techniques/T1087/002/>

## Evidence

- **A convincing observation for this class is: The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance.**  
  `high_confidence` · score 0.854 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.admin_enumeration_command_is_dual_use) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md>
- **A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.**  
  `under_review` · score 0.814 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.auto.derived) states the full boundary.
  sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **A convincing observation for this class is: The observable that triggers this false positive is AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool, filed either as malicious module use or as a detection gap because no command-line alert fired.**  
  `under_review` · score 0.808 · disproved by: Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.living_off_the_land_ad_enumeration_is_dual_use) states the full boundary.
  sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Related classes (via chains)

- `lateral_movement` Lateral Movement (1 chains)
- `internal_recon` Internal Network Reconnaissance (1 chains)
- `info_disclosure` Information Disclosure (1 chains)

## Known gaps

Not yet satisfied: `fp_rules`
