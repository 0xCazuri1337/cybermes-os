---
name: ad_enumeration-hunting
description: Use when hunting Active Directory Enumeration in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Active Directory Enumeration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-200 · OWASP —
> evidence: 17 items, 9 supported, 2 FP rules, 1 chains
> maturity: **mature**

Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.

**Also called:** ad enumeration, domain enumeration, ldap enumeration of ad, cldap, trust enumeration, domain trust enumeration


## Prerequisites (do not start without these)

- In an Active Directory environment a non-privileged domain user can enumerate the domain forest, domain controllers, group membership and domain trust relationships, and that enumeration is the prerequisite for kerberoasting and ACL abuse rather than an end in itself.
  - **Disproof:** If the same enumeration queries fail for a standard domain user and only succeed with an explicit administrative credential or a host-specific privilege, then low-privilege enumeration is not available in that domain and this prerequisite does not hold.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md>
- Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.
  - **Disproof:** The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625> · <https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/>

## Recon signals (where to look)

- An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.
  - **Disproof:** If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Techniques (what to change)

- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md>
- While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and data exfiltration, HTML injection in PDF generation libraries can lead to Server-Side Request Forgery (SSRF), Local File Inclusion (LFI), and other common web vulnerabilities. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While XPath and LDAP injection vulnerabilities can lead to authentication bypasses and dat".
  - Sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- These flaws enable attackers to upload malicious files, execute arbitrary commands on the back-end server, and even take control over the entire server and all web applications hosted on it and potentially gain access to sensitive data or cause a service disruption. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "These flaws enable attackers to upload malicious files, execute arbitrary commands on the ".
  - Sources: <https://www.rfc-editor.org/rfc/rfc4511.html>
- Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Kerberos is an authentication protocol that allows users to authenticate and access servic".
  - Sources: <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.
  - **Disproof:** If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>

## Tests

- To decide this case, observe: Both framings are wrong: the same module an administrator uses for routine domain queries is the one an attacker reuses, so its presence is not evidence either way, and an attacker who proxies requests through a beacon rather than a local shell produces no command line to alert on in the first place.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_enumeration.fp_rule.living_off_the_land_ad_enumeration_is_dual_use) states the full boundary.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- To decide this case, observe: This is a detection-validation instrument rather than an alert: seeding unprivileged decoy accounts lets a team measure, before an incident, whether its log pipeline actually carries the events that distinguish reconnaissance from normal administration.
  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_enumeration.validation.tripwire_accounts_as_deterministic_probe) states the full boundary.
  - Sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Validation bar (how to prove it)

- Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating whether an environment would actually detect reconnaissance.
  - **Disproof:** If the decoy accounts receive no alerts during a controlled adversary-emulation run while events 4625/4768/4769/4771 are confirmed present in the log pipeline, the validation premise fails.
  - Sources: <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## False-positive rules (when to reject it)

- A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action. _(unverified)_
  - **Disproof:** The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/>
- Reject a ad_enumeration finding until it is distinguished from the adjacent behaviour this class also covers. "Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating..." and "Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Domain account names, group memberships and privilege are discoverable" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/>
- AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool is living-off-the-land tradecraft, not a distinct vulnerability; do not file the absence of a command-line alert as a control failure, because the same module an administrator uses for routine domain queries is the one an attacker reuses.
  - **Disproof:** The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>

## Evidence requirements

- A convincing observation for this class is: The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance. _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.admin_enumeration_command_is_dual_use) states the full boundary.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/>
- A convincing observation for this class is: The observable that triggers this false positive is AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool, filed either as malicious module use or as a detection gap because no command-line alert fired. _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.living_off_the_land_ad_enumeration_is_dual_use) states the full boundary.
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at. _(unverified)_
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_enumeration.fp_rule.auto.derived) states the full boundary.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/>

## Chains to

- `lateral_movement` (1 shared chain(s))
- `internal_recon` (1 shared chain(s))
- `info_disclosure` (1 shared chain(s))

---
Full class document: `domains/network/active-directory/ad_enumeration/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_enumeration`
