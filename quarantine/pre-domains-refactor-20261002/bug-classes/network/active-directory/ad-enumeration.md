# Active Directory Enumeration

## Definition

Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["ad enumeration", "domain enumeration", "ldap enumeration of ad", "cldap", "trust enumeration", "domain trust enumeration"]

Canonical home for `ad_enumeration`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.**

Prerequisite: capture a baseline before escalating anything an enumeration tool prints. Two facts make enumeration output noisy by design. First, privilege paths are visible to low-privileged accounts: an AD ACL visualiser built with no prerequisites, requiring no install and running natively on the three major operating systems will give surprising results within minutes even as a regular non-admin user, and the same data can be collected through an indirect service such as ADWS rather than LDAP. Second, enumeration that returns account names is, on its own, low-consequence: user enumeration as a class has minimal impact in general, as the attacker would still be required to guess a valid password, and addresses for an organisation are trivially harvestable from other external means anyway. The baseline therefore has two parts: the set of objects and edges an unprivileged authenticated session returns, and the credential validity status of the identities it reveals. An escalation claim is only sound when it names an edge the baseline did not already grant, or an identity whose credential is confirmed valid rather than merely enumerated. Anything else is a description of the default posture and belongs in the inventory.

*Disproof:* The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.**

Where anonymous or guest access to the domain is still permitted, a single unauthenticated SMB session yields the domain user list, group membership and the password policy. That combination is the classic first observable for internal enumeration and it is genuinely useful: the policy tells the operator whether spraying is safe. But it proves nothing about credential possession - no secret was read, only directory metadata. Detection logic built on it needs the same care as logic built on duplicated infrastructure traffic: internal server-to-server replication duplicates the client's own requests and must be excluded, or the same duplication appears in telemetry as if a second, independent actor were enumerating.

*Disproof:* If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.

## Exploitation

**Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.**

Account enumeration is the cheapest step in an attack chain and the one most often assumed to be blocked. It is not: an ordinary domain account can run an LDAP query against the directory and receive the distinguished name, SAM account name and display name for domain users, and can separately enumerate group membership to find who is actually privileged. The useful hunting insight is that enumeration and privilege lookup are DIFFERENT queries with different blast radius — a host enumerating the domain user list at volume is reconnaissance, while a query against a specific privileged group is targeting. Practically, establish a baseline of which hosts perform LDAP queries and at what rate; a single interactive workstation should not be issuing LDAP searches at all. Anonymous or unauthenticated enumeration where the domain controller permits it removes even the credential requirement.

*Disproof:* If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ad-enum-to-kerberoast-to-lateral-execution` — Directory enumeration to SPN enumeration to kerberoasted service account to lateral execution (goal: `domain_wide_lateral_movement`)

## Real-World Examples

Not yet researched.

## Common False Positives

**AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool is living-off-the-land tradecraft, not a distinct vulnerability; do not file the absence of a command-line alert as a control failure, because the same module an administrator uses for routine domain queries is the one an attacker reuses.**

The observable that triggers this false positive is AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool, filed either as malicious module use or as a detection gap because no command-line alert fired. Both framings are wrong: the same module an administrator uses for routine domain queries is the one an attacker reuses, so its presence is not evidence either way, and an attacker who proxies requests through a beacon rather than a local shell produces no command line to alert on in the first place. The durable signal is identity and origin rather than tooling - which account ran the query and from which host. This rule rejects the tooling as an indicator and points the triage at the querying principal's role and the source host's administrative remit.

*Disproof:* The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.

## Validation

**Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating whether an environment would actually detect reconnaissance.**

This is a detection-validation instrument rather than an alert: seeding unprivileged decoy accounts lets a team measure, before an incident, whether its log pipeline actually carries the events that distinguish reconnaissance from normal administration. The accounts work because no production service references them, so any ticket request or failed logon naming one is unambiguous rather than heuristic. Validate by enabling DC auditing for those four event IDs and confirming alert delivery end to end during a controlled emulation run; the premise fails if no alert arrives while the events are confirmed present in the pipeline.

*Disproof:* If the decoy accounts receive no alerts during a controlled adversary-emulation run while events 4625/4768/4769/4771 are confirmed present in the log pipeline, the validation premise fails.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1087/002/>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/>
- **horizon3.ai** (writeup)
  - <https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md>
- **redcanary.com** (research)
  - <https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4511.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
