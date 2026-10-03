# Methodology — Active Directory Enumeration

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class ad_enumeration --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Domain membership is queryable without authentication on common paths, so the directory's own structure discloses the map needed to attack it.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Directory enumeration output is only a finding once compared against a baseline of what an unprivileged authenticated account can already read, because modern AD tooling returns surprising privilege paths for ordinary non-admin users.**

Prerequisite: capture a baseline before escalating anything an enumeration tool prints. Two facts make enumeration output noisy by design. First, privilege paths are visible to low-privileged accounts: an AD ACL visualiser built with no prerequisites, requiring no install and running natively on the three major operating systems will give surprising results within minutes even as a regular non-admin user, and the same data can be collected through an indirect service such as ADWS rather than LDAP. Second, enumeration that returns account names is, on its own, low-consequence: user enumeration as a class has minimal impact in general, as the attacker would still be required to guess a valid password, and addresses for an organisation are trivially harvestable from other external means anyway. The baseline therefore has two parts: the set of objects and edges an unprivileged authenticated session returns, and the credential validity status of the identities it reveals. An escalation claim is only sound when it names an edge the baseline did not already grant, or an identity whose credential is confirmed valid rather than merely enumerated. Anything else is a description of the default posture and belongs in the inventory.

- *Disproof:* The same enumeration run against a genuinely unprivileged account reproduces the identical object set and edges, showing the tool's output reflects default read access rather than any escalation.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2024/01/15/adalanche-open-source-active-directory-acl-visualizer-explorer/); [talosintelligence.com](https://www.talosintelligence.com/vulnerability_reports/TALOS-2022-1625)

**In an Active Directory environment a non-privileged domain user can enumerate the domain forest, domain controllers, group membership and domain trust relationships, and that enumeration is the prerequisite for kerberoasting and ACL abuse rather than an end in itself.**

PowerView exposes Get-NetDomain, Get-NetForest, Get-NetForestDomain, Get-NetDomainController, Get-NetGroupMember, Get-NetLoggedon and Get-NetDomainTrust as separate cmdlets, and the ired.team lab demonstrates each one returning data from a domain-joined host under a normal user session. The property that matters for a hunter is that the whole map is built passively from LDAP queries the user's own credentials already authorise, so nothing in the traffic looks like privilege escalation. The same lab set also shows the precondition being worked around when it is missing: on a host without RSAT the AD PowerShell module is unavailable, and the documented workaround is to copy Microsoft.ActiveDirectory.Management.dll from a machine that has RSAT and import it, restoring full enumeration without elevation. Two consequences follow. Absence of RSAT on a host is not evidence that enumeration is impossible there, and a defender checking only installed tooling draws the wrong conclusion. Second, the enumeration output is the exact input later AD classes consume, so it should be collected and logged as reconnaissance rather than dismissed as routine directory browsing.

- *Disproof:* If the same enumeration queries fail for a standard domain user and only succeed with an explicit administrative credential or a host-specific privilege, then low-privilege enumeration is not available in that domain and this prerequisite does not hold.
- *Evidence:* high_confidence — [capec.mitre.org](https://capec.mitre.org/data/definitions/118.html); [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.**

Where anonymous or guest access to the domain is still permitted, a single unauthenticated SMB session yields the domain user list, group membership and the password policy. That combination is the classic first observable for internal enumeration and it is genuinely useful: the policy tells the operator whether spraying is safe. But it proves nothing about credential possession - no secret was read, only directory metadata. Detection logic built on it needs the same care as logic built on duplicated infrastructure traffic: internal server-to-server replication duplicates the client's own requests and must be excluded, or the same duplication appears in telemetry as if a second, independent actor were enumerating.

- *Disproof:* If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.**

Account enumeration is the cheapest step in an attack chain and the one most often assumed to be blocked. It is not: an ordinary domain account can run an LDAP query against the directory and receive the distinguished name, SAM account name and display name for domain users, and can separately enumerate group membership to find who is actually privileged. The useful hunting insight is that enumeration and privilege lookup are DIFFERENT queries with different blast radius — a host enumerating the domain user list at volume is reconnaissance, while a query against a specific privileged group is targeting. Practically, establish a baseline of which hosts perform LDAP queries and at what rate; a single interactive workstation should not be issuing LDAP searches at all. Anonymous or unauthenticated enumeration where the domain controller permits it removes even the credential requirement.

- *Disproof:* If the domain controller refuses LDAP binds without a valid credential AND denies all enumeration to a standard user account, then this technique has no foothold; an empty result set from a genuinely authenticated query disproves it.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating whether an environment would actually detect reconnaissance.**

This is a detection-validation instrument rather than an alert: seeding unprivileged decoy accounts lets a team measure, before an incident, whether its log pipeline actually carries the events that distinguish reconnaissance from normal administration. The accounts work because no production service references them, so any ticket request or failed logon naming one is unambiguous rather than heuristic. Validate by enabling DC auditing for those four event IDs and confirming alert delivery end to end during a controlled emulation run; the premise fails if no alert arrives while the events are confirmed present in the pipeline.

- *Disproof:* If the decoy accounts receive no alerts during a controlled adversary-emulation run while events 4625/4768/4769/4771 are confirmed present in the log pipeline, the validation premise fails.
- *Evidence:* high_confidence — [horizon3.ai](https://horizon3.ai/attack-research/defending-with-ad-tripwires-goad-walkthrough/); [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool is living-off-the-land tradecraft, not a distinct vulnerability; do not file the absence of a command-line alert as a control failure, because the same module an administrator uses for routine domain queries is the one an attacker reuses.**

The observable that triggers this false positive is AD enumeration performed with native Windows binaries or the ActiveDirectory PowerShell module rather than a purpose-built tool, filed either as malicious module use or as a detection gap because no command-line alert fired. Both framings are wrong: the same module an administrator uses for routine domain queries is the one an attacker reuses, so its presence is not evidence either way, and an attacker who proxies requests through a beacon rather than a local shell produces no command line to alert on in the first place. The durable signal is identity and origin rather than tooling - which account ran the query and from which host. This rule rejects the tooling as an indicator and points the triage at the querying principal's role and the source host's administrative remit.

- *Disproof:* The enumeration module is loaded and its cmdlets invoked from a host with no legitimate administrative role, or the querying account is a service account that has no reason to enumerate the domain, which places the activity outside any administration workflow.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-ad-module-without-rsat-or-admin-privileges.md); [redcanary.com](https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/)

**Reject a ad_enumeration finding until it is distinguished from the adjacent behaviour this class also covers. "Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating..." and "Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Purpose-built AD tripwire accounts that are never referenced by production services generate deterministic alerts on Windows Security events 4625, 4768, 4769 and 4771 the moment an attacker enumerates or attempts to use them, validating...

Adjacent behaviour that produces the same observable result: Domain account names, group memberships and privilege are discoverable through LDAP with an ordinary domain credential, so a single low-privilege login yields the target list that every later password attack or lateral move is aimed at.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Domain account names, group memberships and privilege are discoverable" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/)

**A single instance of a native enumeration command (net user, whoami /all, dsacls, nltest /domain_trusts) from a workstation is a dual-use tool and not a finding on its own; the signal is a CLUSTER of these commands inside a short window from one process tree, because each individual command is a documented day-one administration action.**

The observable that triggers this false positive is one native enumeration command - net user, whoami /all, dsacls, or nltest /domain_trusts - appearing in process command-line telemetry and filed as reconnaissance. Each of these is a documented day-one administration action, and nltest in particular exists so administrators can enumerate domain controllers and trust status; the adversary reuses the binary rather than shipping a tool. The signal that distinguishes reconnaissance from administration is not the command but the temporal cluster: several of these commands inside a short window from a single process tree, a shape no administration workflow produces because an administrator queries one thing at a time. Without this rule the per-command alert fires on every domain query, the SOC tunes it away, and the real cluster is lost with it.

- *Disproof:* The same commands appear multiple times in a tight window from one parent process, or the requesting host is a server or a jump box with no legitimate administrative role, or the commands target a domain admin group rather than the operator's own account - a pattern no administration workflow produces.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security/enumeration-and-discovery/t1087-account-discovery.md); [redcanary.com](https://redcanary.com/threat-detection-report/techniques/domain-trust-discovery/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
