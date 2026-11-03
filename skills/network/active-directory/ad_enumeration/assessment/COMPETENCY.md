# Methodology — Active Directory Enumeration

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class ad_enumeration --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-enumeration-with-powerview.md)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**An anonymous SMB session that returns a full user listing and the domain password policy is an early observable for enumeration, but it is a read-only baseline capability rather than a credential compromise.**

Where anonymous or guest access to the domain is still permitted, a single unauthenticated SMB session yields the domain user list, group membership and the password policy. That combination is the classic first observable for internal enumeration and it is genuinely useful: the policy tells the operator whether spraying is safe. But it proves nothing about credential possession - no secret was read, only directory metadata. Detection logic built on it needs the same care as logic built on duplicated infrastructure traffic: internal server-to-server replication duplicates the client's own requests and must be excluded, or the same duplication appears in telemetry as if a second, independent actor were enumerating.

- *Disproof:* If the anonymous session yields only public directory metadata and no secret, hash, or policy-derived credential, then the enumeration finding reduces to a hardening gap about anonymous access, and any claim of credential compromise from it is invalid.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## False-positive rejection

_No verified fp_rule items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Test sequence, Validation, False-positive rejection, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
