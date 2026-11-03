# Methodology — Group Policy Abuse

> Derived from 9 verified items. Regenerate with `python -m wks.methodgen --class ad_group_policy --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Group Policy is applied as files in a share that authenticated administrators may write, so editing the policy changes what every affected machine does.

**References.** CWE-269

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Image, text, script, ScheduledTasks.xml or modified registry.pol/GptTmpl.inf files appearing under SYSVOL Policies from a source other than legitimate replication is the earliest file-side observable of a GPO write.**

Directory auditing catches the link change; this catches the payload. The GPO's template half lives in the SYSVOL share, so a hijack necessarily drops new or modified files there before anything reaches an endpoint, and the staging of content into the domain's sysvol share is a separate logged step from the GPO link itself. What makes it detectable is the source: legitimate writes to SYSVOL arrive through domain controller replication from the DC's own NTDS.dit-driven copy. A file appearing under <domain>\Policies\ written by any other host is anomalous. Hunt: alert on file creation under SYSVOL Policies from non-replication sources, and prioritise the specific extensions worth an analyst's time - images and text files (staged content served to endpoints by the Files preference extension), scripts, ScheduledTasks.xml (task definitions), and modified registry.pol or GptTmpl.inf (settings templates). Also baseline the expected file inventory per GPO GUID; a new file in a GPO's Machine\ or Scripts\ directory that no baseline lists is worth a look even when the writer is a DC, because replication will happily carry an attacker-staged file to every DC in the estate and make it look legitimate afterwards.

- *Disproof:* Every file creation under SYSVOL Policies in the window is attributable to the domain controller replication path or to a documented software deployment agent with a maintenance window, and no file in any GPO's template differs from its recorded baseline.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**A 5136 modification to gPLink on the domain root or on a sensitive OU by an account outside the authorised GPO administration set is the earliest observable of domain-wide GPO abuse.**

The GPO itself is not the interesting event; the link is. Creating a groupPolicyContainer and writing settings into it are both recoverable, but the moment gPLink on the domain root changes, scope goes from one OU to the whole domain. That is the first hop of the attack and it happens in the directory log, before any endpoint has applied anything. Practical rule: alert on 5136 where the modified attribute is gPLink and the target object is the domain root or a server or workstation OU, and on 5137 where the object class is groupPolicyContainer. Baseline the set of accounts that legitimately create or link GPOs - normally Domain Admins plus a dedicated, audited GPO administration role - and alert on anything outside it. The second early observable is a simultaneous rise in Group Policy Operational activity across many hosts from the same DC, because a single link change fans out to every machine in scope within one refresh interval. Note that basic domain users can already enumerate GPO objects and their links, so the attacker does not need any special reconnaissance privilege to find the right link target.

- *Disproof:* The gPLink modification is attributable to an account inside the authorised GPO administration set and matches a recorded change window, or the modified object is not a policy-bearing link but a routine OU rename or delegation change that happens to share the attribute name.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**GPO settings that only change appearance and access state - wallpaper, lock screen image, logon banner text, local administrator account status - deliver domain-wide impact with no malware on disk.**

Not every GPO abuse is code execution. The Personalization Policy, Desktop Policy, Group Policy Registry and Security Settings extensions accept wallpaper paths, lock screen images, legal notice caption and text, and the enabled/disabled state of the built-in administrator account. An actor who authors a GPO can point the lock screen and wallpaper at an image staged in SYSVOL, set the logon banner to an extortion demand, and disable the local administrator account - all of which render on every domain-joined workstation in scope. In a real incident this was delivered with no ransomware binary, no endpoint persistence, no malicious process and no encrypted files: the whole attack lived inside Active Directory. Detection consequence: file- and process-based endpoint detection sees nothing, so the hunt belongs on the directory and the SYSVOL share. Flag any GPO whose Personalization or Desktop settings point at a UNC path under SYSVOL, and any GPO setting legalnoticecaption or legalnoticetext to non-baseline text, and any GptTmpl.inf entry disabling the built-in administrator account.

- *Disproof:* The GPO in question configures no wallpaper, lock screen, logon banner or administrator account state, and its settings resolve to an approved baseline with no SYSVOL-referenced file paths, in which case this impact channel is not what the actor used and a different mechanism must be named.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-ldap); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**GPO abuse does not require domain admin, because GPO access control permissions can be delegated to ordinary domain users, so the control to audit is write delegation on the policy object rather than membership of a privileged group.**

MITRE's T1484.001 makes the authorisation surface explicit. GPOs are containers for group policy settings made up of files stored within a predictable network path, and, like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs; it is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain. The default posture is therefore read for everyone and write for nobody, which means any write delegation anywhere in the hierarchy is a deliberate exception and a much smaller set to audit than the domain admin list. The technique's own detection guidance points the same way: identify and correct GPO permissions abuse opportunities, ex: GPO modification privileges, using auditing tools such as BloodHound. Note also that the same source records the breadth of what a write buys, since since GPOs can control so many user and machine settings in the AD environment there are a great number of potential attacks that can stem from this GPO abuse, so a single delegated-write object can reach scheduled tasks, tool disabling, ingress transfer and account creation.

- *Disproof:* No non-domain-admin principal holds write, apply or edit permission on any GPO, its files in SYSVOL, or the OU/site link that scopes it, and the delegated rights found are documented and approved for the administrative function that requires them.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1484/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview)

**Group Policy Objects are file sets in the SYSVOL network path, so write access to SYSVOL lets one write change the behaviour of every machine and user the policy applies to.**

GPO abuse is a file-write problem wearing an Active Directory costume. The settings are stored as files under a predictable network path, and the client applies whatever it finds there at refresh. That means the escalation is not 'modify an object' but 'write a file that a privileged client will execute', and the blast radius is every host the policy applies to — a single write can create a scheduled task, change a security setting, or push a binary. The control is therefore filesystem permission on SYSVOL, not GPO ACLs in the abstract: confirm that only Domain Admins have write on the SYSVOL share and its underlying files, and treat any write to the Policies tree as an incident regardless of the authenticated identity. Because scheduled tasks and software installation are legitimate GPO features, the written content is indistinguishable from policy at the protocol level; the file write is the signal.

- *Disproof:* If SYSVOL and the Policies tree are writable only by Domain Admins and machine accounts, and no lower-privilege principal can create or modify a GPO file, then no GPO-based code execution path exists from that account.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1484/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy)

**Editing a GPO's SYSVOL template files directly, bypassing the Group Policy Management Console, changes what every linked machine applies while leaving no directory-object audit trail.**

The supported administrative path writes a GPO twice: the Group Policy Container change lands in Active Directory and the template change lands in the SYSVOL share under <domain>\Policies\<GUID>\Machine\registry.pol and GptTmpl.inf. An attacker with SYSVOL write access can skip the first half entirely and edit registry.pol, GptTmpl.inf or ScheduledTasks.xml straight on the share, which is what tools such as PowerView and SharpGPOAbuse automate. The operational tell is the audit gap: a supported edit produces a 5136 'directory service object was modified' event on the GPO object, so SYSVOL content that changes with no matching 5136 means the change never went through GPMC. Hunt on the DC by comparing SYSVOL file mtimes and hashes against the versionNumber attribute on each GPO, and alert on registry.pol or GptTmpl.inf writes whose source is not the DC replication path. Note the honest limit - a missing 5136 can also mean DS Access auditing was never enabled, so confirm audit policy state before calling the gap malicious.

- *Disproof:* Every SYSVOL template change in the window is accompanied by a matching 5136 on the corresponding groupPolicyContainer object and the change is attributable to an authorised GPO administrator account, which means the GPMC path was used and no hijack occurred.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A groupPolicyContainer created, linked or modified by an account inside the authorised GPO administration set during a recorded change window is normal administration, not GPO abuse.**

Every rule that watches for groupPolicyContainer creation, gPLink modification or SYSVOL template change will fire on the ordinary case first: an administrator rolling out a new baseline, a helpdesk team linking a printer or kiosk policy to a departmental OU, or a scheduled task policy being updated. That is not a finding. The discriminator is the identity of the actor, not the shape of the event. Baseline the accounts that legitimately create and link GPOs - typically Domain Admins plus a dedicated, audited GPO administration role - and treat anything outside that set as worth investigating. A second legitimate trigger worth knowing about is replication: SYSVOL changes that originate from the domain controller replication path are normal and must be excluded, as must the routine synchronisation traffic between domain controllers. Rules built on these indicators typically need tuning for exactly this reason. Note the residual risk rather than dismissing it: abuse is frequently performed by an account that legitimately holds these rights, which is why the recommendation is to separate GPO creation rights from GPO link rights and grant both only to a dedicated role, with just-in-time elevation for domain admin.

- *Disproof:* The account that created or linked the GPO is outside the authorised GPO administration set, or the SYSVOL change came from a source other than DC replication, in which case the administrative explanation does not hold and the change must be escalated regardless of how routine it looks.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**A SYSVOL Policies write that matches the approved baseline content and the versionNumber bump of the accountable GPO administrator is normal policy deployment, not GPO abuse.**

The second false positive for this class is subtler than the first. A scheduled task policy that actually deploys a scheduled task, a logon script that actually runs, or a drive-mapping policy that actually creates a shortcut will, on its legitimate run, produce file and execution telemetry in SYSVOL and on endpoints that looks like the technique. The test is attribution plus content agreement, not the existence of the artefact: was the account one of the authorised GPO administrators, did the template content match the approved baseline for that GPO, and did versionNumber increment as the supported path requires. GPO auditing tooling exists precisely to produce that approved baseline - one sweep gives you both the abuse test (baseline mismatch) and the false-positive list (baseline match), so run the sweep before filing anything. The residual risk is not that admins write GPOs; it is that an account holding those rights is compromised and the write is genuinely malicious while looking routine. That is why the hardening recommendation separates GPO creation rights from GPO link rights, grants both to a dedicated audited role, and moves domain admin to just-in-time elevation.

- *Disproof:* The SYSVOL write came from an account outside the authorised GPO administrator set, or the template content differs from the approved baseline while versionNumber was left unchanged, which rules out the supported deployment path and makes this administration.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-powerview); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**Write access delegated on a single widely-linked GPO converts one non-admin account into code execution on every machine the policy applies to, which is why the delegation is a domain-compromise primitive rather than a local misconfiguration.**

Four published facts compose into the chain, and each is independently verifiable. First, the authority to modify policy is delegable: it is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain, so the actor need not be a domain administrator. Second, the object being modified is a file-backed construct rather than an abstract setting: Microsoft documents that a GPO consists of two main components, the Group Policy container and the Group Policy template, with the container in the domain partition of Active Directory and the template located in the SYSVOL folder on each domain controller, which is why write to the template is equivalent to write to the policy. Third, the payoff is breadth rather than a single host, because since GPOs can control so many user and machine settings in the AD environment there are a great number of potential attacks that can stem from this GPO abuse, and Microsoft's own overview confirms you can link GPOs to various levels within the AD hierarchy, such as sites, domains, and organizational units, which define their scope of application. Fourth, the specific code-execution payload is the scheduled task definition, where publicly available scripts such as New-GPOImmediateTask can be leveraged to automate the creation of a malicious Scheduled Task/Job by modifying GPO settings, in this case modifying the ScheduledTasks.xml preference file, and the same entry records malicious GPO modifications implementing behaviours including Scheduled Task/Job, Disable or Modify Tools, Ingress Tool Transfer, Create Account and Service Execution. The escalation is not gradual: the chain converts a delegated right on one object into execution on the policy's full link scope, and it lands without an attacker-initiated action because policy settings are applied at computer startup and user sign in. That is why the audit priority is the GPO whose link reaches the widest set of hosts, not the number of GPOs modified.

- *Disproof:* The delegated principal cannot write the GPO or its SYSVOL files, or the GPO's link scope, security filtering and WMI filters resolve to a set of hosts the actor cannot already administer, so the policy edit never reaches a target.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1484/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
