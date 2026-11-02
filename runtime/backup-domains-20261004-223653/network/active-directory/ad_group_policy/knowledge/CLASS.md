# Group Policy Abuse

## Definition

Group Policy is applied as files in a share that authenticated administrators may write, so editing the policy changes what every affected machine does.

- **CWE:** CWE-269
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["gpo", "group policy", "group policy preference", "sysvol", "netlogon", "gpt.ini", "scheduled tasks via gpo"]

Canonical home for `ad_group_policy`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A GPO's blast radius is set entirely by where its container is linked in the directory tree, so a link at the domain root reaches every user and computer object beneath it.**

Before any GPO finding can be rated, the link scope has to be read off the object, because the same malicious setting has completely different consequences depending on where the Group Policy Container is linked. A GPO is two coupled halves: the Group Policy Container (GPC) that lives in Active Directory and carries the link, and the Group Policy Template (GPT) that lives in the SYSVOL share and carries the actual settings files. Scope comes from the GPC side: link it to the domain root and the policy applies to every computer and user object beneath that root, link it to a site and it applies to machines in that site, link it to an OU and it applies to the objects in that OU. Operational step: for every GPO in the report, record the gPLink value and the object it points at before scoring severity, and count the computer objects actually in that scope. A GPO linked at the domain root with a disabled local administrator account is a domain-wide denial of admin; the same GPO linked to a 12-machine kiosk OU is a nuisance. Also enumerate the OU tree, because nested OUs let an operator scope a policy narrowly, and a finding that ignores nesting overstates scope.

*Disproof:* The gPLink value does not place the policy at the domain root or a broad OU - it points at a narrow container holding few or no reachable computer objects - or the object named in the report is not a Group Policy Container at all, in which case link scope is not the enabling condition and a different mechanism must be named.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A 5136 modification to gPLink on the domain root or on a sensitive OU by an account outside the authorised GPO administration set is the earliest observable of domain-wide GPO abuse.**

The GPO itself is not the interesting event; the link is. Creating a groupPolicyContainer and writing settings into it are both recoverable, but the moment gPLink on the domain root changes, scope goes from one OU to the whole domain. That is the first hop of the attack and it happens in the directory log, before any endpoint has applied anything. Practical rule: alert on 5136 where the modified attribute is gPLink and the target object is the domain root or a server or workstation OU, and on 5137 where the object class is groupPolicyContainer. Baseline the set of accounts that legitimately create or link GPOs - normally Domain Admins plus a dedicated, audited GPO administration role - and alert on anything outside it. The second early observable is a simultaneous rise in Group Policy Operational activity across many hosts from the same DC, because a single link change fans out to every machine in scope within one refresh interval. Note that basic domain users can already enumerate GPO objects and their links, so the attacker does not need any special reconnaissance privilege to find the right link target.

*Disproof:* The gPLink modification is attributable to an account inside the authorised GPO administration set and matches a recorded change window, or the modified object is not a policy-bearing link but a routine OU rename or delegation change that happens to share the attribute name.

**GPO abuse detonates late, because computer configuration applies only on reboot or policy refresh, so a GPO written today can sit dormant in the endpoint cache for a day before any visible effect.**

The gap between authoring a GPO and seeing anything on a screen is the most forensically instructive feature of this class and it is what makes timeline reconstruction fail. The template is written to SYSVOL and cached on endpoints immediately, but computer configuration - wallpaper, lock screen, security settings, firewall disabling - only applies on reboot or refresh. In one documented incident the malicious GPO was authored on day one and detonated across the estate the next day purely because machines were restarted in the ordinary course of business. Two hunting consequences. First, the quiet window between weaponisation and impact is where exfiltration, persistence and further staging happen, so a hunt that stops at the first visible symptom has already lost the lead. Second, the cause (a GPO creation event in the directory log) and the effect (mass user-visible disruption) are separated in time, which means correlation has to be done explicitly: pull the Group Policy History and Shadow registry keys and MFT timestamps from affected hosts and align them against 5136/5137 timestamps from the DC. The presence of a Loopback-GPO-List entry in HKCU policy state marks a GPO processed in loopback mode, which makes user configuration apply regardless of who logs on - worth checking explicitly when you are reconstructing scope.

*Disproof:* The Group Policy History and Shadow registry keys on the endpoints show the policy was applied in the same interval it was authored, or no endpoint in scope has a cached copy of the GPO at all, which means there was no dormant window and the dormancy signal does not apply to this incident.

**Image, text, script, ScheduledTasks.xml or modified registry.pol/GptTmpl.inf files appearing under SYSVOL Policies from a source other than legitimate replication is the earliest file-side observable of a GPO write.**

Directory auditing catches the link change; this catches the payload. The GPO's template half lives in the SYSVOL share, so a hijack necessarily drops new or modified files there before anything reaches an endpoint, and the staging of content into the domain's sysvol share is a separate logged step from the GPO link itself. What makes it detectable is the source: legitimate writes to SYSVOL arrive through domain controller replication from the DC's own NTDS.dit-driven copy. A file appearing under <domain>\Policies\ written by any other host is anomalous. Hunt: alert on file creation under SYSVOL Policies from non-replication sources, and prioritise the specific extensions worth an analyst's time - images and text files (staged content served to endpoints by the Files preference extension), scripts, ScheduledTasks.xml (task definitions), and modified registry.pol or GptTmpl.inf (settings templates). Also baseline the expected file inventory per GPO GUID; a new file in a GPO's Machine\ or Scripts\ directory that no baseline lists is worth a look even when the writer is a DC, because replication will happily carry an attacker-staged file to every DC in the estate and make it look legitimate afterwards.

*Disproof:* Every file creation under SYSVOL Policies in the window is attributable to the domain controller replication path or to a documented software deployment agent with a maintenance window, and no file in any GPO's template differs from its recorded baseline.

**A convincing observation for this class is: Operationally: hunt the SYSVOL Policies tree for ScheduledTasks.xml content that differs from the GPO's versionNumber baseline, and treat a scheduled task appearing on many hosts at once with a definition sourced from a UNC SYSVOL path as a GPO-delivery artefact rather than a host compromise.**

Derived from ad_group_policy.technique.gpo_scheduled_task_xml_executes_code_domain_wide, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_group_policy.technique.gpo_scheduled_task_xml_executes_code_domain_wide) states the full boundary.

## Exploitation

**GPO abuse does not require domain admin, because GPO access control permissions can be delegated to ordinary domain users, so the control to audit is write delegation on the policy object rather than membership of a privileged group.**

MITRE's T1484.001 makes the authorisation surface explicit. GPOs are containers for group policy settings made up of files stored within a predictable network path, and, like other objects in AD, GPOs have access controls associated with them. By default all user accounts in the domain have permission to read GPOs; it is possible to delegate GPO access control permissions, e.g. write access, to specific users or groups in the domain. The default posture is therefore read for everyone and write for nobody, which means any write delegation anywhere in the hierarchy is a deliberate exception and a much smaller set to audit than the domain admin list. The technique's own detection guidance points the same way: identify and correct GPO permissions abuse opportunities, ex: GPO modification privileges, using auditing tools such as BloodHound. Note also that the same source records the breadth of what a write buys, since since GPOs can control so many user and machine settings in the AD environment there are a great number of potential attacks that can stem from this GPO abuse, so a single delegated-write object can reach scheduled tasks, tool disabling, ingress transfer and account creation.

*Disproof:* No non-domain-admin principal holds write, apply or edit permission on any GPO, its files in SYSVOL, or the OU/site link that scopes it, and the delegated rights found are documented and approved for the administrative function that requires them.

**Editing a GPO's SYSVOL template files directly, bypassing the Group Policy Management Console, changes what every linked machine applies while leaving no directory-object audit trail.**

The supported administrative path writes a GPO twice: the Group Policy Container change lands in Active Directory and the template change lands in the SYSVOL share under <domain>\Policies\<GUID>\Machine\registry.pol and GptTmpl.inf. An attacker with SYSVOL write access can skip the first half entirely and edit registry.pol, GptTmpl.inf or ScheduledTasks.xml straight on the share, which is what tools such as PowerView and SharpGPOAbuse automate. The operational tell is the audit gap: a supported edit produces a 5136 'directory service object was modified' event on the GPO object, so SYSVOL content that changes with no matching 5136 means the change never went through GPMC. Hunt on the DC by comparing SYSVOL file mtimes and hashes against the versionNumber attribute on each GPO, and alert on registry.pol or GptTmpl.inf writes whose source is not the DC replication path. Note the honest limit - a missing 5136 can also mean DS Access auditing was never enabled, so confirm audit policy state before calling the gap malicious.

*Disproof:* Every SYSVOL template change in the window is accompanied by a matching 5136 on the corresponding groupPolicyContainer object and the change is attributable to an authorised GPO administrator account, which means the GPMC path was used and no hijack occurred.

**GPO settings that only change appearance and access state - wallpaper, lock screen image, logon banner text, local administrator account status - deliver domain-wide impact with no malware on disk.**

Not every GPO abuse is code execution. The Personalization Policy, Desktop Policy, Group Policy Registry and Security Settings extensions accept wallpaper paths, lock screen images, legal notice caption and text, and the enabled/disabled state of the built-in administrator account. An actor who authors a GPO can point the lock screen and wallpaper at an image staged in SYSVOL, set the logon banner to an extortion demand, and disable the local administrator account - all of which render on every domain-joined workstation in scope. In a real incident this was delivered with no ransomware binary, no endpoint persistence, no malicious process and no encrypted files: the whole attack lived inside Active Directory. Detection consequence: file- and process-based endpoint detection sees nothing, so the hunt belongs on the directory and the SYSVOL share. Flag any GPO whose Personalization or Desktop settings point at a UNC path under SYSVOL, and any GPO setting legalnoticecaption or legalnoticetext to non-baseline text, and any GptTmpl.inf entry disabling the built-in administrator account.

*Disproof:* The GPO in question configures no wallpaper, lock screen, logon banner or administrator account state, and its settings resolve to an approved baseline with no SYSVOL-referenced file paths, in which case this impact channel is not what the actor used and a different mechanism must be named.

**Writing a ScheduledTasks.xml entry into a linked GPO's SYSVOL template creates a SYSTEM-context scheduled task on every machine in scope, without placing a binary on the endpoint.**

The Scheduled Tasks client-side extension reads ScheduledTasks.xml from the GPO template in SYSVOL and registers the tasks it defines on the endpoint as SYSTEM. Because the payload is the policy configuration rather than a dropped file, this is a code-execution path with no new executable and no user action. Public ransomware reporting documents exactly this: LockBit affiliates modified SYSVOL Group Policy files including ScheduledTasks.xml to support ransomware execution and propagation, and BlackCat/ALPHV operators abused GPOs to create scheduled tasks. The related startup-item path is the same shape - Ryuk operators were observed distributing through Group Policy and SYSVOL startup items. Operationally: hunt the SYSVOL Policies tree for ScheduledTasks.xml content that differs from the GPO's versionNumber baseline, and treat a scheduled task appearing on many hosts at once with a definition sourced from a UNC SYSVOL path as a GPO-delivery artefact rather than a host compromise. A remote attacker who can write SYSVOL gets domain-scale execution from one file write.

*Disproof:* The ScheduledTasks.xml in question is byte-identical to the last approved baseline for that GPO and its versionNumber matches, or the task definition points at a local signed binary with no SYSVOL UNC source and no GPO-scoped trigger, in which case no GPO-delivered execution path exists.

**Group Policy Objects are file sets in the SYSVOL network path, so write access to SYSVOL lets one write change the behaviour of every machine and user the policy applies to.**

GPO abuse is a file-write problem wearing an Active Directory costume. The settings are stored as files under a predictable network path, and the client applies whatever it finds there at refresh. That means the escalation is not 'modify an object' but 'write a file that a privileged client will execute', and the blast radius is every host the policy applies to — a single write can create a scheduled task, change a security setting, or push a binary. The control is therefore filesystem permission on SYSVOL, not GPO ACLs in the abstract: confirm that only Domain Admins have write on the SYSVOL share and its underlying files, and treat any write to the Policies tree as an incident regardless of the authenticated identity. Because scheduled tasks and software installation are legitimate GPO features, the written content is indistinguishable from policy at the protocol level; the file write is the signal.

*Disproof:* If SYSVOL and the Policies tree are writable only by Domain Admins and machine accounts, and no lower-privilege principal can create or modify a GPO file, then no GPO-based code execution path exists from that account.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `ad-gpo-delegated-write-to-domain-wide-execution` — Delegated GPO write to domain-wide code execution (goal: `Convert write access delegated on one widely-linked Group Policy Object into code execution on every host that policy applies to, without holding a privileged group membership.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A groupPolicyContainer created, linked or modified by an account inside the authorised GPO administration set during a recorded change window is normal administration, not GPO abuse.**

Every rule that watches for groupPolicyContainer creation, gPLink modification or SYSVOL template change will fire on the ordinary case first: an administrator rolling out a new baseline, a helpdesk team linking a printer or kiosk policy to a departmental OU, or a scheduled task policy being updated. That is not a finding. The discriminator is the identity of the actor, not the shape of the event. Baseline the accounts that legitimately create and link GPOs - typically Domain Admins plus a dedicated, audited GPO administration role - and treat anything outside that set as worth investigating. A second legitimate trigger worth knowing about is replication: SYSVOL changes that originate from the domain controller replication path are normal and must be excluded, as must the routine synchronisation traffic between domain controllers. Rules built on these indicators typically need tuning for exactly this reason. Note the residual risk rather than dismissing it: abuse is frequently performed by an account that legitimately holds these rights, which is why the recommendation is to separate GPO creation rights from GPO link rights and grant both only to a dedicated role, with just-in-time elevation for domain admin.

*Disproof:* The account that created or linked the GPO is outside the authorised GPO administration set, or the SYSVOL change came from a source other than DC replication, in which case the administrative explanation does not hold and the change must be escalated regardless of how routine it looks.

**A SYSVOL Policies write that matches the approved baseline content and the versionNumber bump of the accountable GPO administrator is normal policy deployment, not GPO abuse.**

The second false positive for this class is subtler than the first. A scheduled task policy that actually deploys a scheduled task, a logon script that actually runs, or a drive-mapping policy that actually creates a shortcut will, on its legitimate run, produce file and execution telemetry in SYSVOL and on endpoints that looks like the technique. The test is attribution plus content agreement, not the existence of the artefact: was the account one of the authorised GPO administrators, did the template content match the approved baseline for that GPO, and did versionNumber increment as the supported path requires. GPO auditing tooling exists precisely to produce that approved baseline - one sweep gives you both the abuse test (baseline mismatch) and the false-positive list (baseline match), so run the sweep before filing anything. The residual risk is not that admins write GPOs; it is that an account holding those rights is compromised and the write is genuinely malicious while looking routine. That is why the hardening recommendation separates GPO creation rights from GPO link rights, grants both to a dedicated audited role, and moves domain admin to just-in-time elevation.

*Disproof:* The SYSVOL write came from an account outside the authorised GPO administrator set, or the template content differs from the approved baseline while versionNumber was left unchanged, which rules out the supported deployment path and makes this administration.

## Validation

**Comparing SYSVOL template hashes against each GPO's versionNumber, and checking for a matching 5136, separates a GPMC-administrated change from a direct SYSVOL hijack.**

This is the test that decides whether the GPO finding survives scrutiny. Two independent checks. First, audit gap: enable DS Access auditing on the domain controllers, then compare the SYSVOL template files under <domain>\Policies\<GUID>\ against the directory log. If the SYSVOL content changed and no 5136 exists for that groupPolicyContainer, the change did not come through GPMC - which is the signature of a direct template edit by a tool such as PowerView or SharpGPOAbuse. Second, consistency: the versionNumber attribute on the GPO is supposed to increment when the template is edited through the supported path. A template whose content hash has moved while versionNumber stayed flat is an independent confirmation that the SYSVOL side was written outside the management path, and it holds even where auditing was misconfigured and the 5136 gap is therefore uninformative. Operational steps: pull gPCFileSysPath and versionNumber for every GPO, hash registry.pol, GptTmpl.inf and ScheduledTasks.xml on the share, and flag any GPO where the two disagree. GPO auditing tooling is built for exactly this sweep, and the same sweep produces the false-positive baseline of legitimately-administered GPOs for the fp_rule above.

*Disproof:* Every GPO whose SYSVOL template hash moved also shows an incremented versionNumber and a matching 5136 from an authorised GPO administrator, which proves the supported path was used and the versionNumber/hash disagreement test returns clean for the whole estate.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-ldap>
  - <https://academy.hackthebox.com/course/preview/active-directory-powerview>
  - <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1484/001/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview>
  - <https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
