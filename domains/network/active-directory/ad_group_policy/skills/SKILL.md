---
name: ad_group_policy-hunting
description: Use when hunting Group Policy Abuse in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Group Policy Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-269 · OWASP —
> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
> maturity: **mature**

Group Policy is applied as files in a share that authenticated administrators may write, so editing the policy changes what every affected machine does.

**Also called:** gpo, group policy, group policy preference, sysvol, netlogon, gpt.ini, scheduled tasks via gpo


## Prerequisites (do not start without these)

- A GPO's blast radius is set entirely by where its container is linked in the directory tree, so a link at the domain root reaches every user and computer object beneath it.
  - **Disproof:** The gPLink value does not place the policy at the domain root or a broad OU - it points at a narrow container holding few or no reachable computer objects - or the object named in the report is not a Group Policy Container at all, in which case link scope is not the enabling condition and a different mechanism must be named.
  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>

## Recon signals (where to look)

- A 5136 modification to gPLink on the domain root or on a sensitive OU by an account outside the authorised GPO administration set is the earliest observable of domain-wide GPO abuse.
  - **Disproof:** The gPLink modification is attributable to an account inside the authorised GPO administration set and matches a recorded change window, or the modified object is not a policy-bearing link but a routine OU rename or delegation change that happens to share the attribute name.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- GPO abuse detonates late, because computer configuration applies only on reboot or policy refresh, so a GPO written today can sit dormant in the endpoint cache for a day before any visible effect.
  - **Disproof:** The Group Policy History and Shadow registry keys on the endpoints show the policy was applied in the same interval it was authored, or no endpoint in scope has a cached copy of the GPO at all, which means there was no dormant window and the dormancy signal does not apply to this incident.
  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- Image, text, script, ScheduledTasks.xml or modified registry.pol/GptTmpl.inf files appearing under SYSVOL Policies from a source other than legitimate replication is the earliest file-side observable of a GPO write.
  - **Disproof:** Every file creation under SYSVOL Policies in the window is attributable to the domain controller replication path or to a documented software deployment agent with a maintenance window, and no file in any GPO's template differs from its recorded baseline.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Techniques (what to change)

- GPO abuse does not require domain admin, because GPO access control permissions can be delegated to ordinary domain users, so the control to audit is write delegation on the policy object rather than membership of a privileged group.
  - **Disproof:** No non-domain-admin principal holds write, apply or edit permission on any GPO, its files in SYSVOL, or the OU/site link that scopes it, and the delegated rights found are documented and approved for the administrative function that requires them.
  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview>
- Editing a GPO's SYSVOL template files directly, bypassing the Group Policy Management Console, changes what every linked machine applies while leaving no directory-object audit trail.
  - **Disproof:** Every SYSVOL template change in the window is accompanied by a matching 5136 on the corresponding groupPolicyContainer object and the change is attributable to an authorised GPO administrator account, which means the GPMC path was used and no hijack occurred.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- GPO settings that only change appearance and access state - wallpaper, lock screen image, logon banner text, local administrator account status - deliver domain-wide impact with no malware on disk.
  - **Disproof:** The GPO in question configures no wallpaper, lock screen, logon banner or administrator account state, and its settings resolve to an approved baseline with no SYSVOL-referenced file paths, in which case this impact channel is not what the actor used and a different mechanism must be named.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- Writing a ScheduledTasks.xml entry into a linked GPO's SYSVOL template creates a SYSTEM-context scheduled task on every machine in scope, without placing a binary on the endpoint.
  - **Disproof:** The ScheduledTasks.xml in question is byte-identical to the last approved baseline for that GPO and its versionNumber matches, or the task definition points at a local signed binary with no SYSVOL UNC source and no GPO-scoped trigger, in which case no GPO-delivered execution path exists.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- Group Policy Objects are file sets in the SYSVOL network path, so write access to SYSVOL lets one write change the behaviour of every machine and user the policy applies to.
  - **Disproof:** If SYSVOL and the Policies tree are writable only by Domain Admins and machine accounts, and no lower-privilege principal can create or modify a GPO file, then no GPO-based code execution path exists from that account.
  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy>

## Validation bar (how to prove it)

- Comparing SYSVOL template hashes against each GPO's versionNumber, and checking for a matching 5136, separates a GPMC-administrated change from a direct SYSVOL hijack.
  - **Disproof:** Every GPO whose SYSVOL template hash moved also shows an incremented versionNumber and a matching 5136 from an authorised GPO administrator, which proves the supported path was used and the versionNumber/hash disagreement test returns clean for the whole estate.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## False-positive rules (when to reject it)

- A groupPolicyContainer created, linked or modified by an account inside the authorised GPO administration set during a recorded change window is normal administration, not GPO abuse.
  - **Disproof:** The account that created or linked the GPO is outside the authorised GPO administration set, or the SYSVOL change came from a source other than DC replication, in which case the administrative explanation does not hold and the change must be escalated regardless of how routine it looks.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- A SYSVOL Policies write that matches the approved baseline content and the versionNumber bump of the accountable GPO administrator is normal policy deployment, not GPO abuse.
  - **Disproof:** The SYSVOL write came from an account outside the authorised GPO administrator set, or the template content differs from the approved baseline while versionNumber was left unchanged, which rules out the supported deployment path and makes this administration.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Evidence requirements

- A convincing observation for this class is: Operationally: hunt the SYSVOL Policies tree for ScheduledTasks.xml content that differs from the GPO's versionNumber baseline, and treat a scheduled task appearing on many hosts at once with a definition sourced from a UNC SYSVOL path as a GPO-delivery artefact rather than a host compromise.
  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_group_policy.technique.gpo_scheduled_task_xml_executes_code_domain_wide) states the full boundary.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Chaining opportunities

- Write access delegated on a single widely-linked GPO converts one non-admin account into code execution on every machine the policy applies to, which is why the delegation is a domain-compromise primitive rather than a local misconfiguration.
  - **Disproof:** The delegated principal cannot write the GPO or its SYSVOL files, or the GPO's link scope, security filtering and WMI filters resolve to a set of hosts the actor cannot already administer, so the policy edit never reaches a target.
  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview>

---
Full class document: `domains/network/active-directory/ad_group_policy/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_group_policy`
