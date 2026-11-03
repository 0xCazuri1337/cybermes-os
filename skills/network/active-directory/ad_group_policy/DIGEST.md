<!-- GENERATED from db/wks.db — do not edit -->
# Group Policy Abuse

> surface: `ad` · CWE: CWE-269 · OWASP: —
> maturity: **mature** — 14 items, 9 supported, 2 FP rules, 1 chains

Group Policy is applied as files in a share that authenticated administrators may write, so editing the policy changes what every affected machine does.

**Aliases:** gpo, group policy, group policy preference, sysvol, netlogon, gpt.ini, scheduled tasks via gpo

## Signal

- **Image, text, script, ScheduledTasks.xml or modified registry.pol/GptTmpl.inf files appearing under SYSVOL Policies from a source other than legitimate replication is the earliest file-side observable of a GPO write.**  
  `high_confidence` · score 0.9265 · disproved by: Every file creation under SYSVOL Policies in the window is attributable to the domain controller replication path or to a documented software deployment agent with a maintenance window, and no file in any GPO's template differs from its recorded baseline.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **A 5136 modification to gPLink on the domain root or on a sensitive OU by an account outside the authorised GPO administration set is the earliest observable of domain-wide GPO abuse.**  
  `high_confidence` · score 0.899 · disproved by: The gPLink modification is attributable to an account inside the authorised GPO administration set and matches a recorded change window, or the modified object is not a policy-bearing link but a routine OU rename or delegation change that happens to share the attribute name.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Technique

- **GPO settings that only change appearance and access state - wallpaper, lock screen image, logon banner text, local administrator account status - deliver domain-wide impact with no malware on disk.**  
  `high_confidence` · score 0.863 · disproved by: The GPO in question configures no wallpaper, lock screen, logon banner or administrator account state, and its settings resolve to an approved baseline with no SYSVOL-referenced file paths, in which case this impact channel is not what the actor used and a different mechanism must be named.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **GPO abuse does not require domain admin, because GPO access control permissions can be delegated to ordinary domain users, so the control to audit is write delegation on the policy object rather than membership of a privileged group.**  
  `high_confidence` · score 0.85 · disproved by: No non-domain-admin principal holds write, apply or edit permission on any GPO, its files in SYSVOL, or the OU/site link that scopes it, and the delegated rights found are documented and approved for the administrative function that requires them.
  sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview>
- **Group Policy Objects are file sets in the SYSVOL network path, so write access to SYSVOL lets one write change the behaviour of every machine and user the policy applies to.**  
  `high_confidence` · score 0.85 · disproved by: If SYSVOL and the Policies tree are writable only by Domain Admins and machine accounts, and no lower-privilege principal can create or modify a GPO file, then no GPO-based code execution path exists from that account.
  sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows/client-management/enroll-a-windows-10-device-automatically-using-group-policy>
- **Editing a GPO's SYSVOL template files directly, bypassing the Group Policy Management Console, changes what every linked machine applies while leaving no directory-object audit trail.**  
  `high_confidence` · score 0.844 · disproved by: Every SYSVOL template change in the window is accompanied by a matching 5136 on the corresponding groupPolicyContainer object and the change is attributable to an authorised GPO administrator account, which means the GPMC path was used and no hijack occurred.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Fp Rule

- **A groupPolicyContainer created, linked or modified by an account inside the authorised GPO administration set during a recorded change window is normal administration, not GPO abuse.**  
  `high_confidence` · score 0.8715 · disproved by: The account that created or linked the GPO is outside the authorised GPO administration set, or the SYSVOL change came from a source other than DC replication, in which case the administrative explanation does not hold and the change must be escalated regardless of how routine it looks.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **A SYSVOL Policies write that matches the approved baseline content and the versionNumber bump of the accountable GPO administrator is normal policy deployment, not GPO abuse.**  
  `high_confidence` · score 0.863 · disproved by: The SYSVOL write came from an account outside the authorised GPO administrator set, or the template content differs from the approved baseline while versionNumber was left unchanged, which rules out the supported deployment path and makes this administration.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Chain Link

- **Write access delegated on a single widely-linked GPO converts one non-admin account into code execution on every machine the policy applies to, which is why the delegation is a domain-compromise primitive rather than a local misconfiguration.**  
  `high_confidence` · score 0.8775 · disproved by: The delegated principal cannot write the GPO or its SYSVOL files, or the GPO's link scope, security filtering and WMI filters resolve to a set of hosts the actor cannot already administer, so the policy edit never reaches a target.
  sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview>
