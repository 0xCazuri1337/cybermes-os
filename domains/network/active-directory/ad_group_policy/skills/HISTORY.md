# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
--- ad_group_policy@current
+++ ad_group_policy@new
@@ -76,4 +76,4 @@
   - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-policy/group-policy-overview>
 
 ---
-Full class document: `domains/network/active-directory/ad_group_policy/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_group_policy`
+Full class document: `domains/network/active-directory/ad_group_policy/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_group_policy`
```

## 2026-10-03 01:46 — 42 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
--- ad_group_policy@current
+++ ad_group_policy@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-269 · OWASP —
-> evidence: 13 items, 13 supported, 2 FP rules, 1 chains
+> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Group Policy is applied as files in a share that authenticated administrators may write, so editing the policy changes what every affected machine does.
@@ -22,7 +22,7 @@
 
 - A GPO's blast radius is set entirely by where its container is linked in the directory tree, so a link at the domain root reaches every user and computer object beneath it.
   - **Disproof:** The gPLink value does not place the policy at the domain root or a broad OU - it points at a narrow container holding few or no reachable computer objects - or the object named in the report is not a Group Policy Container at all, in which case link scope is not the enabling condition and a different mechanism must be named.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://academy.hackthebox.com/course/preview/active-directory-ldap>
 
 ## Recon signals (where to look)
 
@@ -31,7 +31,7 @@
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-ldap> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - GPO abuse detonates late, because computer configuration applies only on reboot or policy refresh, so a GPO written today can sit dormant in the endpoint cache for a day before any visible effect.
   - **Disproof:** The Group Policy History and Shadow registry keys on the endpoints show the policy was applied in the same interval it was authored, or no endpoint in scope has a cached copy of the GPO at all, which means there was no dormant window and the dormancy signal does not apply to this incident.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://attack.mitre.org/techniques/T1484/001/> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 - Image, text, script, ScheduledTasks.xml or modified registry.pol/GptTmpl.inf files appearing under SYSVOL Policies from a source other than legitimate replication is the earliest file-side observable of a GPO write.
   - **Disproof:** Every file creation under SYSVOL Policies in the window is attributable to the domain controller replication path or to a documented software deployment agent with a maintenance window, and no file in any GPO's template differs from its recorded baseline.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
@@ -69,6 +69,12 @@
   - **Disproof:** The SYSVOL write came from an account outside the authorised GPO administrator set, or the template content differs from the approved baseline while versionNumber was left unchanged, which rules out the supported deployment path and makes this administration.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-powerview> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: Operationally: hunt the SYSVOL Policies tree for ScheduledTasks.xml content that differs from the GPO's versionNumber baseline, and treat a scheduled task appearing on many hosts at once with a definition sourced from a UNC SYSVOL path as a GPO-delivery artefact rather than a host compromise.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_group_policy.technique.gpo_scheduled_task_xml_executes_code_domain_wide) states the full boundary.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+
 ## Chaining opportunities
 
 - Write access delegated on a single widely-linked GPO converts one non-admin account into code execution on every machine the policy applies to, which is why the delegation is a domain-compromise primitive rather than a local misconfiguration.
```
