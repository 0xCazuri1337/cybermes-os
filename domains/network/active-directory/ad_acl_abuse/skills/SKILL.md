---
name: ad_acl_abuse-hunting
description: Use when hunting Active Directory ACL Abuse in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Active Directory ACL Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-269 · OWASP —
> evidence: 10 items, 5 supported, 3 FP rules, 1 chains
> maturity: **researching** — missing: items

A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.

**Also called:** acl abuse, genericwrite, genericall, writedacl, writeowner, dcsync, dcsync rights, object access abuse, privilege escalation rights, acl misconfiguration


## Techniques (what to change)

- A principal holding both DS-Replication-Get-Changes and DS-Replication-Get-Changes-All on the domain object can perform DCSync to dump all domain hashes including krbtgt.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Either replication right is missing, or the principal is not in a position to invoke DRS replication against a DC.
  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
- An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.  _(merged 1 duplicate row(s))_
  - **Disproof:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
- Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
  - Sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- GenericAll or AddMember on a group lets an attacker add themselves to that group, escalating privileges if the group is privileged.  _(merged 1 duplicate row(s))_
  - **Disproof:** No AddMember or GenericAll ACE exists on the group, or group membership changes are blocked by Protected Users / managed service accounts.
  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups>
- GenericAll over a user object lets an attacker reset the password, set an SPN for targeted Kerberoasting, or write msDS-KeyCredentialLink for shadow credentials, gaining control of that account.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** No write access exists on the user object, or the target is a protected admin (AdminSDHolder resets the ACL every 60 minutes).
  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
- WriteDACL on any object lets an attacker grant themselves GenericAll on that object, then abuse it as if they already held full control.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** The attacker lacks WriteDACL, or the object is protected by AdminSDHolder/privileged container ACL inheritance.
  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>
- WriteOwner on an object lets an attacker take ownership of it, then grant themselves WriteDACL and finally GenericAll, achieving full control.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** WriteOwner is absent, or the object's owner cannot be changed by the attacker's principal.
  - Sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md>

## False-positive rules (when to reject it)

- A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.
- A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
  - Sources: <https://www.thehacker.recipes/ad/movement/dacl/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>

## Rejected before you report

- **ACL abuse occurred: BloodHound shows a path from the compromised principal to Domain Admins**
  - Killed by: no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
  - Rule: an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration


## Hunt procedure

1. Enumerate the ACL on the target object and test only the specific write principal it grants.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/active-directory/ad_acl_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_acl_abuse`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
