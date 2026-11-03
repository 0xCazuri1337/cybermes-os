<!-- GENERATED from db/wks.db — do not edit -->
# Active Directory ACL Abuse

> surface: `ad` · CWE: CWE-269 · OWASP: —
> maturity: **researching** — 10 items, 5 supported, 3 FP rules, 1 chains

A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.

**Aliases:** acl abuse, genericwrite, genericall, writedacl, writeowner, dcsync, dcsync rights, object access abuse, privilege escalation rights, acl misconfiguration

## Technique

- **An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.**  
  `high_confidence` · score 0.85 · disproved by: If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
- **Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.**  
  `high_confidence` · score 0.818 · disproved by: Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
  sources: <https://attack.mitre.org/techniques/T1222/001/> · <https://academy.hackthebox.com/course/preview/active-directory-bloodhound> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **GenericAll or AddMember on a group lets an attacker add themselves to that group, escalating privileges if the group is privileged.**  
  `high_confidence` · score 0.743 · disproved by: No AddMember or GenericAll ACE exists on the group, or group membership changes are blocked by Protected Users / managed service accounts.
  sources: <https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md> · <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups>

## Fp Rule

- **Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/> · <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
- **A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
  sources: <https://www.thehacker.recipes/ad/movement/dacl/> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>

## False-positive rules

- **Hypothesis:** ACL abuse occurred: BloodHound shows a path from the compromised principal to Domain Admins
  - **Invalidated by:** no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
  - **Rule:** an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration

## Known gaps

Not yet satisfied: `items`
