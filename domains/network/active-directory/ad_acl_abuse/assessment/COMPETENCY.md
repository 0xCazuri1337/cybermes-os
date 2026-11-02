# Methodology — Active Directory ACL Abuse

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class ad_acl_abuse --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.

**References.** CWE-269

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.**

This is a privilege-escalation primitive, not a data leak. Because access control is itself an object whose access is controlled by the DACL, granting a principal the right to modify the DACL (or to take ownership, which lets you then rewrite it) means the principal can grant itself any right it likes. On a domain object that governs replication or password reset, that is domain compromise. The enumeration approach: for each interesting object, read the access control entries and ask not 'can I write this object' but 'can I rewrite this object's permissions' — the two are different rights and only the second compounds. The Windows utilities that expose this are the same ones an adversary would use (icacls, cacls, takeown), which is useful for validation: confirm with the built-in tool rather than by asserting the permission model from the DACL dump alone.

- *Disproof:* If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1222/001/); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control)

**Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist.**

odules can be considered prerequisites for successful completion of this module: 
 
 Introduction to Networking 
 Linux Fundamentals 
 Active Directory LDAP 
 Active Directory PowerView 
 
 
 
 
 BloodHound Overview 
 
 Active Directory Access Management 
 Access management in Active Directory is complex, and it is easy to introduce vulnerabilities or bad practices in day-to-day configurations. 
 Attackers and defenders commonly have difficulty discovering or auditing all the accesses of a user or how these accesses are interconnected to give privileges to a user that are not supposed to exist. 
 Because the attack surface and the amount of data produced in Active Directory environments are highly complex and evolving, and because we needed a way to automate the collection and analysis of this data, @_wald0 , @harmj0y , and @CptJesus created BloodHound . 
 
 
 Note: To understand more about Active Directory, we can look at these modules Introduction to Active Directory and Active Direct

- *Disproof:* Refuted when: the action is unreachable for the lower-privileged identity tested, i.e. the same request returns an authorisation failure rather than the elevated result. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Attackers and defenders commonly have difficulty discovering or auditing all the”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-bloodhound); [attack.mitre.org](https://attack.mitre.org/techniques/T1222/001/); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

**GenericAll or AddMember on a group lets an attacker add themselves to that group, escalating privileges if the group is privileged.**

GenericAll over a group includes the AddMember right. The attacker runs net group <group> <user> /add or Add-ADGroupMember to join a privileged group such as Domain Admins or Account Operators, immediately inheriting its permissions.

- *Disproof:* No AddMember or GenericAll ACE exists on the group, or group membership changes are blocked by Protected Users / managed service accounts.
- *Evidence:* high_confidence — [github.com](https://github.com/yaklang/hack-skills/blob/main/skills/active-directory-acl-abuse/SKILL.md); [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.**

Discard when the ACE report names only those four built-in groups: the DCSync write-up states these are the principals holding the replication rights by default, so no misconfiguration was introduced. It survives when a low-privileged principal, a service account or an unexpected group holds those same rights.

- *Disproof:* Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync)

**A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.**

Discard when the report stops at the ACE: the abuse catalogue states these abuses can only be carried out while running commands as the principal listed in the ACE, so an ACE the tester cannot exercise is not an escalation path. It survives when the tester actually assumed that principal and wrote msDS-AllowedToActOnBehalfOfOtherIdentity or a forged SPN.

- *Disproof:* Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
- *Evidence:* high_confidence — [specterops.io](https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/dacl/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
