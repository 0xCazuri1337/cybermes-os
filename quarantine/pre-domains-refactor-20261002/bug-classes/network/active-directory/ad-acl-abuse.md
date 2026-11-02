# Active Directory ACL Abuse

## Definition

A principal holds a permission on an object that permits changing what that object grants, so read access becomes control of the domain.

- **CWE:** CWE-269
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["acl abuse", "genericwrite", "genericall", "writedacl", "writeowner", "dcsync", "dcsync rights", "object access abuse", "privilege escalation rights", "acl misconfiguration"]

Canonical home for `ad_acl_abuse`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.**

This is a privilege-escalation primitive, not a data leak. Because access control is itself an object whose access is controlled by the DACL, granting a principal the right to modify the DACL (or to take ownership, which lets you then rewrite it) means the principal can grant itself any right it likes. On a domain object that governs replication or password reset, that is domain compromise. The enumeration approach: for each interesting object, read the access control entries and ask not 'can I write this object' but 'can I rewrite this object's permissions' — the two are different rights and only the second compounds. The Windows utilities that expose this are the same ones an adversary would use (icacls, cacls, takeown), which is useful for validation: confirm with the built-in tool rather than by asserting the permission model from the DACL dump alone.

*Disproof:* If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.**

The most common false positive in this class is escalating a graph edge into an incident. BloodHound represents relationships as edges between objects - member of a group, AdminTo, and similar - and its value is finding attack paths that traditional enumeration cannot see, which is exactly why the edges are a capability map. An edge says the ACL permits the transition. It does not say anyone took it. In a real incident the route taken often cannot be reconstructed at all: privileged-access routes such as DCSync, Kerberoasting of privileged service accounts, or Pass-the-Hash/Pass-the-Ticket may be left genuinely unresolved because the telemetry needed to choose between them was not collected. Therefore report a capability with a severity tied to reachability, and reserve incident language for an edge you have independent execution evidence for.

*Disproof:* If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.

**Replication or delegation ACEs held by Domain Admins, Enterprise Admins, Administrators and Domain Controllers are the Active Directory default, not an ACL-abuse finding.**

Discard when the ACE report names only those four built-in groups: the DCSync write-up states these are the principals holding the replication rights by default, so no misconfiguration was introduced. It survives when a low-privileged principal, a service account or an unexpected group holds those same rights.

*Disproof:* Would be wrong in a tenant where a group's membership was added silently, because the default right-holder list then hides a real privilege grant.

**A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.**

Discard when the report stops at the ACE: the abuse catalogue states these abuses can only be carried out while running commands as the principal listed in the ACE, so an ACE the tester cannot exercise is not an escalation path. It survives when the tester actually assumed that principal and wrote msDS-AllowedToActOnBehalfOfOtherIdentity or a forged SPN.

*Disproof:* Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
**Hypothesis:** ACL abuse occurred: BloodHound shows a path from the compromised principal to Domain Admins
- Invalidated by: no execution evidence existed for any hop; the edges record what the ACL permits, and in the real incident the route taken was left unresolved because the needed telemetry was never collected
- **Rejection rule:** an ACL edge is a capability finding, not an exploitation finding; report incident language only for a hop with independent execution evidence, and otherwise severity-track it as a latent misconfiguration

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-bloodhound>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1222/001/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-securing-active-directory-against-dcsync-attacks/>
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/dumping/dcsync>
  - <https://www.thehacker.recipes/ad/movement/dacl/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
