# Methodology — LDAP Enumeration

> Derived from 10 verified items. Regenerate with `python -m wks.methodgen --class ldap_enum --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.**

The primitive gives you: a directory read, and the precondition is that the bind completes at all. Microsoft documents that enforcing LDAP signing on a domain controller rejects SASL binds that don't request signing and rejects simple binds over nonencrypted connections, and KrbRelayUp's guidance is to set the LDAP server signing requirement to Require signing and enable Extended Protection for Authentication. Where signing is not enforced, the same page notes that intruders can intercept authentication attempts, modify packets in transit, or hijack encrypted sessions, so the unauthenticated bind is also the tap point for the relay link. Observation that proves this segment holds: a simple bind with no SASL and no TLS completes and returns directory content, while the same bind against an enforcing domain controller returns an error rather than data. The next link consumes whatever the read returns, typically an SPN or delegation inventory.

- *Disproof:* If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**LDAP channel binding ties the bind to its TLS tunnel; when the directory server does not enforce channel binding or signing, a relayed bind can succeed even though the original transport was encrypted.**

TLS on the client side does not by itself stop a relay. Channel binding makes the server verify that the bind is arriving over the same TLS tunnel the client authenticated to, and LDAP signing protects the bind traffic's integrity. A successful bind over TLS without either control is therefore a policy signal, not proof that relay is impossible. The test should record the directory server's channel-binding and signing policy, then attempt a bind through a controlled relay. Event 3074/3075 or an equivalent channel-binding failure is a negative result; a successful bind through the relay is the positive observation.

- *Disproof:* The relay finding fails when the directory server enforces channel binding or LDAP signing and rejects the relayed bind, or when the bind never traversed the attacker's relay and the original TLS session was used end to end.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/); [trustedsec.com](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An LDAP SearchRequest whose baseObject is the zero-length DN and whose scope is base is answered by the rootDSE rather than by any naming context, so naming contexts, the server's own DNS host name and functional-level data arrive from a read whose access decision is separate from the anonymous-bind policy, which means the domain suffix can be established on a target before any credential exists.**

Probe the DSE before probing the tree. Send one SearchRequest with an empty (zero-length) baseObject, scope base, filter (objectClass=*) and the attribute list namingContexts (defaultNamingContext on AD DS), dnsHostName, forestFunctionalLevel, supportedLDAPVersion - first with no credentials at all against tcp/389, then the identical request against tcp/636, and record both responses verbatim. The rootDSE is not part of any naming context, so this request cannot be answered out of an object's subtree and its outcome is independent of whether a subtree search would return entries. Then re-send the same search with scope sub under the namingContext the DSE just handed you and diff the two responses: a base-scope request that returns a full DN while the subtree request comes back noSuchObject or insufficientAccessRights is the differential that says the DSE read and the bind policy are different controls, and a target that refuses the DSE read needs an externally supplied base DN instead. Repeat both requests once with supplied credentials and keep that as the baseline for what a bind identity changes, and record whether the DSE answered before the bind at all, because that ordering is the whole signal. Keep the raw searchRequest and searchResultEntry bytes: the naming context is what every later subtree filter is built from, so a wrong one makes the rest of the enumeration silently empty.

- *Disproof:* Wrong when the empty-base base-scope request is refused for the same caller the subtree search accepts - unwillingToPerform, noSuchObject, insufficientAccessRights, or a success whose entry carries no namingContexts attribute - because then the DSE is gated by the same policy as the rest of the directory and no suffix can be learned from the protocol at all. Also wrong to carry the result further than it reaches: the DSE sits outside every naming context, so a DSE that answers proves nothing about whether any entry below it is readable, and a host that answers the DSE while returning an empty subtree is behaving as documented rather than contradicting itself. The two responses have to be reported separately, and an answered DSE on one port says nothing about the other port until the request is repeated there.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4512.html); [thehacker.recipes](https://www.thehacker.recipes/ad/recon/ldap)

**An extensibleMatch filter component carries a matching-rule OID in place of a comparison operator, so the client is asking the server to evaluate that rule over stored values, and on AD DS the rule 1.2.840.113556.1.4.1941 walks the ancestry chain to the root, which means one subtree SearchRequest over a groups container returns the transitive membership set that a per-level member filter stops short of.**

Put a DN in the matchValue of an extensibleMatch filter component - member with rule OID 1.2.840.113556.1.4.1941 against a user DN, baseObject set to the groups container, scope subtree - and the traversal happens on the server. The differential that proves the mechanism is a count, not a status code: enumerate the container with the extended rule, then enumerate it again by reading each returned group's direct members and recursing, and diff the two principal sets. Any principal reachable only through an intermediate nested group is in the first set and absent from a single-level member filter, and that gap is exactly what a client-side loop with a fixed recursion depth gets wrong. Record the rule OID you actually sent, because a server that does not implement it answers with a result code or an empty set rather than an error that names the rule, and an empty set from an unimplemented rule is indistinguishable from an empty group unless the OID is in the notes. Record the scope as well: the rule is not restricted to a base-scope search, and a subtree chase across a high fan-out container is the expensive shape the server logs as an inefficient search. The returned principal set and the per-level expansion are the two artefacts to keep.

- *Disproof:* Wrong when the DC rejects or ignores the extended filter - unwillingToPerform, inappropriateMatching, undefinedAttributeType, or a success carrying zero entries against a container known to hold members - because then the transitive set is only reachable one level at a time and this single-query coverage does not exist on that server. Also wrong to read the returned set as an authorization answer: the rule is limited to filters that apply to the DN and it reports ancestry rather than permissions, so a principal in the result is not thereby readable, writable or reachable for anything else. And wrong whenever the recursive expansion was never run, because an empty result from a chain-walk filter has the same shape as an empty result from a group with no members, and only the count comparison distinguishes the unimplemented rule from an uninteresting group.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

**LDAP enumeration with anonymous bind exposes the directory tree, revealing group membership and the service accounts worth targeting.**

In practice on HTB this shows up as: | `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Uses `ldapsearch` to enumerate the password policy in a  target Windows domain from a Linux-based host. |
| `net accounts`                                               | Used to enumerate the password policy in a Windows domain from a Windows-based host. |
| `Import-Module .\PowerView.ps1`                              | Uses the Import-Module cmd-let to import the `PowerView.ps1` tool from a Windows-based host. |
| `Get-DomainPolicy`                                           | Used to enumerate the password policy in a target Windows domain from a Windows-based host. |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/13. Active Directory Enumeration & Attacks.md (6753 words, classified network).

- *Disproof:* Refuted when anonymous bind is disabled and no credential allows a bind, in which case the directory reveals nothing without prior authentication.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

**This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**

and forwards altered requests to the domain controller. 
 
 By default, LDAP uses port 389. LDAP over SSL/TLS (LDAPS) uses port 636 and establishes encryption immediately upon connection. 
 How LDAP channel binding works 
 LDAP channel binding uses Channel Binding Tokens (CBT) to cryptographically bind application-layer security (such as an SSL/TLS session) with the underlying network connection. This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection. 
 Channel binding is important when you use NTLM or Simple Bind authentication over SSL/TLS. Without CBT enforcement, SSL/TLS encryption alone doesn't prevent all man-in-the-middle scenarios. An attacker positioned between client and server could potentially intercept the connection. By binding the security context directly to the SSL/TLS session, CBT ensures the session remains tamper-proof thro

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This binding ensures that even if an attacker intercepts the encrypted session, ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/); [specterops.io](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.**

Discard when the tester bound with a valid domain account: the reconnaissance guide states anonymous binding is usually disabled and that most directory information is only retrievable through an authenticated bind, which is normal client behaviour. It survives when metadata or objects were returned over a genuinely anonymous bind.

- *Disproof:* Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
- *Evidence:* high_confidence — [specterops.io](https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/); [thehacker.recipes](https://www.thehacker.recipes/ad/recon/ldap)

**A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.**

Discard when the report cites event 1644 volume or request counts alone: the guide describes 1644 as logging expensive or inefficient queries and treats volume spikes as a workload observation to be correlated. It survives when the same events show unusual search filters targeting sensitive attributes such as admincount.

- *Disproof:* Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.
- *Evidence:* high_confidence — [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/); [thehacker.recipes](https://www.thehacker.recipes/ad/recon/ldap)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
