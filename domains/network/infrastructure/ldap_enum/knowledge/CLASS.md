# LDAP Enumeration

## Definition

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["ldap enumeration", "ldap search", "directory tree walk", "anonymous ldap", "ldap tree"]

Canonical home for `ldap_enum`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.**

The primitive gives you: a directory read, and the precondition is that the bind completes at all. Microsoft documents that enforcing LDAP signing on a domain controller rejects SASL binds that don't request signing and rejects simple binds over nonencrypted connections, and KrbRelayUp's guidance is to set the LDAP server signing requirement to Require signing and enable Extended Protection for Authentication. Where signing is not enforced, the same page notes that intruders can intercept authentication attempts, modify packets in transit, or hijack encrypted sessions, so the unauthenticated bind is also the tap point for the relay link. Observation that proves this segment holds: a simple bind with no SASL and no TLS completes and returns directory content, while the same bind against an enforcing domain controller returns an error rather than data. The next link consumes whatever the read returns, typically an SPN or delegation inventory.

*Disproof:* If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.

## Attack Surface

Surface: **net**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**LDAP channel binding ties the bind to its TLS tunnel; when the directory server does not enforce channel binding or signing, a relayed bind can succeed even though the original transport was encrypted.**

TLS on the client side does not by itself stop a relay. Channel binding makes the server verify that the bind is arriving over the same TLS tunnel the client authenticated to, and LDAP signing protects the bind traffic's integrity. A successful bind over TLS without either control is therefore a policy signal, not proof that relay is impossible. The test should record the directory server's channel-binding and signing policy, then attempt a bind through a controlled relay. Event 3074/3075 or an equivalent channel-binding failure is a negative result; a successful bind through the relay is the positive observation.

*Disproof:* The relay finding fails when the directory server enforces channel binding or LDAP signing and rejects the relayed bind, or when the bind never traversed the attacker's relay and the original TLS session was used end to end.

## Exploitation

**When you enable LDAP signing, both the client and server cryptographically sign their communications.**

and servers can trust the authenticity and integrity of their communications. 
 This article explains how LDAP signing and channel binding work, describes the security improvements Microsoft has introduced over time, and highlights new features in Windows Server 2025. 
 How LDAP signing works 
 LDAP signing digitally signs LDAP messages to ensure that data isn't tampered with during transmission. When you enable LDAP signing, both the client and server cryptographically sign their communications. The process rejects any unsigned or improperly signed requests, preventing unauthorized modifications to LDAP messages. 
 The signing process uses Simple Authentication and Security Layer (SASL) protocols, which include Negotiate, Kerberos, NTLM, and Digest protocols. When you enforce LDAP signing on a domain controller, it rejects SASL LDAP binds that don't request signing and rejects simple bin

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When you enable LDAP signing, both the client and server cryptographically sign ”) does not occur under a test that isolates that control.

**Man-in-the-middle attacks : An attacker captures packets between client and server, modifies them, and forwards altered requests to the domain controller.**

e Negotiate, Kerberos, NTLM, and Digest protocols. When you enforce LDAP signing on a domain controller, it rejects SASL LDAP binds that don't request signing and rejects simple binds performed over nonencrypted connections. 
 Unsigned LDAP traffic is vulnerable to: 
 
 Replay attacks : An intruder intercepts authentication attempts and tickets, then reuses them to impersonate legitimate users. 
 Man-in-the-middle attacks : An attacker captures packets between client and server, modifies them, and forwards altered requests to the domain controller. 
 
 By default, LDAP uses port 389. LDAP over SSL/TLS (LDAPS) uses port 636 and establishes encryption immediately upon connection. 
 How LDAP channel binding works 
 LDAP channel binding uses Channel Binding Tokens (CBT) to cryptographically bind application-layer security (such as an SSL/TLS session) with the underlying network connection. This binding ensures that even if an attacker intercept

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Man-in-the-middle attacks : An attacker captures packets between client and server, modifi".

**This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**

and forwards altered requests to the domain controller. 
 
 By default, LDAP uses port 389. LDAP over SSL/TLS (LDAPS) uses port 636 and establishes encryption immediately upon connection. 
 How LDAP channel binding works 
 LDAP channel binding uses Channel Binding Tokens (CBT) to cryptographically bind application-layer security (such as an SSL/TLS session) with the underlying network connection. This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection. 
 Channel binding is important when you use NTLM or Simple Bind authentication over SSL/TLS. Without CBT enforcement, SSL/TLS encryption alone doesn't prevent all man-in-the-middle scenarios. An attacker positioned between client and server could potentially intercept the connection. By binding the security context directly to the SSL/TLS session, CBT ensures the session remains tamper-proof thro

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This binding ensures that even if an attacker intercepts the encrypted session, ”) does not occur under a test that isolates that control.

**Man-in-the-middle attacks : An attacker captures packets between client and server, modifies them, and forwards altered requests to the domain controller.**

e Negotiate, Kerberos, NTLM, and Digest protocols. When you enforce LDAP signing on a domain controller, it rejects SASL LDAP binds that don't request signing and rejects simple binds performed over nonencrypted connections. 
 Unsigned LDAP traffic is vulnerable to: 
 
 Replay attacks : An intruder intercepts authentication attempts and tickets, then reuses them to impersonate legitimate users. 
 Man-in-the-middle attacks : An attacker captures packets between client and server, modifies them, and forwards altered requests to the domain controller. 
 
 By default, LDAP uses port 389. LDAP over SSL/TLS (LDAPS) uses port 636 and establishes encryption immediately upon connection. 
 How LDAP channel binding works 
 LDAP channel binding uses Channel Binding Tokens (CBT) to cryptographically bind application-layer security (such as an SSL/TLS session) with the underlying network connection. This binding ensures that even if an attacker intercept

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Man-in-the-middle attacks : An attacker captures packets between client and server, modifi".

**This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.**

and forwards altered requests to the domain controller. 
 
 By default, LDAP uses port 389. LDAP over SSL/TLS (LDAPS) uses port 636 and establishes encryption immediately upon connection. 
 How LDAP channel binding works 
 LDAP channel binding uses Channel Binding Tokens (CBT) to cryptographically bind application-layer security (such as an SSL/TLS session) with the underlying network connection. This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection. 
 Channel binding is important when you use NTLM or Simple Bind authentication over SSL/TLS. Without CBT enforcement, SSL/TLS encryption alone doesn't prevent all man-in-the-middle scenarios. An attacker positioned between client and server could potentially intercept the connection. By binding the security context directly to the SSL/TLS session, CBT ensures the session remains tamper-proof thro

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This binding ensures that even if an attacker intercepts the encrypted session, ”) does not occur under a test that isolates that control.

**When you enable LDAP signing, both the client and server cryptographically sign their communications.**

and servers can trust the authenticity and integrity of their communications. 
 This article explains how LDAP signing and channel binding work, describes the security improvements Microsoft has introduced over time, and highlights new features in Windows Server 2025. 
 How LDAP signing works 
 LDAP signing digitally signs LDAP messages to ensure that data isn't tampered with during transmission. When you enable LDAP signing, both the client and server cryptographically sign their communications. The process rejects any unsigned or improperly signed requests, preventing unauthorized modifications to LDAP messages. 
 The signing process uses Simple Authentication and Security Layer (SASL) protocols, which include Negotiate, Kerberos, NTLM, and Digest protocols. When you enforce LDAP signing on a domain controller, it rejects SASL LDAP binds that don't request signing and rejects simple bin

*Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When you enable LDAP signing, both the client and server cryptographically sign ”) does not occur under a test that isolates that control.

**Additional settings allow restricting or auditing outgoing or incoming NTLM authentication or requiring session security settings, but we won’t elaborate on those.**

oon. 
 Looking at the table above, we can make a few observations: 
 
 As a client, a Windows host can have either NTLMv1 or NTLMv2 enabled but not both. 
 As a server, a Windows host will likely enable both NTLMv1 and NTLMv2. 
 If a Windows host enables NTLMv1 as a client, it must also enable it as a server. 
 A Windows host doesn’t have to enable NTLMv1 as a client to enable it as a server. 
 
 Additional settings allow restricting or auditing outgoing or incoming NTLM authentication or requiring session security settings, but we won’t elaborate on those. 
 Password Cracking is a Problem 
 There are different tools for capturing NTLM responses for cracking. Responder is the most well-known and widely used tool, but Inveigh and Farmer deserve an honorable mention, too. 
 An attacker can potentially crack a captured NTLM exchange, whether it’s NTLMv1 or NTLMv2, to recover the password if it is not sufficiently strong . In the case of NTLMv1, the NT

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Additional settings allow restricting or auditing outgoing or incoming NTLM authentication".

**An extensibleMatch filter component carries a matching-rule OID in place of a comparison operator, so the client is asking the server to evaluate that rule over stored values, and on AD DS the rule 1.2.840.113556.1.4.1941 walks the ancestry chain to the root, which means one subtree SearchRequest over a groups container returns the transitive membership set that a per-level member filter stops short of.**

Put a DN in the matchValue of an extensibleMatch filter component - member with rule OID 1.2.840.113556.1.4.1941 against a user DN, baseObject set to the groups container, scope subtree - and the traversal happens on the server. The differential that proves the mechanism is a count, not a status code: enumerate the container with the extended rule, then enumerate it again by reading each returned group's direct members and recursing, and diff the two principal sets. Any principal reachable only through an intermediate nested group is in the first set and absent from a single-level member filter, and that gap is exactly what a client-side loop with a fixed recursion depth gets wrong. Record the rule OID you actually sent, because a server that does not implement it answers with a result code or an empty set rather than an error that names the rule, and an empty set from an unimplemented rule is indistinguishable from an empty group unless the OID is in the notes. Record the scope as well: the rule is not restricted to a base-scope search, and a subtree chase across a high fan-out container is the expensive shape the server logs as an inefficient search. The returned principal set and the per-level expansion are the two artefacts to keep.

*Disproof:* Wrong when the DC rejects or ignores the extended filter - unwillingToPerform, inappropriateMatching, undefinedAttributeType, or a success carrying zero entries against a container known to hold members - because then the transitive set is only reachable one level at a time and this single-query coverage does not exist on that server. Also wrong to read the returned set as an authorization answer: the rule is limited to filters that apply to the DN and it reports ancestry rather than permissions, so a principal in the result is not thereby readable, writable or reachable for anything else. And wrong whenever the recursive expansion was never run, because an empty result from a chain-walk filter has the same shape as an empty result from a group with no members, and only the count comparison distinguishes the unimplemented rule from an uninteresting group.

**LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.**

The LDAP search operation is defined by the filter the client sends and the attributes it asks for; when the filter evaluates true for an entry, that entry's attributes come back subject to applicable access control. So the enumeration surface is the product of three server-side settings — base scope, subtree depth, and which attributes may be returned anonymously — and each is independently misconfigurable. A permissive filter such as (objectClass=*) returns every entry in scope, which converts one query into a directory dump and, in a directory where computer accounts live, into a host inventory. The validation is differential: request the same subtree with a narrow filter and with (objectClass=*), and if the broad form returns entries the narrow one cannot, the broad filter is authorized when it should not be. This is the same structural property that makes filter injection dangerous, viewed from the read side rather than the write side.

*Disproof:* If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.

**LDAP enumeration with anonymous bind exposes the directory tree, revealing group membership and the service accounts worth targeting.**

In practice on HTB this shows up as: | `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Uses `ldapsearch` to enumerate the password policy in a  target Windows domain from a Linux-based host. |
| `net accounts`                                               | Used to enumerate the password policy in a Windows domain from a Windows-based host. |
| `Import-Module .\PowerView.ps1`                              | Uses the Import-Module cmd-let to import the `PowerView.ps1` tool from a Windows-based host. |
| `Get-DomainPolicy`                                           | Used to enumerate the password policy in a target Windows domain from a Windows-based host. |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/13. Active Directory Enumeration & Attacks.md (6753 words, classified network).

*Disproof:* Refuted when anonymous bind is disabled and no credential allows a bind, in which case the directory reveals nothing without prior authentication.

**An LDAP SearchRequest whose baseObject is the zero-length DN and whose scope is base is answered by the rootDSE rather than by any naming context, so naming contexts, the server's own DNS host name and functional-level data arrive from a read whose access decision is separate from the anonymous-bind policy, which means the domain suffix can be established on a target before any credential exists.**

Probe the DSE before probing the tree. Send one SearchRequest with an empty (zero-length) baseObject, scope base, filter (objectClass=*) and the attribute list namingContexts (defaultNamingContext on AD DS), dnsHostName, forestFunctionalLevel, supportedLDAPVersion - first with no credentials at all against tcp/389, then the identical request against tcp/636, and record both responses verbatim. The rootDSE is not part of any naming context, so this request cannot be answered out of an object's subtree and its outcome is independent of whether a subtree search would return entries. Then re-send the same search with scope sub under the namingContext the DSE just handed you and diff the two responses: a base-scope request that returns a full DN while the subtree request comes back noSuchObject or insufficientAccessRights is the differential that says the DSE read and the bind policy are different controls, and a target that refuses the DSE read needs an externally supplied base DN instead. Repeat both requests once with supplied credentials and keep that as the baseline for what a bind identity changes, and record whether the DSE answered before the bind at all, because that ordering is the whole signal. Keep the raw searchRequest and searchResultEntry bytes: the naming context is what every later subtree filter is built from, so a wrong one makes the rest of the enumeration silently empty.

*Disproof:* Wrong when the empty-base base-scope request is refused for the same caller the subtree search accepts - unwillingToPerform, noSuchObject, insufficientAccessRights, or a success whose entry carries no namingContexts attribute - because then the DSE is gated by the same policy as the rest of the directory and no suffix can be learned from the protocol at all. Also wrong to carry the result further than it reaches: the DSE sits outside every naming context, so a DSE that answers proves nothing about whether any entry below it is readable, and a host that answers the DSE while returning an empty subtree is behaving as documented rather than contradicting itself. The two responses have to be reported separately, and an answered DSE on one port says nothing about the other port until the request is repeated there.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ldap_enum.auto.01` — ldap_enum: observe, exercise, confirm (goal: `Establish, exercise and confirm a ldap_enum condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.**

Discard when the tester bound with a valid domain account: the reconnaissance guide states anonymous binding is usually disabled and that most directory information is only retrievable through an authenticated bind, which is normal client behaviour. It survives when metadata or objects were returned over a genuinely anonymous bind.

*Disproof:* Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.

**A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.**

Discard when the report cites event 1644 volume or request counts alone: the guide describes 1644 as logging expensive or inefficient queries and treats volume spikes as a workload observation to be correlated. It survives when the same events show unusual search filters targeting sensitive attributes such as admincount.

*Disproof:* Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.

## Validation

**An anonymous LDAP enumeration finding requires both a successful anonymous bind and a SearchRequest whose filter returns directory entries; a successful bind alone returns no entries and is not enumeration.**

The bind establishes the connection's authentication state; the search returns the directory data. RFC 4511 makes the search result conditional on the filter evaluating true for an entry, and the ldapsearch manual describes the same two-step operation: connect, bind, then perform a search. A test that stops after the bind proves only that the server accepted the authentication choice. Record the base DN, scope, filter, requested attributes, and the returned entries. If the server returns an empty result, a size-limit error, or only the rootDSE metadata, the evidence supports a bind or discovery observation but not anonymous directory enumeration.

*Disproof:* The enumeration finding fails when the client only completed a bind, when the search returned no entries or only rootDSE metadata, or when the server rejected the search with a size-limit or access-control error.

**The paged-results control lets the server choose how many entries one search sequence returns and echoes its own estimate of the whole result set back in the searchResultDone control, so an LDAP subtree walk that reads neither the echoed size nor the cookie stops on a server-chosen cap while looking exactly like a complete walk, and only re-issuing the identical baseObject and filter at a second page size tells the two apart.**

Send the subtree search twice against the same baseObject with the same filter, changing only the size in the pagedResultsControl (1.2.840.113556.1.4.319) - 500 on one run, 2000 on the other - and capture the control on the searchResultDone of both. The echoed size field is the server's estimate of the total entries, the cookie is the resume token and it is empty only when the server has nothing left to return. Four outcomes separate cleanly. Equal counts with an empty cookie on both runs is the baseline for a complete enumeration. Equal counts with a non-empty cookie on the first run is a walk that stopped early and was filed as a whole tree - that pair is the finding. A count that rises when the page size rises is client-side truncation. An estimate of zero is not a small result set, because a server that cannot estimate is allowed to send zero, so a zero estimate beside a non-zero count is itself evidence of truncation rather than of an empty directory. Record the result code too: sizeLimitExceeded (4), timeLimitExceeded (3) and adminLimitExceeded (11) each cut the response short, and a client that only counts SearchResultEntry objects will read any of them as a finished enumeration. Keep the cookie values and the per-run request count next to the entry count, and treat an unpaged request that returns more entries than a paged one at the same page size as the cleanest proof that the cap was server-side.

*Disproof:* Wrong when the two runs agree on entry count AND the searchResultDone on the larger page size carries an empty cookie: no server-side cap applied to that baseObject and filter, the enumeration is complete, and a page size below the cap changes nothing except latency and round trips. Equally wrong to read the echoed size as exact rather than as an estimate, since a server that cannot compute one may send zero and a client that trusts a zero estimate will call a full directory empty. And an unpaged request cut short by sizeLimitExceeded is stopped by a limit the request itself or the site's policy set, which is a different test from the paging cap and has to be recorded as a separate result rather than folded into the same evidence.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1087/002/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5>
  - <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db>
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing>
  - <https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax>
- **man7.org** (docs)
  - <https://man7.org/linux/man-pages/man1/ldapsearch.1.html>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc2696.html>
  - <https://www.rfc-editor.org/rfc/rfc4511.html>
  - <https://www.rfc-editor.org/rfc/rfc4512.html>
- **specterops.io** (research)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/recon/ldap>
- **trustedsec.com** (research)
  - <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
