---
name: ldap_enum-hunting
description: Use when hunting LDAP Enumeration in a net target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# LDAP Enumeration — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `net` · CWE CWE-200 · OWASP —
> evidence: 12 items, 10 supported, 2 FP rules, 1 chains
> maturity: **mature**

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**Also called:** ldap enumeration, ldap search, directory tree walk, anonymous ldap, ldap tree


## Prerequisites (do not start without these)

- Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>

## Recon signals (where to look)

- LDAP channel binding ties the bind to its TLS tunnel; when the directory server does not enforce channel binding or signing, a relayed bind can succeed even though the original transport was encrypted.  _(merged 1 duplicate row(s))_
  - **Disproof:** The relay finding fails when the directory server enforces channel binding or LDAP signing and rejects the relayed bind, or when the bind never traversed the attacker's relay and the original TLS session was used end to end.
  - Sources: <https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>

## Techniques (what to change)

- An LDAP SearchRequest whose baseObject is the zero-length DN and whose scope is base is answered by the rootDSE rather than by any naming context, so naming contexts, the server's own DNS host name and functional-level data arrive from a read whose access decision is separate from the anonymous-bind policy, which means the domain suffix can be established on a target before any credential exists.  _(merged 1 duplicate row(s))_
  - **Disproof:** Wrong when the empty-base base-scope request is refused for the same caller the subtree search accepts - unwillingToPerform, noSuchObject, insufficientAccessRights, or a success whose entry carries no namingContexts attribute - because then the DSE is gated by the same policy as the rest of the directory and no suffix can be learned from the protocol at all. Also wrong to carry the result further than it reaches: the DSE sits outside every naming context, so a DSE that answers proves nothing about whether any entry below it is readable, and a host that answers the DSE while returning an empty subtree is behaving as documented rather than contradicting itself. The two responses have to be reported separately, and an answered DSE on one port says nothing about the other port until the request is repeated there.
  - Sources: <https://www.rfc-editor.org/rfc/rfc4512.html> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/96f7b086-1ca3-4764-9a08-33f8f7a543db> · <https://www.thehacker.recipes/ad/recon/ldap>
- An extensibleMatch filter component carries a matching-rule OID in place of a comparison operator, so the client is asking the server to evaluate that rule over stored values, and on AD DS the rule 1.2.840.113556.1.4.1941 walks the ancestry chain to the root, which means one subtree SearchRequest over a groups container returns the transitive membership set that a per-level member filter stops short of.  _(merged 1 duplicate row(s))_
  - **Disproof:** Wrong when the DC rejects or ignores the extended filter - unwillingToPerform, inappropriateMatching, undefinedAttributeType, or a success carrying zero entries against a container known to hold members - because then the transitive set is only reachable one level at a time and this single-query coverage does not exist on that server. Also wrong to read the returned set as an authorization answer: the rule is limited to filters that apply to the DN and it reports ancestry rather than permissions, so a principal in the result is not thereby readable, writable or reachable for anything else. And wrong whenever the recursive expansion was never run, because an empty result from a chain-walk filter has the same shape as an empty result from a group with no members, and only the count comparison distinguishes the unimplemented rule from an uninteresting group.
  - Sources: <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/4e638665-f466-4597-93c4-12f2ebfabab5> · <https://learn.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax>
- LDAP enumeration with anonymous bind exposes the directory tree, revealing group membership and the service accounts worth targeting.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when anonymous bind is disabled and no credential allows a bind, in which case the directory reveals nothing without prior authentication.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.
  - Sources: <https://attack.mitre.org/techniques/T1087/002/> · <https://www.rfc-editor.org/rfc/rfc4511.html>
- This binding ensures that even if an attacker intercepts the encrypted session, they can't hijack or downgrade the connection.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“This binding ensures that even if an attacker intercepts the encrypted session, ”) does not occur under a test that isolates that control.
  - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- When you enable LDAP signing, both the client and server cryptographically sign their communications.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“When you enable LDAP signing, both the client and server cryptographically sign ”) does not occur under a test that isolates that control.
  - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>

## Tests

- An anonymous LDAP enumeration finding requires both a successful anonymous bind and a SearchRequest whose filter returns directory entries; a successful bind alone returns no entries and is not enumeration.  _(merged 1 duplicate row(s))_
  - **Disproof:** The enumeration finding fails when the client only completed a bind, when the search returned no entries or only rootDSE metadata, or when the server rejected the search with a size-limit or access-control error.
  - Sources: <https://www.rfc-editor.org/rfc/rfc4511.html> · <https://man7.org/linux/man-pages/man1/ldapsearch.1.html>
- The paged-results control lets the server choose how many entries one search sequence returns and echoes its own estimate of the whole result set back in the searchResultDone control, so an LDAP subtree walk that reads neither the echoed size nor the cookie stops on a server-chosen cap while looking exactly like a complete walk, and only re-issuing the identical baseObject and filter at a second page size tells the two apart.  _(merged 1 duplicate row(s))_
  - **Disproof:** Wrong when the two runs agree on entry count AND the searchResultDone on the larger page size carries an empty cookie: no server-side cap applied to that baseObject and filter, the enumeration is complete, and a page size below the cap changes nothing except latency and round trips. Equally wrong to read the echoed size as exact rather than as an estimate, since a server that cannot compute one may send zero and a client that trusts a zero estimate will call a full directory empty. And an unpaged request cut short by sizeLimitExceeded is stopped by a limit the request itself or the site's policy set, which is a different test from the paging cap and has to be recorded as a separate result rather than folded into the same evidence.
  - Sources: <https://www.rfc-editor.org/rfc/rfc2696.html> · <https://man7.org/linux/man-pages/man1/ldapsearch.1.html>

## False-positive rules (when to reject it)

- A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/> · <https://www.thehacker.recipes/ad/recon/ldap>
- A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
  - Sources: <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/> · <https://www.thehacker.recipes/ad/recon/ldap>


## Hunt procedure

1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
4. Record raw request and response pairs verbatim, including headers, before you interpret anything.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/infrastructure/ldap_enum/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ldap_enum`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
