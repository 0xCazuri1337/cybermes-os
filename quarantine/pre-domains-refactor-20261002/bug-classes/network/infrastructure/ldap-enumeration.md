# LDAP Enumeration

## Definition

LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

- **CWE:** CWE-200
- **OWASP:** None
- **Surface:** net
- **Aliases:** ["ldap enumeration", "ldap search", "directory tree walk", "anonymous ldap", "ldap tree"]

Canonical home for `ldap_enum`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

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

Not yet researched.

## Exploitation

**LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.**

The LDAP search operation is defined by the filter the client sends and the attributes it asks for; when the filter evaluates true for an entry, that entry's attributes come back subject to applicable access control. So the enumeration surface is the product of three server-side settings — base scope, subtree depth, and which attributes may be returned anonymously — and each is independently misconfigurable. A permissive filter such as (objectClass=*) returns every entry in scope, which converts one query into a directory dump and, in a directory where computer accounts live, into a host inventory. The validation is differential: request the same subtree with a narrow filter and with (objectClass=*), and if the broad form returns entries the narrow one cannot, the broad filter is authorized when it should not be. This is the same structural property that makes filter injection dangerous, viewed from the read side rather than the write side.

*Disproof:* If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.

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

**A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.**

Discard when the tester bound with a valid domain account: the reconnaissance guide states anonymous binding is usually disabled and that most directory information is only retrievable through an authenticated bind, which is normal client behaviour. It survives when metadata or objects were returned over a genuinely anonymous bind.

*Disproof:* Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.

**A high volume of LDAP queries on a domain controller is a capacity signal, not enumeration evidence, unless the filters are unusual.**

Discard when the report cites event 1644 volume or request counts alone: the guide describes 1644 as logging expensive or inefficient queries and treats volume spikes as a workload observation to be correlated. It survives when the same events show unusual search filters targeting sensitive attributes such as admincount.

*Disproof:* Would be wrong for a small forest where any 1644 event is anomalous, since the baseline volume would not make the spike benign.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1087/002/>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
- **nccgroup.com** (research)
  - <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4511.html>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/recon/ldap>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
