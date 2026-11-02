# Methodology — LDAP Enumeration

> Derived from 5 verified items. Regenerate with `python -m wks.methodgen --class ldap_enum --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** LDAP returns directory structure to a client, so filter syntax that reaches the query shape turns enumeration into extraction.

**References.** CWE-200

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections, which removes the read primitive before any enumeration question arises.**

The primitive gives you: a directory read, and the precondition is that the bind completes at all. Microsoft documents that enforcing LDAP signing on a domain controller rejects SASL binds that don't request signing and rejects simple binds over nonencrypted connections, and KrbRelayUp's guidance is to set the LDAP server signing requirement to Require signing and enable Extended Protection for Authentication. Where signing is not enforced, the same page notes that intruders can intercept authentication attempts, modify packets in transit, or hijack encrypted sessions, so the unauthenticated bind is also the tap point for the relay link. Observation that proves this segment holds: a simple bind with no SASL and no TLS completes and returns directory content, while the same bind against an enforcing domain controller returns an error rather than data. The next link consumes whatever the read returns, typically an SPN or delegation inventory.

- *Disproof:* If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [nccgroup.com](https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-fortifying-active-directory-against-ldap-injection-threats/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.**

The LDAP search operation is defined by the filter the client sends and the attributes it asks for; when the filter evaluates true for an entry, that entry's attributes come back subject to applicable access control. So the enumeration surface is the product of three server-side settings — base scope, subtree depth, and which attributes may be returned anonymously — and each is independently misconfigurable. A permissive filter such as (objectClass=*) returns every entry in scope, which converts one query into a directory dump and, in a directory where computer accounts live, into a host inventory. The validation is differential: request the same subtree with a narrow filter and with (objectClass=*), and if the broad form returns entries the narrow one cannot, the broad filter is authorized when it should not be. This is the same structural property that makes filter injection dangerous, viewed from the read side rather than the write side.

- *Disproof:* If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

**LDAP enumeration with anonymous bind exposes the directory tree, revealing group membership and the service accounts worth targeting.**

In practice on HTB this shows up as: | `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" \| grep -m 1 -B 10 pwdHistoryLength` | Uses `ldapsearch` to enumerate the password policy in a  target Windows domain from a Linux-based host. |
| `net accounts`                                               | Used to enumerate the password policy in a Windows domain from a Windows-based host. |
| `Import-Module .\PowerView.ps1`                              | Uses the Import-Module cmd-let to import the `PowerView.ps1` tool from a Windows-based host. |
| `Get-DomainPolicy`                                           | Used to enumerate the password policy in a target Windows domain from a Windows-based host. |

Write-up provenance: ajcriado/htb-writeups :: Academy/CPTS/Content Summary/13. Active Directory Enumeration & Attacks.md (6753 words, classified network).

- *Disproof:* Refuted when anonymous bind is disabled and no credential allows a bind, in which case the directory reveals nothing without prior authentication.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1087/002/); [raw.githubusercontent.com](https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4511.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

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

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
