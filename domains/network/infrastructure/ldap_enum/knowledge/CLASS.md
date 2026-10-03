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

Not yet researched.

## Exploitation

**When you enable LDAP signing, both the client and server cryptographically sign their communications.**

and servers can trust the authenticity and integrity of their communications. 
 This article explains how LDAP signing and channel binding work, describes the security improvements Microsoft has introduced over time, and highlights new features in Windows Server 2025. 
 How LDAP signing works 
 LDAP signing digitally signs LDAP messages to ensure that data isn't tampered with during transmission. When you enable LDAP signing, both the client and server cryptographically sign their communications. The process rejects any unsigned or improperly signed requests, preventing unauthorized modifications to LDAP messages. 
 The signing process uses Simple Authentication and Security Layer (SASL) protocols, which include Negotiate, Kerberos, NTLM, and Digest protocols. When you enforce LDAP signing on a domain controller, it rejects SASL LDAP binds that don't request signing and rejects simple bin

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When you enable LDAP signing, both the client and server cryptographically sign their comm".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This binding ensures that even if an attacker intercepts the encrypted session, they can't".

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

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This binding ensures that even if an attacker intercepts the encrypted session, they can't".

**When you enable LDAP signing, both the client and server cryptographically sign their communications.**

and servers can trust the authenticity and integrity of their communications. 
 This article explains how LDAP signing and channel binding work, describes the security improvements Microsoft has introduced over time, and highlights new features in Windows Server 2025. 
 How LDAP signing works 
 LDAP signing digitally signs LDAP messages to ensure that data isn't tampered with during transmission. When you enable LDAP signing, both the client and server cryptographically sign their communications. The process rejects any unsigned or improperly signed requests, preventing unauthorized modifications to LDAP messages. 
 The signing process uses Simple Authentication and Security Layer (SASL) protocols, which include Negotiate, Kerberos, NTLM, and Digest protocols. When you enforce LDAP signing on a domain controller, it rejects SASL LDAP binds that don't request signing and rejects simple bin

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "When you enable LDAP signing, both the client and server cryptographically sign their comm".

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
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4511.html>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2025/04/08/the-renaissance-of-ntlm-relay-attacks-everything-you-need-to-know/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/recon/ldap>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
