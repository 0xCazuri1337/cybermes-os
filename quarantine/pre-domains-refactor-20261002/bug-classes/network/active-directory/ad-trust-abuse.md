# Active Directory Trust Abuse

## Definition

A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.

- **CWE:** CWE-863
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["trust abuse", "trust relationship", "forest trust", "external trust", "sid filtering", "trust direction", "cross forest", "transitive trust"]

Canonical home for `ad_trust_abuse`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.**

Prerequisite: before scoring any privilege-escalation or lateral-movement claim that crosses a domain boundary, establish two facts for every trust object. First, direction and transitivity: one-way trusts allow users from one domain to access resources in another domain but not vice versa, while two-way trusts enable two-way access and transitive trusts extend reach to domains that trust the first domain, so an edge labelled only 'trust' in a graph is ambiguous in exactly the way that matters. Second, SID filtering: SID history is a feature in Active Directory that allows administrators to maintain the SID of a user or group account when it's moved from one domain to another within a domain forest, and SID filtering is the control that stops a foreign SIDHistory value from being honoured on an access attempt. A trust with SID filtering disabled inherits an exposure that no amount of graph analysis of the trusting domain will reveal. This matters because AD defaults are permissive: Active Directory is susceptible to compromise due to its permissive default settings, its complex relationships, and permissions. A trust-scoped finding is therefore not the product of a clever graph query but of a recorded, per-trust configuration pair. Escalate a trust-abuse item only when the trust object's direction, transitivity, and SID filtering state are all present in the evidence.

*Disproof:* The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.

**No cross-domain attack path can be evaluated from protocol telemetry alone until trust direction and trust type are read off the trust object, because two-way and one-way trusts produce the same traffic shape.**

Kerberos traffic does not tell you whether the trust carrying it is one-way or two-way, and a legitimate service ticket request is indistinguishable from one issued by an attacker. That is the structural reason trust configuration has to come first: reachability is a property of the trust object, not of the packets. The trust types differ in exactly the ways that matter for a hunt. A parent-child trust inside a forest is established automatically and is two-way - the parent inherently trusts the child and vice versa. A tree-root trust links the roots of two trees in one forest and is also automatic. An external trust links domains in two different forests. A shortcut or cross-link trust joins two child domains in the same forest to shorten authentication hops, and can be either one-way or two-way transitive. A forest trust links the roots of two forests. A realm trust links a Windows domain to a non-Windows Kerberos realm. Operationally: for every trust in the environment record direction, type, transitivity and whether SID filtering is in force, then map reachability against that. Getting this wrong inverts the finding - a one-way trust reported as bidirectional manufactures an attack path that does not exist.

*Disproof:* The path under assessment stays entirely inside a single domain and never crosses a trust boundary, in which case trust direction and type cannot be the enabling condition and a different mechanism must be named.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Reconnaissance that walks trust relationships shows up as LDAP volume against trust and configuration objects, Kerberos user enumeration, and DNS zone transfer requests from hosts that are not DNS servers.**

Mapping a trust graph is reconnaissance, and reconnaissance is what a detection platform has to name explicitly because nothing about it is protocol-illegal. The observable set is a cross-protocol pattern rather than a single event: large-volume Active Directory object collection via LDAP, a bulk enumeration of Kerberos principals, LDAP reads aimed at delegation and administrative credential attributes, and DNS zone data replication requests arriving from sources other than DNS servers. A trust-aware adversary has to touch the trust objects and the foreign security principal and ACL material on both sides, so the practical rule is to treat an authentication or enumeration pattern that crosses a domain boundary it has no business crossing as the signal, not the specific protocol. Concretely: alert on LDAP sessions collecting trust and configuration-naming-context objects from a workstation; on DNS zone transfer and zone data replication requests whose source is not a DNS server; and on internal horizontal or vertical port scans that fan out across the trust edge. Exclude the domain controllers and the management hosts that legitimately enumerate this material, or the signal drowns.

*Disproof:* Every cross-boundary enumeration in the window originates from a domain controller, a management host or an authorised monitoring platform that is documented to enumerate trusts, and no non-administrative host touched trust, foreign principal or delegation attributes, in which case this is routine inventory rather than trust reconnaissance.

## Exploitation

**An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.**

The parent-child trust is created automatically whenever a child domain joins a forest, and it is two-way, which makes it the shortest escalation path inside a forest. The move is Kerberoasting across the trust: from the compromised child, request TGS tickets for service accounts in the parent, take them offline, crack them, and authenticate as the parent service account. Once the child is fully compromised that access compromises the parent the actor was already positioned in. The same logic extends outward - trust relationships with other forests mean compromising a partner forest may hand over access into the current one. Operationally: on the child domain's KDC, alert on a single source IP and client account receiving successful TGS responses for an unusual number of distinct SPNs in a short window, and specifically on requests for SPNs that live in the parent domain rather than the child's. The discriminating detail is that the requests themselves are protocol-legal, so signature matching on TGS-REQ never separates them; you need the request-source anomaly and the SPN surge. A user in the child asking for a parent-domain service ticket is not normal application traffic.

*Disproof:* The trust between the two domains is one-way with the child unable to authenticate outward, or SID filtering and the trust configuration prevent a child-domain principal from being accepted by the parent, in which case the cross-trust Kerberoast path does not exist.

**Changing a domain's trust configuration to include an adversary-controlled domain lets an identity from that domain forge access tokens that victim-domain resources will accept.**

A trust is a statement that identities in one forest may authenticate to resources in another. That makes the trust configuration itself an authorization control, and modifying it is a privilege action rather than a configuration cleanup: adding an adversary-controlled domain produces a trusted path whose tokens the victim forest will accept. The detection problem is that the change is made through ordinary administrative APIs, so it looks like administration unless you are watching the specific object. The specific objects matter: domain trust configuration, federation settings and Group Policy Objects are the three that ATT&CK groups as domain/tenant policy modification, and all three are directory-object changes rather than file writes. Watch for trust and GPO objects being modified — not for who modified them, since a legitimate administrator is the expected actor in both the benign and the malicious case.

*Disproof:* If the domain's trust objects cannot be modified by any principal outside Domain Admins and no trust exists with an uncontrolled or unexpected partner, then no cross-forest token forgery is available to a lower-privilege actor.

## Variations

**Unconstrained delegation configured on a machine or service principal in a trusted forest lets an attacker who compromises that host capture a TGT for any user who authenticates to it, including across the trust.**

Unconstrained delegation is listed among the intra-forest attacks that make a forest a soft boundary and it is explicitly enumerated as a cross-forest variant. The mechanism is Kerberos, not the trust object: a host or service principal trusted for unconstrained delegation receives a forwardable TGT from any client that authenticates to it, and it can hand that TGT to an attacker who has compromised it. Across a forest trust the captured ticket is issued by the trusted forest's KDC and is therefore useful against resources in that forest, not just the local domain. Operational detection: watch Kerberos TGS requests carrying a non-standard combination of ticket flags - forwardable, proxiable and renewable together on a service that should not need them - and correlate with a delegation-enabled principal being contacted from a host outside its normal client set. Because the abuse is a legitimate protocol exchange, alert on the flag combination and the source-destination pair rather than on the request itself. Note the prerequisite: unconstrained delegation must be enabled on something reachable, so a first pass should enumerate which principals carry it.

*Disproof:* No principal reachable across the trust is configured for unconstrained delegation, or the cross-forest path requires SID filtering to be disabled and it is enabled in this environment, in which case a captured TGT from the trusted forest will not be accepted for the victim resource.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.**

Trust objects outlive the reason they were created. Migrations complete and the old external trust stays; a partner organisation is acquired and the PAM trust stays; a cross-link trust exists only to shorten authentication hops and is barely used. Reporting the existence of such a trust as abuse produces a finding that cannot be actioned, because the remediation is 'delete the trust' and nobody will agree to that without knowing it is unused. The discriminator is traffic, not configuration: map the trust, then check whether authentication requests actually traverse it. No cross-boundary Kerberos or LDAP sessions in the retention window means the relationship is dormant. This does not make it harmless - a configured trust is available to anyone who later compromises the partner domain, and dormant trust objects are exactly what gets forgotten during incident response - so the correct output is a hygiene finding on an unused trust, not an abuse finding. Distinguish that clearly from the case where the trust is being actively used to escalate, which is where the real risk lives: the common routes to privileged control are credential-based, such as DCSync or Kerberoasting of privileged service accounts, not the mere presence of the trust object.

*Disproof:* Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.

## Validation

**Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic.**

DCSync works because a domain controller can replicate the directory, so a principal holding replication rights can request the directory contents itself and walk away with credential material instead of a single hash. The validation that separates the two cases is not the request itself - replication traffic looks like replication traffic - but the identity of the caller and the source host. Concrete test: for the source IP in the alert, establish whether it is a domain controller; if it is not, no legitimate reason exists for it to be issuing replication requests. Then check the principal's replication rights. Observed attacker behaviour includes requesting Kerberos tickets with an unusual flag combination and then attempting to replicate the Domain-Password object from the directory to impersonate the domain controller, after obtaining an account with sufficient privileges. In a documented intrusion chain a machine account's NT hash was taken with a shadow credentials attack and then used to run DCSync, retrieving NTLM hashes for all users in the domain because a domain controller can perform the replication DCSync requires. So the discriminator is: non-DC source host, or a principal with replication rights that is not a domain controller account or a dedicated replication service identity, means the request is credential abuse, not replication.

*Disproof:* The requesting host is a domain controller and the requesting principal is an account legitimately entrusted with replication rights for that domain, with a matching service or backup schedule behind the traffic, in which case the requests are ordinary replication and the abuse hypothesis fails.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
  - <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1484/>
- **helpnetsecurity.com** (blog)
  - <https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/>
- **proofpoint.com** (blog)
  - <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4120.html>
- **securelist.com** (research)
  - <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
  - <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
