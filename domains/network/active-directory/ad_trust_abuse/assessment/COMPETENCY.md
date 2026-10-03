# Methodology — Active Directory Trust Abuse

> Derived from 9 verified items. Regenerate with `python -m wks.methodgen --class ad_trust_abuse --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.

**References.** CWE-863

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**No cross-domain attack path can be evaluated from protocol telemetry alone until trust direction and trust type are read off the trust object, because two-way and one-way trusts produce the same traffic shape.**

Kerberos traffic does not tell you whether the trust carrying it is one-way or two-way, and a legitimate service ticket request is indistinguishable from one issued by an attacker. That is the structural reason trust configuration has to come first: reachability is a property of the trust object, not of the packets. The trust types differ in exactly the ways that matter for a hunt. A parent-child trust inside a forest is established automatically and is two-way - the parent inherently trusts the child and vice versa. A tree-root trust links the roots of two trees in one forest and is also automatic. An external trust links domains in two different forests. A shortcut or cross-link trust joins two child domains in the same forest to shorten authentication hops, and can be either one-way or two-way transitive. A forest trust links the roots of two forests. A realm trust links a Windows domain to a non-Windows Kerberos realm. Operationally: for every trust in the environment record direction, type, transitivity and whether SID filtering is in force, then map reachability against that. Getting this wrong inverts the finding - a one-way trust reported as bidirectional manufactures an attack path that does not exist.

- *Disproof:* The path under assessment stays entirely inside a single domain and never crosses a trust boundary, in which case trust direction and type cannot be the enabling condition and a different mechanism must be named.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-trust-attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

**No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.**

Prerequisite: before scoring any privilege-escalation or lateral-movement claim that crosses a domain boundary, establish two facts for every trust object. First, direction and transitivity: one-way trusts allow users from one domain to access resources in another domain but not vice versa, while two-way trusts enable two-way access and transitive trusts extend reach to domains that trust the first domain, so an edge labelled only 'trust' in a graph is ambiguous in exactly the way that matters. Second, SID filtering: SID history is a feature in Active Directory that allows administrators to maintain the SID of a user or group account when it's moved from one domain to another within a domain forest, and SID filtering is the control that stops a foreign SIDHistory value from being honoured on an access attempt. A trust with SID filtering disabled inherits an exposure that no amount of graph analysis of the trusting domain will reveal. This matters because AD defaults are permissive: Active Directory is susceptible to compromise due to its permissive default settings, its complex relationships, and permissions. A trust-scoped finding is therefore not the product of a clever graph query but of a recorded, per-trust configuration pair. Escalate a trust-abuse item only when the trust object's direction, transitivity, and SID filtering state are all present in the evidence.

- *Disproof:* The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.
- *Evidence:* high_confidence — [helpnetsecurity.com](https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/); [proofpoint.com](https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Reconnaissance that walks trust relationships shows up as LDAP volume against trust and configuration objects, Kerberos user enumeration, and DNS zone transfer requests from hosts that are not DNS servers.**

Mapping a trust graph is reconnaissance, and reconnaissance is what a detection platform has to name explicitly because nothing about it is protocol-illegal. The observable set is a cross-protocol pattern rather than a single event: large-volume Active Directory object collection via LDAP, a bulk enumeration of Kerberos principals, LDAP reads aimed at delegation and administrative credential attributes, and DNS zone data replication requests arriving from sources other than DNS servers. A trust-aware adversary has to touch the trust objects and the foreign security principal and ACL material on both sides, so the practical rule is to treat an authentication or enumeration pattern that crosses a domain boundary it has no business crossing as the signal, not the specific protocol. Concretely: alert on LDAP sessions collecting trust and configuration-naming-context objects from a workstation; on DNS zone transfer and zone data replication requests whose source is not a DNS server; and on internal horizontal or vertical port scans that fan out across the trust edge. Exclude the domain controllers and the management hosts that legitimately enumerate this material, or the signal drowns.

- *Disproof:* Every cross-boundary enumeration in the window originates from a domain controller, a management host or an authorised monitoring platform that is documented to enumerate trusts, and no non-administrative host touched trust, foreign principal or delegation attributes, in which case this is routine inventory rather than trust reconnaissance.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-trust-attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.**

The parent-child trust is created automatically whenever a child domain joins a forest, and it is two-way, which makes it the shortest escalation path inside a forest. The move is Kerberoasting across the trust: from the compromised child, request TGS tickets for service accounts in the parent, take them offline, crack them, and authenticate as the parent service account. Once the child is fully compromised that access compromises the parent the actor was already positioned in. The same logic extends outward - trust relationships with other forests mean compromising a partner forest may hand over access into the current one. Operationally: on the child domain's KDC, alert on a single source IP and client account receiving successful TGS responses for an unusual number of distinct SPNs in a short window, and specifically on requests for SPNs that live in the parent domain rather than the child's. The discriminating detail is that the requests themselves are protocol-legal, so signature matching on TGS-REQ never separates them; you need the request-source anomaly and the SPN surge. A user in the child asking for a parent-domain service ticket is not normal application traffic.

- *Disproof:* The trust between the two domains is one-way with the child unable to authenticate outward, or SID filtering and the trust configuration prevent a child-domain principal from being accepted by the parent, in which case the cross-trust Kerberoast path does not exist.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-trust-attacks); [securelist.com](https://securelist.com/tr/network-anomaly-detection-in-kata/120892/)

**Changing a domain's trust configuration to include an adversary-controlled domain lets an identity from that domain forge access tokens that victim-domain resources will accept.**

A trust is a statement that identities in one forest may authenticate to resources in another. That makes the trust configuration itself an authorization control, and modifying it is a privilege action rather than a configuration cleanup: adding an adversary-controlled domain produces a trusted path whose tokens the victim forest will accept. The detection problem is that the change is made through ordinary administrative APIs, so it looks like administration unless you are watching the specific object. The specific objects matter: domain trust configuration, federation settings and Group Policy Objects are the three that ATT&CK groups as domain/tenant policy modification, and all three are directory-object changes rather than file writes. Watch for trust and GPO objects being modified — not for who modified them, since a legitimate administrator is the expected actor in both the benign and the malicious case.

- *Disproof:* If the domain's trust objects cannot be modified by any principal outside Domain Admins and no trust exists with an uncontrolled or unexpected partner, then no cross-forest token forgery is available to a lower-privilege actor.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1484/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4120.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a ad_trust_abuse finding until it is distinguished from the adjacent behaviour this class also covers. "No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability." and "Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.

Adjacent behaviour that produces the same observable result: Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

- *Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Testing whether the requesting principal actually holds domain replica" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks); [attack.mitre.org](https://attack.mitre.org/techniques/T1484/)

**A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.**

Trust objects outlive the reason they were created. Migrations complete and the old external trust stays; a partner organisation is acquired and the PAM trust stays; a cross-link trust exists only to shorten authentication hops and is barely used. Reporting the existence of such a trust as abuse produces a finding that cannot be actioned, because the remediation is 'delete the trust' and nobody will agree to that without knowing it is unused. The discriminator is traffic, not configuration: map the trust, then check whether authentication requests actually traverse it. No cross-boundary Kerberos or LDAP sessions in the retention window means the relationship is dormant. This does not make it harmless - a configured trust is available to anyone who later compromises the partner domain, and dormant trust objects are exactly what gets forgotten during incident response - so the correct output is a hygiene finding on an unused trust, not an abuse finding. Distinguish that clearly from the case where the trust is being actively used to escalate, which is where the real risk lives: the common routes to privileged control are credential-based, such as DCSync or Kerberoasting of privileged service accounts, not the mere presence of the trust object.

- *Disproof:* Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-trust-attacks); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

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
