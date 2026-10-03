# Active Directory Trust Abuse

> surface: `ad` · CWE: CWE-863 · OWASP: —
> maturity: **mature** — 14 items, 14 supported, 2 FP rules, 1 chains

A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.

**Aliases:** trust abuse, trust relationship, forest trust, external trust, sid filtering, trust direction, cross forest, transitive trust

## Prerequisite

- **No cross-domain attack path can be evaluated from protocol telemetry alone until trust direction and trust type are read off the trust object, because two-way and one-way trusts produce the same traffic shape.**  
  `high_confidence` · score 0.8715 · disproved by: The path under assessment stays entirely inside a single domain and never crosses a trust boundary, in which case trust direction and type cannot be the enabling condition and a different mechanism must be named.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.**  
  `high_confidence` · score 0.754 · disproved by: The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.
  sources: <https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>

## Signal

- **Reconnaissance that walks trust relationships shows up as LDAP volume against trust and configuration objects, Kerberos user enumeration, and DNS zone transfer requests from hosts that are not DNS servers.**  
  `high_confidence` · score 0.8355 · disproved by: Every cross-boundary enumeration in the window originates from a domain controller, a management host or an authorised monitoring platform that is documented to enumerate trusts, and no non-administrative host touched trust, foreign principal or delegation attributes, in which case this is routine inventory rather than trust reconnaissance.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.**  
  `high_confidence` · score 0.899 · disproved by: The trust between the two domains is one-way with the child unable to authenticate outward, or SID filtering and the trust configuration prevent a child-domain principal from being accepted by the parent, in which case the cross-trust Kerberoast path does not exist.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **Changing a domain's trust configuration to include an adversary-controlled domain lets an identity from that domain forge access tokens that victim-domain resources will accept.**  
  `high_confidence` · score 0.798 · disproved by: If the domain's trust objects cannot be modified by any principal outside Domain Admins and no trust exists with an uncontrolled or unexpected partner, then no cross-forest token forgery is available to a lower-privilege actor.
  sources: <https://attack.mitre.org/techniques/T1484/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
- **While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While these trust relationships enhance collaboration and resource access, they also intro".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover enumerating and mapping trust relationships, exploitation of intra-forest tr".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **Hence, as penetration testers we must have a deep understanding of the ins and outs of AD, its complexities, intricacies, and the many ways it can be misconfigured or native features can be abused.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Hence, as penetration testers we must have a deep understanding of the ins and outs of AD,".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **We may also identify trust relationships with other forests and compromising a partner forest may grant us access that we need to compromise our current forest through any number of attacks.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We may also identify trust relationships with other forests and compromising a partner for".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- **As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.**  
  `high_confidence` · score 0.748 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>

## Validation

- **Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic.**  
  `high_confidence` · score 0.8715 · disproved by: The requesting host is a domain controller and the requesting principal is an account legitimately entrusted with replication rights for that domain, with a matching service or backup schedule behind the traffic, in which case the requests are ordinary replication and the abuse hypothesis fails.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Fp Rule

- **Reject a ad_trust_abuse finding until it is distinguished from the adjacent behaviour this class also covers. "No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability." and "Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.869 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Testing whether the requesting principal actually holds domain replica" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://attack.mitre.org/techniques/T1484/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
- **A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.**  
  `high_confidence` · score 0.863 · disproved by: Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Variant

- **Unconstrained delegation configured on a machine or service principal in a trusted forest lets an attacker who compromises that host capture a TGT for any user who authenticates to it, including across the trust.**  
  `high_confidence` · score 0.8355 · disproved by: No principal reachable across the trust is configured for unconstrained delegation, or the cross-forest path requires SID filtering to be disabled and it is enabled in this environment, in which case a captured TGT from the trusted forest will not be accepted for the victim resource.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
