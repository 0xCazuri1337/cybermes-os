---
name: ad_trust_abuse-hunting
description: Use when hunting Active Directory Trust Abuse in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Active Directory Trust Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-863 · OWASP —
> evidence: 8 items, 8 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, fp_rules, chain

A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.

**Also called:** trust abuse, trust relationship, forest trust, external trust, sid filtering, trust direction, cross forest, transitive trust


## Prerequisites (do not start without these)

- No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.
  - **Disproof:** The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.
  - Sources: <https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
- No cross-domain attack path can be evaluated from protocol telemetry alone until trust direction and trust type are read off the trust object, because two-way and one-way trusts produce the same traffic shape.
  - **Disproof:** The path under assessment stays entirely inside a single domain and never crosses a trust boundary, in which case trust direction and type cannot be the enabling condition and a different mechanism must be named.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Recon signals (where to look)

- Reconnaissance that walks trust relationships shows up as LDAP volume against trust and configuration objects, Kerberos user enumeration, and DNS zone transfer requests from hosts that are not DNS servers.
  - **Disproof:** Every cross-boundary enumeration in the window originates from a domain controller, a management host or an authorised monitoring platform that is documented to enumerate trusts, and no non-administrative host touched trust, foreign principal or delegation attributes, in which case this is routine inventory rather than trust reconnaissance.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Techniques (what to change)

- An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.
  - **Disproof:** The trust between the two domains is one-way with the child unable to authenticate outward, or SID filtering and the trust configuration prevent a child-domain principal from being accepted by the parent, in which case the cross-trust Kerberoast path does not exist.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- Changing a domain's trust configuration to include an adversary-controlled domain lets an identity from that domain forge access tokens that victim-domain resources will accept.
  - **Disproof:** If the domain's trust objects cannot be modified by any principal outside Domain Admins and no trust exists with an uncontrolled or unexpected partner, then no cross-forest token forgery is available to a lower-privilege actor.
  - Sources: <https://attack.mitre.org/techniques/T1484/> · <https://www.rfc-editor.org/rfc/rfc4120.html>

## Validation bar (how to prove it)

- Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic.
  - **Disproof:** The requesting host is a domain controller and the requesting principal is an account legitimately entrusted with replication rights for that domain, with a matching service or backup schedule behind the traffic, in which case the requests are ordinary replication and the abuse hypothesis fails.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## False-positive rules (when to reject it)

- A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.
  - **Disproof:** Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Variants

- Unconstrained delegation configured on a machine or service principal in a trusted forest lets an attacker who compromises that host capture a TGT for any user who authenticates to it, including across the trust.
  - **Disproof:** No principal reachable across the trust is configured for unconstrained delegation, or the cross-forest path requires SID filtering to be disabled and it is enabled in this environment, in which case a captured TGT from the trusted forest will not be accepted for the victim resource.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

---
Full class document: `skills/Network + AD/ad_trust_abuse/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_trust_abuse`
