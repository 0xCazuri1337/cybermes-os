<!-- GENERATED from db/wks.db — do not edit -->
# Active Directory Trust Abuse

> surface: `ad` · CWE: CWE-863 · OWASP: —
> maturity: **researching** — 14 items, 8 supported, 1 FP rules, 1 chains

A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.

**Aliases:** trust abuse, trust relationship, forest trust, external trust, sid filtering, trust direction, cross forest, transitive trust

## Prerequisite

- **No cross-domain attack path can be evaluated from protocol telemetry alone until trust direction and trust type are read off the trust object, because two-way and one-way trusts produce the same traffic shape.**  
  `high_confidence` · score 0.8715 · disproved by: The path under assessment stays entirely inside a single domain and never crosses a trust boundary, in which case trust direction and type cannot be the enabling condition and a different mechanism must be named.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- **No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.**  
  `high_confidence` · score 0.819 · disproved by: The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.
  sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts> · <https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/>

## Signal

- **Reconnaissance that walks trust relationships shows up as LDAP volume against trust and configuration objects, Kerberos user enumeration, and DNS zone transfer requests from hosts that are not DNS servers.**  
  `high_confidence` · score 0.8355 · disproved by: Every cross-boundary enumeration in the window originates from a domain controller, a management host or an authorised monitoring platform that is documented to enumerate trusts, and no non-administrative host touched trust, foreign principal or delegation attributes, in which case this is routine inventory rather than trust reconnaissance.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **Changing a domain's trust configuration to include an adversary-controlled domain lets an identity from that domain forge access tokens that victim-domain resources will accept.**  
  `high_confidence` · score 0.798 · disproved by: If the domain's trust objects cannot be modified by any principal outside Domain Admins and no trust exists with an uncontrolled or unexpected partner, then no cross-forest token forgery is available to a lower-privilege actor.
  sources: <https://attack.mitre.org/techniques/T1484/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
- **As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.**  
  `high_confidence` · score 0.778 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“As penetration testers, understanding the nuances of these trust relationships e”) does not occur under a test that isolates that control.
  sources: <https://attack.mitre.org/techniques/T1484/> · <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
- **While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“While these trust relationships enhance collaboration and resource access, they ”) does not occur under a test that isolates that control.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>

## Fp Rule

- **A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.**  
  `high_confidence` · score 0.863 · disproved by: Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>

## Variant

- **Unconstrained delegation configured on a machine or service principal in a trusted forest lets an attacker who compromises that host capture a TGT for any user who authenticates to it, including across the trust.**  
  `high_confidence` · score 0.8355 · disproved by: No principal reachable across the trust is configured for unconstrained delegation, or the cross-forest path requires SID filtering to be disabled and it is enabled in this environment, in which case a captured TGT from the trusted forest will not be accepted for the victim resource.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>

## Known gaps

Not yet satisfied: `fp_rules`
