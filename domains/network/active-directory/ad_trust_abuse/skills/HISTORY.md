# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 14 (supported 14), FP rules 2, chains 1, state mature

```diff
--- ad_trust_abuse@current
+++ ad_trust_abuse@new
@@ -79,4 +79,4 @@
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
 ---
-Full class document: `domains/network/active-directory/ad_trust_abuse/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_trust_abuse`
+Full class document: `domains/network/active-directory/ad_trust_abuse/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_trust_abuse`
```

## 2026-10-02 19:37 — 62 diff lines
- items: 15 (supported 9), FP rules 2, chains 1, state mature

```diff
--- ad_trust_abuse@current
+++ ad_trust_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-863 · OWASP —
-> evidence: 14 items, 14 supported, 2 FP rules, 1 chains
+> evidence: 15 items, 9 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.
@@ -22,7 +22,7 @@
 
 - No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.
   - **Disproof:** The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.
-  - Sources: <https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts> · <https://www.helpnetsecurity.com/2024/09/26/active-directory-compromise/>
 - No cross-domain attack path can be evaluated from protocol telemetry alone until trust direction and trust type are read off the trust object, because two-way and one-way trusts produce the same traffic shape.
   - **Disproof:** The path under assessment stays entirely inside a single domain and never crosses a trust boundary, in which case trust direction and type cannot be the enabling condition and a different mechanism must be named.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
@@ -35,19 +35,19 @@
 
 ## Techniques (what to change)
 
-- While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored.
+- While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "While these trust relationships enhance collaboration and resource access, they also intro".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary.
+- We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover enumerating and mapping trust relationships, exploitation of intra-forest tr".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- Hence, as penetration testers we must have a deep understanding of the ins and outs of AD, its complexities, intricacies, and the many ways it can be misconfigured or native features can be abused.
+- Hence, as penetration testers we must have a deep understanding of the ins and outs of AD, its complexities, intricacies, and the many ways it can be misconfigured or native features can be abused. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Hence, as penetration testers we must have a deep understanding of the ins and outs of AD,".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- We may also identify trust relationships with other forests and compromising a partner forest may grant us access that we need to compromise our current forest through any number of attacks.
+- We may also identify trust relationships with other forests and compromising a partner forest may grant us access that we need to compromise our current forest through any number of attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We may also identify trust relationships with other forests and compromising a partner for".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
-- As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.
+- As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.
@@ -57,9 +57,15 @@
   - **Disproof:** If the domain's trust objects cannot be modified by any principal outside Domain Admins and no trust exists with an uncontrolled or unexpected partner, then no cross-forest token forgery is available to a lower-privilege actor.
   - Sources: <https://attack.mitre.org/techniques/T1484/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
 
+## Tests
+
+- To decide this case, observe: rgotten during incident response - so the correct output is a hygiene finding on an unused trust, not an abuse finding. Distinguish that clearly from the case where the trust is being actively used to escalate, which is where the real risk lives: the common routes to privileged control are credential-based, such as DCSync or Kerberoasting of privileged service accounts, not the
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_trust_abuse.fp_rule.configured_but_never_traversed_trust_is_architecture_not_abuse) states the full boundary.
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+
 ## Validation bar (how to prove it)
 
-- Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic.
+- Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic. _(unverified)_
   - **Disproof:** The requesting host is a domain controller and the requesting principal is an account legitimately entrusted with replication rights for that domain, with a matching service or backup schedule behind the traffic, in which case the requests are ordinary replication and the abuse hypothesis fails.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/nighteagle-apt-ghostcontainer-and-tunneling/121323/>
 
```

## 2026-10-03 01:46 — 48 diff lines
- items: 16 (supported 9), FP rules 2, chains 1, state mature

```diff
--- ad_trust_abuse@current
+++ ad_trust_abuse@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-863 · OWASP —
-> evidence: 15 items, 9 supported, 2 FP rules, 1 chains
+> evidence: 16 items, 9 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 A trust lets an identity authenticate across a boundary, so a principal in one forest may reach an object in another.
@@ -49,7 +49,7 @@
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
 - As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+  - Sources: <https://attack.mitre.org/techniques/T1484/> · <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
 - An actor holding a foothold in a child domain can request service tickets across the parent-child trust and, on compromising the child, pivot to the parent domain the trust points at.
   - **Disproof:** The trust between the two domains is one-way with the child unable to authenticate outward, or SID filtering and the trust configuration prevent a child-domain principal from being accepted by the parent, in which case the cross-trust Kerberoast path does not exist.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
@@ -59,7 +59,7 @@
 
 ## Tests
 
-- To decide this case, observe: rgotten during incident response - so the correct output is a hygiene finding on an unused trust, not an abuse finding. Distinguish that clearly from the case where the trust is being actively used to escalate, which is where the real risk lives: the common routes to privileged control are credential-based, such as DCSync or Kerberoasting of privileged service accounts, not the
+- To decide this case, observe: This does not make it harmless - a configured trust is available to anyone who later compromises the partner domain, and dormant trust objects are exactly what gets forgotten during incident response - so the correct output is a hygiene finding on an unused trust, not an abuse finding.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (ad_trust_abuse.fp_rule.configured_but_never_traversed_trust_is_architecture_not_abuse) states the full boundary.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
 
@@ -73,10 +73,16 @@
 
 - Reject a ad_trust_abuse finding until it is distinguished from the adjacent behaviour this class also covers. "No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability." and "Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Testing whether the requesting principal actually holds domain replica" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://attack.mitre.org/techniques/T1484/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
+  - Sources: <https://attack.mitre.org/techniques/T1484/> · <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
 - A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.
   - **Disproof:** Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://www.proofpoint.com/us/blog/email-and-cloud-threats/identity-protection-risks-of-domains-and-trusts>
+
+## Evidence requirements
+
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic. _(unverified)_
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_trust_abuse.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://attack.mitre.org/techniques/T1484/> · <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks>
 
 ## Variants
 
```
