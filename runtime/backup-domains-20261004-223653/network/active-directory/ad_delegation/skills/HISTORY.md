# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 12 (supported 12), FP rules 3, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 12 (supported 12), FP rules 3, chains 1, state mature

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -67,4 +67,4 @@
   - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
 
 ---
-Full class document: `domains/network/active-directory/ad_delegation/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_delegation`
+Full class document: `domains/network/active-directory/ad_delegation/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_delegation`
```

## 2026-10-02 19:37 — 37 diff lines
- items: 12 (supported 8), FP rules 3, chains 1, state mature

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-863 · OWASP —
-> evidence: 12 items, 12 supported, 3 FP rules, 1 chains
+> evidence: 12 items, 8 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.
@@ -26,13 +26,13 @@
 
 ## Techniques (what to change)
 
-- We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary.
+- We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover enumerating and mapping trust relationships, exploitation of intra-forest tr".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://horizon3.ai/ad-tripwires/>
-- As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.
+- As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://horizon3.ai/ad-tripwires/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://horizon3.ai/ad-tripwires/>
 - Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.
@@ -59,7 +59,7 @@
 - A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.
   - **Disproof:** Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.
   - Sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md>
-- When a write-capable principal can set msDS-AllowedToDelegateTo on a host or service account, the attacker can request a service ticket for any principal to the listed SPN and present it to that resource, so the delegated hop ends in code execution as SYSTEM on the resource server rather than as the original low-privilege identity.
+- When a write-capable principal can set msDS-AllowedToDelegateTo on a host or service account, the attacker can request a service ticket for any principal to the listed SPN and present it to that resource, so the delegated hop ends in code execution as SYSTEM on the resource server rather than as the original low-privilege identity. _(unverified)_
   - **Disproof:** A KDC that refuses the s4u TGS-REQ for a target outside the delegating account's own SPN list, or a resource service that rejects a ticket without EPA/channel binding, breaks this segment; so does a directory where no principal other than domain admins can write msDS-AllowedToDelegateTo.
   - Sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
 - When an account is trusted for unconstrained delegation, every subsequent interactive logon to it causes the domain controller to hand a decryptable copy of that user's credentials to the host, so compromising the host hands the next link the credential of whoever logs on next, not just the current session.
```

## 2026-10-03 01:46 — 51 diff lines
- items: 13 (supported 8), FP rules 3, chains 1, state mature

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `ad` · CWE CWE-863 · OWASP —
-> evidence: 12 items, 8 supported, 3 FP rules, 1 chains
+> evidence: 13 items, 8 supported, 3 FP rules, 1 chains
 > maturity: **mature**
 
 Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.
@@ -20,21 +20,21 @@
 
 ## Prerequisites (do not start without these)
 
-- Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.
+- Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it. _(unverified)_
   - **Disproof:** If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
+  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
 
 ## Techniques (what to change)
 
 - We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover enumerating and mapping trust relationships, exploitation of intra-forest tr".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://horizon3.ai/ad-tripwires/>
+  - Sources: <https://horizon3.ai/ad-tripwires/>
 - As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://horizon3.ai/ad-tripwires/>
+  - Sources: <https://horizon3.ai/ad-tripwires/>
 - The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://horizon3.ai/ad-tripwires/>
+  - Sources: <https://horizon3.ai/ad-tripwires/>
 - Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.
   - **Disproof:** If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
   - Sources: <https://attack.mitre.org/techniques/T1134/003/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
@@ -50,6 +50,12 @@
 - A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.
   - **Disproof:** Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.
   - Sources: <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/> · <https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/>
+
+## Evidence requirements
+
+- A convincing observation for this class is: The observable that triggers this false positive is TrustedForDelegation set to true on a domain computer, filed as unconstrained delegation abuse.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_delegation.fp_rule.delegation_flag_on_service_host_is_intended_configuration) states the full boundary.
+  - Sources: <https://horizon3.ai/ad-tripwires/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
 
 ## Chaining opportunities
 
```

## 2026-10-04 00:43 — 100 diff lines
- items: 13 (supported 8), FP rules 3, chains 1, state mature

```diff
--- ad_delegation@current
+++ ad_delegation@new
@@ -20,57 +20,72 @@
 
 ## Prerequisites (do not start without these)
 
-- Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it. _(unverified)_
+- Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.
   - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
 
 ## Techniques (what to change)
 
-- We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary. _(unverified)_
+- As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
+  - Sources: <https://horizon3.ai/ad-tripwires/>
+- Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
+  - Sources: <https://attack.mitre.org/techniques/T1134/003/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
+- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
+  - Sources: <https://horizon3.ai/ad-tripwires/>
+- We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover enumerating and mapping trust relationships, exploitation of intra-forest tr".
   - Sources: <https://horizon3.ai/ad-tripwires/>
-- As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".
-  - Sources: <https://horizon3.ai/ad-tripwires/>
-- The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".
-  - Sources: <https://horizon3.ai/ad-tripwires/>
-- Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.
-  - **Disproof:** If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
-  - Sources: <https://attack.mitre.org/techniques/T1134/003/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
 
 ## False-positive rules (when to reject it)
 
-- TrustedForDelegation set to true on a domain computer running a service that fronts a back-end datastore is the intended single-sign-on configuration, not a misconfiguration; do not file it as unconstrained delegation abuse unless the privileged host is a workstation or a host that does not front a back-end service, because the flag is normally assigned to machines for exactly this purpose.
+- A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.
+  - Sources: <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/> · <https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/>
+- Constrained delegation configured as Kerberos-only does not yield a forwardable ticket, so the delegation claim does not survive without RBCD.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Would be wrong on a host where RBCD is also configured, because then a forwardable ticket is reachable even without protocol transition.
+  - Sources: <https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
+- TrustedForDelegation set to true on a domain computer running a service that fronts a back-end datastore is the intended single-sign-on configuration, not a misconfiguration; do not file it as unconstrained delegation abuse unless the privileged host is a workstation or a host that does not front a back-end service, because the flag is normally assigned to machines for exactly this purpose.  _(merged 1 duplicate row(s))_
   - **Disproof:** TrustedForDelegation is true on a workstation, a jump host, or any host with no back-end service, so a user's TGT is cached on a machine an operator logs into interactively, or the configured delegation is unconstrained rather than limited to a named target SPN.
   - Sources: <https://horizon3.ai/ad-tripwires/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
-- Constrained delegation configured as Kerberos-only does not yield a forwardable ticket, so the delegation claim does not survive without RBCD.
-  - **Disproof:** Would be wrong on a host where RBCD is also configured, because then a forwardable ticket is reachable even without protocol transition.
-  - Sources: <https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
-- A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.
-  - **Disproof:** Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.
-  - Sources: <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/> · <https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/>
 
 ## Evidence requirements
 
-- A convincing observation for this class is: The observable that triggers this false positive is TrustedForDelegation set to true on a domain computer, filed as unconstrained delegation abuse.
+- A convincing observation for this class is: The observable that triggers this false positive is TrustedForDelegation set to true on a domain computer, filed as unconstrained delegation abuse.  _(merged 1 duplicate row(s))_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_delegation.fp_rule.delegation_flag_on_service_host_is_intended_configuration) states the full boundary.
   - Sources: <https://horizon3.ai/ad-tripwires/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
 
 ## Chaining opportunities
 
-- An unconstrained-delegation host that a domain controller authenticates to exposes the controller's own TGT, which converts a single host foothold into a DCSync-capable impersonation of a tier-0 principal and therefore full domain compromise.
+- A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.
+  - Sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md>
+- An unconstrained-delegation host that a domain controller authenticates to exposes the controller's own TGT, which converts a single host foothold into a DCSync-capable impersonation of a tier-0 principal and therefore full domain compromise.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the domain has removed unconstrained delegation from all computer and user objects, or if the coercion target runs no print server and cannot be made to issue an outbound authentication to an attacker-chosen host; the lab result depends on both.
   - Sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
-- A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.
-  - **Disproof:** Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.
-  - Sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md>
-- When a write-capable principal can set msDS-AllowedToDelegateTo on a host or service account, the attacker can request a service ticket for any principal to the listed SPN and present it to that resource, so the delegated hop ends in code execution as SYSTEM on the resource server rather than as the original low-privilege identity. _(unverified)_
+- When a write-capable principal can set msDS-AllowedToDelegateTo on a host or service account, the attacker can request a service ticket for any principal to the listed SPN and present it to that resource, so the delegated hop ends in code execution as SYSTEM on the resource server rather than as the original low-privilege identity.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** A KDC that refuses the s4u TGS-REQ for a target outside the delegating account's own SPN list, or a resource service that rejects a ticket without EPA/channel binding, breaks this segment; so does a directory where no principal other than domain admins can write msDS-AllowedToDelegateTo.
   - Sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
-- When an account is trusted for unconstrained delegation, every subsequent interactive logon to it causes the domain controller to hand a decryptable copy of that user's credentials to the host, so compromising the host hands the next link the credential of whoever logs on next, not just the current session.
+- When an account is trusted for unconstrained delegation, every subsequent interactive logon to it causes the domain controller to hand a decryptable copy of that user's credentials to the host, so compromising the host hands the next link the credential of whoever logs on next, not just the current session.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the domain controller only sends forwardable TGTs (modern protocol transition, gMSA, or 'do not trust for delegation' state) rather than decryptable credentials, or if no interactive logon by a privileged user is ever observed against that host, the handoff never occurs and the chain stops.
   - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
 
+
+## Hunt procedure
+
+1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
+2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
+3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
+4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+
+### What counts as proof
+
+- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
+- An invariant the application is supposed to hold, observed broken.
+- A second independent confirmation, or an explicit statement that this is single-account evidence only.
+
+> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/network/active-directory/ad_delegation/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_delegation`
```
