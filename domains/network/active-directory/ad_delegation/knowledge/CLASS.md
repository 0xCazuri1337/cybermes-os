# Kerberos Delegation Abuse

## Definition

Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.

- **CWE:** CWE-863
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["delegation abuse", "unconstrained delegation", "constrained delegation", "resource based constrained delegation", "rbcd", "s4u2self", "s4u2proxy", "ms-was"]

Canonical home for `ad_delegation`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Constrained delegation is configured as a list of target SPNs on the delegating account; the delegate can request tickets only to those SPNs, so a service absent from msDS-AllowedToDelegateTo is not reachable through that delegation.**

Constrained delegation is an allow-list, not a general impersonation right. Microsoft describes the feature as restricting the services to which the specified server can act on behalf of a user, and the listed targets are stored on the delegating account. The test should read msDS-AllowedToDelegateTo, compare it with the SPN of the intended service, and then request a service ticket for that SPN. A target outside the list is a negative result even when the account has the delegation flag and can obtain an S4U2Self ticket; the S4U2Proxy step has no matching target entry.

*Disproof:* The constrained-delegation finding fails when the intended service's SPN is absent from msDS-AllowedToDelegateTo, or when the ticket request succeeds only for a different SPN than the one recorded as the target.

**Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.**

Delegation abuse (unconstrained delegation, protocol transition, delegation flags) lives inside the forest: it needs a service or host account with delegation configured and a way to present a captured ticket to that service. The classic mistake is to gate the hunt on 'are there forest trusts', which is the wrong prerequisite. The forest is not the security boundary, and delegation primitives are exercised within a single forest where the attacker already holds a foothold. Enumerate delegation configuration first: msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity, TrustedForDelegation, and the SPN-to-account map. Until that map exists you cannot say which principal is even a candidate, and an inference that a route was available from the mere presence of privileged accounts is an inference the evidence does not carry.

*Disproof:* If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A convincing observation for this class is: The observable that triggers this false positive is TrustedForDelegation set to true on a domain computer, filed as unconstrained delegation abuse.**

Derived from ad_delegation.fp_rule.delegation_flag_on_service_host_is_intended_configuration, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (ad_delegation.fp_rule.delegation_flag_on_service_host_is_intended_configuration) states the full boundary.

## Exploitation

**We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary.**

into their operation environment. 
 
 4.77 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 
 Created by Sentinal 
 Co-Authors:
 MrGrep, mrb3n 
 
 
 
 Start Module 
 
 
 HTB Academy Business 
 
 
 
 
 
 Summary
 
 
 
 Module
 Overview 
 
 
 
 
 
 
 
 Hard
 
 
 Offensive
 
 
 
 
 
 
 
 
 
 
 
 
 
 Summary 
 This module introduces AD enumeration and attack techniques targeting intra-forest and cross forest trusts. We will cover enumerating and mapping trust relationships, exploitation of intra-forest trusts and various attacks that can be performed between forests, dispelling the notion that the forest is the security boundary. 
 In this module, we will cover: 
 
 Enumerating and mapping domain/forest trusts 
 Intra forest attacks, such as:
 
 Unconstrained Delegation 
 Configuration Naming Context (NC) 
 Abusing Active Directory Certificate Services (AD CS) 
 GPO on Site Attack 
 GoldenGMSA Attack 
 DNS Trust Attack 
 Abusing Foreign Groups & ACL Principals 
 The ExtraSids Attack 
 
 
 Cross Forest trust attacks:
 
 Co

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "We will cover enumerating and mapping trust relationships, exploitation of intra-forest tr".

**As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity.**

intra-forest and cross-forest trusts. Intra-forest trusts allow for communication and resource sharing between multiple domains within a single forest, while cross-forest trusts extend this capability across domains in different forests. While these trust relationships enhance collaboration and resource access, they also introduce potential security risks if not properly configured and monitored. As penetration testers, understanding the nuances of these trust relationships enables us to identify and exploit weaknesses that adversaries may leverage to compromise network integrity. 
 
 Why Should We Care About Trusts? 
 Oftentimes a penetration tester will find themselves assessing a large organization where they are able to gain a foothold in their current Active Directory domain but unable to escalate privileges. Enter trusts. Perhaps we have exhausted all avenues of attack but find that we can Kerberoast across a trust and compromise a child domain. Once compromised, we

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "As penetration testers, understanding the nuances of these trust relationships enables us ".

**The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols.**

ements. This module delves into various lateral movement techniques on Windows systems, providing a comprehensive understanding and practical examples of executing and defending against these methods. 
 
 
 
 Using CrackMapExec 
 
 
 Medium 
 
 
 27 Sections 
 
 Reward: +100 
 
 Active Directory presents a vast attack surface and often requires us to use many different tools during an assessment. The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enumeration, attacks, and post-exploitation that can be leveraged against most any domain using multiple network protocols. It is a versatile and highly customizable tool that should be in any penetration tester's toolbox. 
 
 
 
 Kerberos Attacks 
 
 
 Hard 
 
 
 23 Sections 
 
 Reward: +100 
 
 Kerberos is an authentication protocol that allows users to authenticate and access services on a potentially insecure network. Due to its prevalence throughout an Active Directory environment, it presents us with a significa

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The CrackMapExec tool, known as a "Swiss Army Knife" for testing networks, facilitates enu".

**Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.**

Delegation is the protocol feature that lets a middle tier hold forwardable credentials on a user's behalf. RFC 4120 makes the client's decision explicit: the OK-AS-DELEGATE flag in the ticket flags is set when the realm considers the named server a suitable recipient, and the flag exists so the client can decide whether to forward. The security weight is entirely in which servers are marked delegable: where delegation is configured unconstrained, or where resource-based constrained delegation lets a service obtain forwardable tickets to arbitrary SPNs, the service can authenticate as the user to systems the user never intended. The test is to enumerate which SPNs are configured for delegation, then confirm whether the constraint is to a single target or open. A service that is delegable to anything is a credential-forwarding open door, not a hardening question.

*Disproof:* If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.ad_delegation.auto.01` — ad_delegation: observe, exercise, confirm (goal: `Establish, exercise and confirm a ad_delegation condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**TrustedForDelegation set to true on a domain computer running a service that fronts a back-end datastore is the intended single-sign-on configuration, not a misconfiguration; do not file it as unconstrained delegation abuse unless the privileged host is a workstation or a host that does not front a back-end service, because the flag is normally assigned to machines for exactly this purpose.**

The observable that triggers this false positive is TrustedForDelegation set to true on a domain computer, filed as unconstrained delegation abuse. The flag is normally assigned to machines running IIS, MSSQL, or similar services that must reach a back-end datastore on the authenticated user's behalf, so its presence on those hosts is the intended single-sign-on configuration rather than a deviation from it. The genuinely dangerous case is narrow and different in kind: delegation enabled on a workstation or jump host, where an interactive operator's TGT is cached in memory and can be dumped, or delegation that is unconstrained rather than limited to a named target SPN. This rule rejects the flag on a service host and keeps the sweep pointed at the hosts where an interactive logon lands.

*Disproof:* TrustedForDelegation is true on a workstation, a jump host, or any host with no back-end service, so a user's TGT is cached on a machine an operator logs into interactively, or the configured delegation is unconstrained rather than limited to a named target SPN.

**Constrained delegation configured as Kerberos-only does not yield a forwardable ticket, so the delegation claim does not survive without RBCD.**

Discard when the report lists msDS-AllowedToDelegateTo but never obtained an S4U2proxy ticket: without protocol transition the S4U2self request returns a non-forwardable service ticket and the chain fails. It survives when a forwardable ticket was actually obtained, which requires protocol transition or an RBCD write to msDS-AllowedToActOnBehalfOfOtherIdentity.

*Disproof:* Would be wrong on a host where RBCD is also configured, because then a forwardable ticket is reachable even without protocol transition.

**A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.**

Discard when the engagement only recorded that a computer account has unconstrained delegation enabled: exploitation needs the DC coerced into authenticating to that host so its TGT can be captured, and the Rapid7 work notes the primitive worked only on unconstrained-delegation systems. It survives when the delegation host received a foreign TGT during the test.

*Disproof:* Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.

## Validation

**Unconstrained delegation is not proven by the TrustedForDelegation flag; it is proven by coercing a domain controller to authenticate to the host and observing a TGT for the controller in the host's credential cache.**

The delegation flag describes what the host is allowed to do; the finding is the credential it captured. The test has two stages. First, coerce a domain controller to authenticate to the host configured for unconstrained delegation, using a printer or other authentication trigger. Second, inspect the host's credential cache and show a TGT whose client is the domain controller. The second source describes the same mechanism from the controller's side: the DC authenticates to the compromised host and reveals its TGT to the attacker-controlled system. A host with the flag but no coerced authentication and no controller TGT is a configuration observation, not a delegated domain compromise.

*Disproof:* The delegation finding fails when the host has the TrustedForDelegation flag but no domain controller authenticated to it, or when the cache contains only the host's own TGT and no controller TGT.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **academy.hackthebox.com** (docs)
  - <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks>
- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1134/003/>
- **horizon3.ai** (writeup)
  - <https://horizon3.ai/ad-tripwires/>
- **ired.team** (writeup)
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md>
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation.md>
  - <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
- **learn.microsoft.com** (docs)
  - <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview>
- **microsoft.com** (research)
  - <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
- **rapid7.com** (writeup)
  - <https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/>
- **rfc-editor.org** (standard)
  - <https://www.rfc-editor.org/rfc/rfc4120.html>
- **specterops.io** (writeup)
  - <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/>
  - <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **tenable.com** (research)
  - <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained>
- **unit42.paloaltonetworks.com** (research)
  - <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
