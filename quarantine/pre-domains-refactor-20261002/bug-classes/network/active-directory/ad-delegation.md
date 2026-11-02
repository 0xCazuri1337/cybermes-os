# Kerberos Delegation Abuse

## Definition

Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.

- **CWE:** CWE-863
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["delegation abuse", "unconstrained delegation", "constrained delegation", "resource based constrained delegation", "rbcd", "s4u2self", "s4u2proxy", "ms-was"]

Canonical home for `ad_delegation`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.**

Delegation abuse (unconstrained delegation, protocol transition, delegation flags) lives inside the forest: it needs a service or host account with delegation configured and a way to present a captured ticket to that service. The classic mistake is to gate the hunt on 'are there forest trusts', which is the wrong prerequisite. The forest is not the security boundary, and delegation primitives are exercised within a single forest where the attacker already holds a foothold. Enumerate delegation configuration first: msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity, TrustedForDelegation, and the SPN-to-account map. Until that map exists you cannot say which principal is even a candidate, and an inference that a route was available from the mere presence of privileged accounts is an inference the evidence does not carry.

*Disproof:* If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

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

Not yet researched.

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

Not yet researched.

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
- **securelist.com** (research)
  - <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>
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
