# Methodology — Kerberos Delegation Abuse

> Derived from 8 verified items. Regenerate with `python -m wks.methodgen --class ad_delegation --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.

**References.** CWE-863

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.**

Delegation abuse (unconstrained delegation, protocol transition, delegation flags) lives inside the forest: it needs a service or host account with delegation configured and a way to present a captured ticket to that service. The classic mistake is to gate the hunt on 'are there forest trusts', which is the wrong prerequisite. The forest is not the security boundary, and delegation primitives are exercised within a single forest where the attacker already holds a foothold. Enumerate delegation configuration first: msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity, TrustedForDelegation, and the SPN-to-account map. Until that map exists you cannot say which principal is even a candidate, and an inference that a route was available from the mere presence of privileged accounts is an inference the evidence does not carry.

- *Disproof:* If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.
- *Evidence:* high_confidence — [academy.hackthebox.com](https://academy.hackthebox.com/course/preview/active-directory-trust-attacks); [securelist.com](https://securelist.com/tr/payload-ransomware-via-group-policy/121335/)

## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.**

Delegation is the protocol feature that lets a middle tier hold forwardable credentials on a user's behalf. RFC 4120 makes the client's decision explicit: the OK-AS-DELEGATE flag in the ticket flags is set when the realm considers the named server a suitable recipient, and the flag exists so the client can decide whether to forward. The security weight is entirely in which servers are marked delegable: where delegation is configured unconstrained, or where resource-based constrained delegation lets a service obtain forwardable tickets to arbitrary SPNs, the service can authenticate as the user to systems the user never intended. The test is to enumerate which SPNs are configured for delegation, then confirm whether the constraint is to a single target or open. A service that is delegable to anything is a credential-forwarding open door, not a hardening question.

- *Disproof:* If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1134/003/); [rfc-editor.org](https://www.rfc-editor.org/rfc/rfc4120.html)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Constrained delegation configured as Kerberos-only does not yield a forwardable ticket, so the delegation claim does not survive without RBCD.**

Discard when the report lists msDS-AllowedToDelegateTo but never obtained an S4U2proxy ticket: without protocol transition the S4U2self request returns a non-forwardable service ticket and the chain fails. It survives when a forwardable ticket was actually obtained, which requires protocol transition or an RBCD write to msDS-AllowedToActOnBehalfOfOtherIdentity.

- *Disproof:* Would be wrong on a host where RBCD is also configured, because then a forwardable ticket is reachable even without protocol transition.
- *Evidence:* high_confidence — [specterops.io](https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)

**TrustedForDelegation set to true on a domain computer running a service that fronts a back-end datastore is the intended single-sign-on configuration, not a misconfiguration; do not file it as unconstrained delegation abuse unless the privileged host is a workstation or a host that does not front a back-end service, because the flag is normally assigned to machines for exactly this purpose.**

The observable that triggers this false positive is TrustedForDelegation set to true on a domain computer, filed as unconstrained delegation abuse. The flag is normally assigned to machines running IIS, MSSQL, or similar services that must reach a back-end datastore on the authenticated user's behalf, so its presence on those hosts is the intended single-sign-on configuration rather than a deviation from it. The genuinely dangerous case is narrow and different in kind: delegation enabled on a workstation or jump host, where an interactive operator's TGT is cached in memory and can be dumped, or delegation that is unconstrained rather than limited to a named target SPN. This rule rejects the flag on a service host and keeps the sweep pointed at the hosts where an interactive logon lands.

- *Disproof:* TrustedForDelegation is true on a workstation, a jump host, or any host with no back-end service, so a user's TGT is cached on a machine an operator logs into interactively, or the configured delegation is unconstrained rather than limited to a named target SPN.
- *Evidence:* high_confidence — [horizon3.ai](https://horizon3.ai/ad-tripwires/); [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md)

**A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.**

Discard when the engagement only recorded that a computer account has unconstrained delegation enabled: exploitation needs the DC coerced into authenticating to that host so its TGT can be captured, and the Rapid7 work notes the primitive worked only on unconstrained-delegation systems. It survives when the delegation host received a foreign TGT during the test.

- *Disproof:* Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.
- *Evidence:* high_confidence — [rapid7.com](https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/); [specterops.io](https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 4. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.**

Constrained delegation narrows the SPN the attacker may request but does not narrow the identity they may borrow. The lab is explicit: if you have compromised a user account or a computer account that has Kerberos constrained delegation enabled, it is possible to impersonate any domain user including administrator and authenticate to a service that the user account is trusted to delegate to. The mechanism is the S4U exchanges, where the service fills out the pa_for_user structure naming the user on whose behalf the ticket is requested and the service ticket is sent back to the service, carrying a PAC for the borrowed identity. So the dangerous property is asymmetric with its name: constrained controls the destination service, not the subject. A single delegating service account in a highly privileged tier converts any foothold on that host into an administrator ticket for that one backend.

- *Disproof:* Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)

**An unconstrained-delegation host that a domain controller authenticates to exposes the controller's own TGT, which converts a single host foothold into a DCSync-capable impersonation of a tier-0 principal and therefore full domain compromise.**

The chain is entirely made of published lab steps. Unrestricted Kerberos delegation is a privilege assignable to a domain computer or user, so a single compromised delegation-trusted host is the entire prerequisite. The controller is coerced into authenticating to the attacker host by calling a print-server notification API, and that authentication reveals its TGT to the attacker-controlled system. The attacker then extracts the controllers TGT and impersonates the domain controller to carry out a DCSync attack, dumping domain member hashes. Impact is therefore not bounded by the original hosts privileges: one delegation foothold plus one coercible print-capable victim reaches domain admin.

- *Disproof:* Refuted if the domain has removed unconstrained delegation from all computer and user objects, or if the coercion target runs no print server and cannot be made to issue an outbound authentication to an attacker-chosen host; the lab result depends on both.
- *Evidence:* high_confidence — [ired.team](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md); [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)

**When an account is trusted for unconstrained delegation, every subsequent interactive logon to it causes the domain controller to hand a decryptable copy of that user's credentials to the host, so compromising the host hands the next link the credential of whoever logs on next, not just the current session.**

Previous primitive hands over: an account or host marked TrustedForDelegation. The domain controller sends a copy of that user's credentials to the server, which lets the server authenticate on the user's behalf, and Microsoft notes that if such a server is compromised the resource services behind it can be compromised too. Precondition the NEXT link needs: an interactive (interactive logon, not a service logon) authentication to the delegated host by a higher-privileged account, so a decryptable credential lands in that host's memory. Observation that proves this segment: a logon by an administrator-tier account to a host whose delegation attribute is unconstrained, followed by retrievable LSASS-resident secrets for that account on the delegated host. The handoff is a credential, so the next link consumes hashes/tickets and moves laterally with them.

- *Disproof:* If the domain controller only sends forwardable TGTs (modern protocol transition, gMSA, or 'do not trust for delegation' state) rather than decryptable credentials, or if no interactive logon by a privileged user is ever observed against that host, the handoff never occurs and the chain stops.
- *Evidence:* high_confidence — [learn.microsoft.com](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview); [tenable.com](https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link)

## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Reconnaissance signals, Validation, Known bypasses, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
