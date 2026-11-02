---
name: ad_delegation-hunting
description: Use when hunting Kerberos Delegation Abuse in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Kerberos Delegation Abuse — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-863 · OWASP —
> evidence: 9 items, 8 supported, 3 FP rules, 0 chains
> maturity: **researching** — missing: items, chain

Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.

**Also called:** delegation abuse, unconstrained delegation, constrained delegation, resource based constrained delegation, rbcd, s4u2self, s4u2proxy, ms-was


## Prerequisites (do not start without these)

- Delegation abuse is only testable after intra-forest delegation and trust configuration is enumerated, because cross-forest trust presence is not a precondition for it.
  - **Disproof:** If the enumeration returns no accounts with delegation attributes set (no TrustedForDelegation, no msDS-AllowedToDelegateTo, no msDS-AllowedToActOnBehalfOfOtherIdentity) anywhere in the forest, then no delegation abuse is testable regardless of what trust objects exist.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-trust-attacks> · <https://securelist.com/tr/payload-ransomware-via-group-policy/121335/>

## Techniques (what to change)

- Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.
  - **Disproof:** If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
  - Sources: <https://attack.mitre.org/techniques/T1134/003/> · <https://www.rfc-editor.org/rfc/rfc4120.html>

## False-positive rules (when to reject it)

- TrustedForDelegation set to true on a domain computer running a service that fronts a back-end datastore is the intended single-sign-on configuration, not a misconfiguration; do not file it as unconstrained delegation abuse unless the privileged host is a workstation or a host that does not front a back-end service, because the flag is normally assigned to machines for exactly this purpose.
  - **Disproof:** TrustedForDelegation is true on a workstation, a jump host, or any host with no back-end service, so a user's TGT is cached on a machine an operator logs into interactively, or the configured delegation is unconstrained rather than limited to a named target SPN.
  - Sources: <https://horizon3.ai/ad-tripwires/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
- Constrained delegation configured as Kerberos-only does not yield a forwardable ticket, so the delegation claim does not survive without RBCD.
  - **Disproof:** Would be wrong on a host where RBCD is also configured, because then a forwardable ticket is reachable even without protocol transition.
  - Sources: <https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.
  - **Disproof:** Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.
  - Sources: <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/> · <https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/>

## Chaining opportunities

- An unconstrained-delegation host that a domain controller authenticates to exposes the controller's own TGT, which converts a single host foothold into a DCSync-capable impersonation of a tier-0 principal and therefore full domain compromise.
  - **Disproof:** Refuted if the domain has removed unconstrained delegation from all computer and user objects, or if the coercion target runs no print server and cannot be made to issue an outbound authentication to an attacker-chosen host; the lab result depends on both.
  - Sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
- A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.
  - **Disproof:** Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.
  - Sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md>
- When a write-capable principal can set msDS-AllowedToDelegateTo on a host or service account, the attacker can request a service ticket for any principal to the listed SPN and present it to that resource, so the delegated hop ends in code execution as SYSTEM on the resource server rather than as the original low-privilege identity. _(unverified)_
  - **Disproof:** A KDC that refuses the s4u TGS-REQ for a target outside the delegating account's own SPN list, or a resource service that rejects a ticket without EPA/channel binding, breaks this segment; so does a directory where no principal other than domain admins can write msDS-AllowedToDelegateTo.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.microsoft.com/en-us/security/blog/2022/05/25/detecting-and-preventing-privilege-escalation-attacks-leveraging-kerberos-relaying-krbrelayup/>
- When an account is trusted for unconstrained delegation, every subsequent interactive logon to it causes the domain controller to hand a decryptable copy of that user's credentials to the host, so compromising the host hands the next link the credential of whoever logs on next, not just the current session.
  - **Disproof:** If the domain controller only sends forwardable TGTs (modern protocol transition, gMSA, or 'do not trust for delegation' state) rather than decryptable credentials, or if no interactive logon by a privileged user is ever observed against that host, the handoff never occurs and the chain stops.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>

---
Full class document: `skills/Network + AD/ad_delegation/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_delegation`
