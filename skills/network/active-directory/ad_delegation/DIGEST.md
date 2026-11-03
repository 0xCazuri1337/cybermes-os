<!-- GENERATED from db/wks.db — do not edit -->
# Kerberos Delegation Abuse

> surface: `ad` · CWE: CWE-863 · OWASP: —
> maturity: **mature** — 12 items, 7 supported, 2 FP rules, 1 chains

Delegation lets one identity authenticate as another to a third service, so the ticket a server holds can be replayed as the client it was issued for.

**Aliases:** delegation abuse, unconstrained delegation, constrained delegation, resource based constrained delegation, rbcd, s4u2self, s4u2proxy, ms-was

## Technique

- **Kerberos delegation lets a service present a client's ticket to a downstream service as that client, so a service holding delegated credentials can act as the user against a third system the user could reach.**  
  `high_confidence` · score 0.798 · disproved by: If no SPN in the domain is configured for unconstrained delegation and all resource-based constrained delegation is bound to a specific target service, then no delegable ticket can be redirected and the primitive is closed.
  sources: <https://attack.mitre.org/techniques/T1134/003/> · <https://www.rfc-editor.org/rfc/rfc4120.html>

## Test

- **Unconstrained delegation is not proven by the TrustedForDelegation flag; it is proven by coercing a domain controller to authenticate to the host and observing a TGT for the controller in the host's credential cache.**  
  `high_confidence` · score 0.819 · disproved by: The delegation finding fails when the host has the TrustedForDelegation flag but no domain controller authenticated to it, or when the cache contains only the host's own TGT and no controller TGT.
  sources: <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation.md>

## Fp Rule

- **Constrained delegation configured as Kerberos-only does not yield a forwardable ticket, so the delegation claim does not survive without RBCD.**  
  `high_confidence` · score 0.8715 · disproved by: Would be wrong on a host where RBCD is also configured, because then a forwardable ticket is reachable even without protocol transition.
  sources: <https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained> · <https://specterops.io/blog/2019/02/28/a-case-study-in-wagging-the-dog-computer-takeover/>
- **A TrustedForDelegation host is only a delegation-abuse finding when a working authentication-coercion primitive and a reachable forwarding target both exist.**  
  `high_confidence` · score 0.819 · disproved by: Would be wrong if the environment already runs an exposed credential-capture service that receives authentications without any coercion step.
  sources: <https://specterops.io/blog/2018/11/28/hunting-in-active-directory-unconstrained-delegation-forests-trusts/> · <https://www.rapid7.com/blog/post/2022/02/14/dropping-files-on-a-domain-controller-using-cve-2021-43893/>

## Chain Link

- **A user or computer account trusted for Kerberos constrained delegation lets its holder impersonate any domain user, including an administrator, and authenticate to the specific service that account is trusted to delegate to.**  
  `high_confidence` · score 0.8715 · disproved by: Refuted if no compromised principal holds msDS-AllowedToDelegateTo, or if the KDC enforces the bronze-bit mitigation so that S4U delegation cannot produce a service ticket for a transition that did not authenticate interactively.
  sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation.md>
- **An unconstrained-delegation host that a domain controller authenticates to exposes the controller's own TGT, which converts a single host foothold into a DCSync-capable impersonation of a tier-0 principal and therefore full domain compromise.**  
  `high_confidence` · score 0.86 · disproved by: Refuted if the domain has removed unconstrained delegation from all computer and user objects, or if the coercion target runs no print server and cannot be made to issue an outbound authentication to an attacker-chosen host; the lab result depends on both.
  sources: <https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-dc-print-server-and-kerberos-delegation.md> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/domain-compromise-via-unrestricted-kerberos-delegation.md>
- **When an account is trusted for unconstrained delegation, every subsequent interactive logon to it causes the domain controller to hand a decryptable copy of that user's credentials to the host, so compromising the host hands the next link the credential of whoever logs on next, not just the current session.**  
  `high_confidence` · score 0.844 · disproved by: If the domain controller only sends forwardable TGTs (modern protocol transition, gMSA, or 'do not trust for delegation' state) rather than decryptable credentials, or if no interactive logon by a privileged user is ever observed against that host, the handoff never occurs and the chain stops.
  sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
