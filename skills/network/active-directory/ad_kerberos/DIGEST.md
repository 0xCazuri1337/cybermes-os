<!-- GENERATED from db/wks.db — do not edit -->
# Kerberos Authentication Weaknesses

> surface: `ad` · CWE: CWE-287 · OWASP: —
> maturity: **mature** — 14 items, 11 supported, 3 FP rules, 1 chains

Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.

**Aliases:** kerberoasting, kerberoast, asrep roasting, as-rep roasting, asreproasting, golden ticket, silver ticket, spn, service principal name, ticket forgery, tgs request, service ticket, krbtgt

## Signal

- **A single host receiving TGS-REP responses for numerous unique SPNs inside a short window is an early observable for Kerberoasting but is identical to legitimate service-ticket traffic.**  
  `high_confidence` · score 0.899 · disproved by: If the unique SPNs in the window resolve to a single known management or monitoring principal that is documented to service that SPN set on a schedule, then the fan-out is the agent's normal behaviour and the Kerberoasting hypothesis for that host is invalidated.
  sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Technique

- **A Kerberos service ticket whose SPN is issued to an account with no interactive login (a service principal) is an offline password-cracking oracle when the KDC still protects it with RC4, because the ticket's encrypted part is keyed on the account password hash.**  
  `high_confidence` · score 0.9175 · disproved by: If the KDC refuses to issue service tickets to requesting users' RC4 (etype 23 is globally disabled), or every crackable ticket offline fails to recover the account password, then this class is not exploitable in this environment and the finding is a false positive.
  sources: <https://attack.mitre.org/techniques/T1558/003/> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
- **An AD account with a service principal name set is requestable by any authenticated domain principal, and the returned ticket is encrypted with the account's own long-term key, so the SPN inventory is the precondition that makes offline key recovery a single request away.**  
  `high_confidence` · score 0.8715 · disproved by: If the domain enforces AES-only service tickets and the SPNs are all AES with long keys, or if no low-privilege principal holds a TGT at all, the request fails or the returned ticket is not crackable with the assumed key material, and the technique has no entry point.
  sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
- **A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.**  
  `high_confidence` · score 0.8615 · disproved by: If enumeration returns no accounts with preauthentication disabled, or an AS-REQ without an encrypted timestamp is rejected with KDC_ERR_PREAUTH_REQUIRED for every account tested, then no AS-REP material exists and the attack has no precondition.
  sources: <https://attack.mitre.org/techniques/T1558/004/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
- **Possession of the KRBTGT account password hash is sufficient to forge arbitrary Kerberos ticket-granting tickets for any principal in the forest, because KRBTGT is the key that signs and encrypts every TGT in that domain.**  
  `high_confidence` · score 0.834 · disproved by: If KRBTGT cannot be dumped (credential protection intact, PAW/Protected Users enforced) or a ticket minted from the hash is rejected by a domain controller, then no forged TGT is usable and the class does not apply here.
  sources: <https://attack.mitre.org/techniques/T1558/001/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
- **Kerberoasting targets service tickets for accounts with a pre-authentication setting that permits it, and the returned ticket is cracked offline for the account password.**  
  `high_confidence` · score 0.8295 · disproved by: Refuted when no account has a non-empty SPN or the accounts that do are configured not to require pre-authentication, in which case no roastable ticket is obtainable.
  sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>

## Fp Rule

- **The number of accounts with an SPN is not itself a Kerberoasting finding; the finding needs a cracked or reusable ticket to survive.**  
  `high_confidence` · score 0.899 · disproved by: Would be wrong for a domain whose service accounts all carry short dictionary passwords, where ticket extraction alone is already sufficient for compromise.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/> · <https://www.thehacker.recipes/ad/movement/kerberos/kerberoast>
- **A single Kerberos 4769 service-ticket event is not evidence of Kerberoasting unless it also shows RC4 request, a user account and a burst pattern.**  
  `high_confidence` · score 0.8715 · disproved by: Would be wrong if a domain is hardened so that every 4769 originates from machine accounts using AES, since then the account-name signal alone carries no information.
  sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/> · <https://www.thehacker.recipes/ad/movement/kerberos/kerberoast>

## Chain Link

- **Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack them offline without triggering account lockout.**  
  `high_confidence` · score 0.945 · disproved by: If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.
  sources: <https://capec.mitre.org/data/definitions/191.html> · <https://capec.mitre.org/data/definitions/497.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md>
- **An account flagged Do not require Kerberos preauthentication can be turned into a password hash by any domain user, because the AS-REP returned in place of a pre-authentication exchange is encrypted with that user's NTLM hash.**  
  `high_confidence` · score 0.8465 · disproved by: Refuted if preauthentication is enforced for every user in the domain, or if all qualifying accounts hold passwords of high enough entropy that offline cracking fails; the roast still succeeds but yields nothing.
  sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
- **Kerberoasting is available to any domain user because the service ticket returned for a service principal name carries a portion encrypted with the service account's NTLM hash, which the attacker cracks offline without ever touching that account's password.**  
  `high_confidence` · score 0.8465 · disproved by: Refuted if every service principal name is mapped to an account whose password is a random value of high entropy, or if the domain has disabled RC4 so tickets are AES-encrypted and offline cracking is impractical.
  sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

## False-positive rules

- **Hypothesis:** Host is Kerberoasting: one client requested TGS tickets for many SPNs in a short window
  - **Invalidated by:** the excess was entirely system SPNs, which exist in nearly every corporate environment regardless of adversary activity; the corrected unique non-system SPN count sat below threshold across a full business cycle
  - **Rule:** a Kerberoasting threshold that counts system SPNs or raw response packets is invalid; require a per-client count of unique non-system sname values before calling the fan-out an attack
