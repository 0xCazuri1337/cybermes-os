---
name: ad_kerberos-hunting
description: Use when hunting Kerberos Authentication Weaknesses in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Kerberos Authentication Weaknesses — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-287 · OWASP —
> evidence: 15 items, 12 supported, 4 FP rules, 1 chains
> maturity: **mature**

Kerberos issues tickets that can be requested offline and cracked, or forged outright when the relevant key material is reachable.

**Also called:** kerberoasting, kerberoast, asrep roasting, as-rep roasting, asreproasting, golden ticket, silver ticket, spn, service principal name, ticket forgery, tgs request, service ticket, krbtgt


## Recon signals (where to look)

- A single host receiving TGS-REP responses for numerous unique SPNs inside a short window is an early observable for Kerberoasting but is identical to legitimate service-ticket traffic.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the unique SPNs in the window resolve to a single known management or monitoring principal that is documented to service that SPN set on a schedule, then the fan-out is the agent's normal behaviour and the Kerberoasting hypothesis for that host is invalidated.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>

## Techniques (what to change)

- A Kerberos service ticket whose SPN is issued to an account with no interactive login (a service principal) is an offline password-cracking oracle when the KDC still protects it with RC4, because the ticket's encrypted part is keyed on the account password hash.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the KDC refuses to issue service tickets to requesting users' RC4 (etype 23 is globally disabled), or every crackable ticket offline fails to recover the account password, then this class is not exploitable in this environment and the finding is a false positive.
  - Sources: <https://attack.mitre.org/techniques/T1558/003/> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
- A domain account configured with 'do not require Kerberos preauthentication' will return an AS-REP containing ticket-granting data to an unauthenticated AS-REQ, turning the authentication service into an offline password-cracking oracle for that account.  _(merged 1 duplicate row(s))_
  - **Disproof:** If enumeration returns no accounts with preauthentication disabled, or an AS-REQ without an encrypted timestamp is rejected with KDC_ERR_PREAUTH_REQUIRED for every account tested, then no AS-REP material exists and the attack has no precondition.
  - Sources: <https://attack.mitre.org/techniques/T1558/004/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
- An AD account with a service principal name set is requestable by any authenticated domain principal, and the returned ticket is encrypted with the account's own long-term key, so the SPN inventory is the precondition that makes offline key recovery a single request away.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the domain enforces AES-only service tickets and the SPNs are all AES with long keys, or if no low-privilege principal holds a TGT at all, the request fails or the returned ticket is not crackable with the assumed key material, and the technique has no entry point.
  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview> · <https://www.tenable.com/blog/service-accounts-in-active-directory-these-og-nhis-could-be-your-weakest-link>
- Kerberoasting targets service tickets for accounts with a pre-authentication setting that permits it, and the returned ticket is cracked offline for the account password.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when no account has a non-empty SPN or the accounts that do are configured not to require pre-authentication, in which case no roastable ticket is obtainable.
  - Sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://raw.githubusercontent.com/ajcriado/htb-writeups/main/Academy/CPTS/Content%20Summary/13.%20Active%20Directory%20Enumeration%20%26%20Attacks.md>
- Possession of the KRBTGT account password hash is sufficient to forge arbitrary Kerberos ticket-granting tickets for any principal in the forest, because KRBTGT is the key that signs and encrypts every TGT in that domain.  _(merged 1 duplicate row(s))_
  - **Disproof:** If KRBTGT cannot be dumped (credential protection intact, PAW/Protected Users enforced) or a ticket minted from the hash is rejected by a domain controller, then no forged TGT is usable and the class does not apply here.
  - Sources: <https://attack.mitre.org/techniques/T1558/001/> · <https://www.rfc-editor.org/rfc/rfc4120.html>
- SQL injection is a code injection technique used to take advantage of coding vulnerabilities and inject SQL queries via an application to bypass authentication, retrieve data from the back-end database, or achieve code execution on the underlying server.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "SQL injection is a code injection technique used to take advantage of coding vulnerabiliti".
  - Sources: <https://www.rfc-editor.org/rfc/rfc4120.html> · <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
- This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations".
  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>
- This will make us more effective as attackers and equip us to give sound recommendations to our clients on the major issues within their environment, as well as clear and actionable remediation advice.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This will make us more effective as attackers and equip us to give sound recommendations t".
  - Sources: <https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview>

## False-positive rules (when to reject it)

- A single Kerberos 4769 service-ticket event is not evidence of Kerberoasting unless it also shows RC4 request, a user account and a burst pattern.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong if a domain is hardened so that every 4769 originates from machine accounts using AES, since then the account-name signal alone carries no information.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/> · <https://www.thehacker.recipes/ad/movement/kerberos/kerberoast>
- Counting system SPNs toward a unique-SPN Kerberoasting threshold produces a false positive, because system SPNs exist in nearly every corporate environment and are irrelevant to the attack.  _(merged 1 duplicate row(s))_
  - **Disproof:** If a per-client unique-SPN count computed with system SPNs excluded stays below threshold across the estate's normal traffic for a full business cycle, then the threshold was being inflated by system SPNs and the flagged alerts were false positives.
  - Sources: <https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks> · <https://securelist.com/tr/network-anomaly-detection-in-kata/120892/>
- The number of accounts with an SPN is not itself a Kerberoasting finding; the finding needs a cracked or reusable ticket to survive.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong for a domain whose service accounts all carry short dictionary passwords, where ticket extraction alone is already sufficient for compromise.
  - Sources: <https://www.nccgroup.com/research/defending-your-directory-an-expert-guide-to-combating-kerberoasting-in-active-directory/> · <https://www.thehacker.recipes/ad/movement/kerberos/kerberoast>

## Chaining opportunities

- An account flagged Do not require Kerberos preauthentication can be turned into a password hash by any domain user, because the AS-REP returned in place of a pre-authentication exchange is encrypted with that user's NTLM hash.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted if preauthentication is enforced for every user in the domain, or if all qualifying accounts hold passwords of high enough entropy that offline cracking fails; the roast still succeeds but yields nothing.
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>
- Disclosed SPN-bearing account names from directory enumeration are the direct input to kerberoasting, because it allows any domain user to request TGS tickets encrypted with the NTLM hash of those accounts' plaintext passwords and crack them offline without triggering account lockout.  _(merged 1 duplicate row(s))_
  - **Disproof:** If the domain enforces AES-only encryption with no RC4 fallback for the service tickets, or every service account has a long random password of full entropy, then the disclosed account list yields no crackable material and the chain terminates.
  - Sources: <https://capec.mitre.org/data/definitions/191.html> · <https://capec.mitre.org/data/definitions/497.html> · <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md>
- Kerberoasting is available to any domain user because the service ticket returned for a service principal name carries a portion encrypted with the service account's NTLM hash, which the attacker cracks offline without ever touching that account's password.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted if every service principal name is mapped to an account whose password is a random value of high entropy, or if the domain has disabled RC4 so tickets are AES-encrypted and offline cracking is impractical.
  - Sources: <https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting.md> · <https://www.zscaler.com/blogs/product-insights/active-directory-kerberoasting-deception-detection>

## Rejected before you report

- **Host is Kerberoasting: one client requested TGS tickets for many SPNs in a short window**
  - Killed by: the excess was entirely system SPNs, which exist in nearly every corporate environment regardless of adversary activity; the corrected unique non-system SPN count sat below threshold across a full business cycle
  - Rule: a Kerberoasting threshold that counts system SPNs or raw response packets is invalid; require a per-client count of unique non-system sname values before calling the fan-out an attack


## Hunt procedure

1. Request a ticket for the target SPN and compare the encryption type and roasting viability against the domain baseline.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/active-directory/ad_kerberos/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id ad_kerberos`
