---
name: password_attacks-hunting
description: Use when hunting Password Attacks against Active Directory in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Password Attacks against Active Directory — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-521 · OWASP —
> evidence: 12 items, 4 supported, 2 FP rules, 1 chains
> maturity: **mature**

Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

**Also called:** password spraying, spray, password attack, password quality, credential stuffing, password reuse, lockout evasion


## Techniques (what to change)

- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.  _(merged 1 duplicate row(s))_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The badPasswordTime attribute complements these events: if several user objects ”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The only approach proposed is to place a canary GPP password belonging to a user”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- The variant applies to user objects configured not to require Kerberos pre-authentication.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The variant applies to user objects configured not to require Kerberos pre-authe”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- There is a single mitigating control: require Kerberos pre-authentication on all user objects.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“There is a single mitigating control: require Kerberos pre-authentication on all”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft.  _(merged 1 duplicate row(s))_ _(unverified)_
  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not de”) does not occur under a test that isolates that control.
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## Tests

- Password spraying is detected by correlating failed authentications across many accounts that share a narrow time window and a common source, not by a single failed logon.  _(merged 1 duplicate row(s))_
  - **Disproof:** The spray finding fails when the failures involve only one account, when each account is tried with many different passwords, or when the failed events have no common source or narrow time window.
  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## False-positive rules (when to reject it)

- One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.
  - Sources: <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.  _(merged 1 duplicate row(s))_
  - **Disproof:** Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
  - Sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>


## Hunt procedure

1. Rate-limit your attempts inside the authorized window and record what a single-account, low-and-slow check can and cannot conclude.

### What counts as proof

- Two responses that differ in a way the CONTROL did not, produced by a single changed variable.
- An invariant the application is supposed to hold, observed broken.
- A second independent confirmation, or an explicit statement that this is single-account evidence only.

> Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
---
Full class document: `domains/network/active-directory/password_attacks/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`

---
Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
