---
name: password_attacks-hunting
description: Use when hunting Password Attacks against Active Directory in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Password Attacks against Active Directory — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-521 · OWASP —
> evidence: 21 items, 3 supported, 2 FP rules, 1 chains
> maturity: **researching** — missing: supported_items

Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

**Also called:** password spraying, spray, password attack, password quality, credential stuffing, password reuse, lockout evasion


## Techniques (what to change)

- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
- Second point: MFA is largely ineffective against this technique once initial access has been obtained, because authentication can be made directly to a Domain Controller over NTLM (14), which does not support it. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Second point: MFA is largely ineffective against this technique once initial access has be".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM accepts the hash as a valid authentication token. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The hashes obtained are either cracked or replayed directly in a Pass-the-Hash, since NTLM".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- The variant applies to user objects configured not to require Kerberos pre-authentication. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The variant applies to user objects configured not to require Kerberos pre-authentication.".
- The only approach proposed is to place a canary GPP password belonging to a user object that should never be used, and to monitor any authentication by that object. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The only approach proposed is to place a canary GPP password belonging to a user object th".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- There is a single mitigating control: require Kerberos pre-authentication on all user objects. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "There is a single mitigating control: require Kerberos pre-authentication on all user obje".
- Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in the guidance, which refers readers to work by SpecterOps, Mandiant and Microsoft. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Twelve other vulnerable configurations, ESC2 through ESC13, exist and are not detailed in ".
- The configuration known as ESC1 combines four conditions: enrolment rights open to user objects, an extended key usage, EKU (21), that enables client authentication, the ability for the requester to supply their own subject alternative name, SAN (22), and the absence of certificate manager approval. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The configuration known as ESC1 combines four conditions: enrolment rights open to user ob".
- The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The badPasswordTime attribute complements these events: if several user objects share the ".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without a valid user object, which produces a logon failure while the ticket is still issued. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Event 4625 adds to it: AS-REP Roasting can be executed before any authentication, without ".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Functional Level to support passwordless authentication including Windows Hello for Business, accepts key credentials. _(unverified)_
  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The msDS-KeyCredentialLink attribute, introduced with the Windows Server 2016 Domain Funct".
  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.
  - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## False-positive rules (when to reject it)

- One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.
  - **Disproof:** Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.
  - Sources: <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.
  - **Disproof:** Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
  - Sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>

---
Full class document: `domains/network/active-directory/password_attacks/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
