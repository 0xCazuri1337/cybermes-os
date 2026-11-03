<!-- GENERATED from db/wks.db — do not edit -->
# Password Attacks against Active Directory

> surface: `ad` · CWE: CWE-521 · OWASP: —
> maturity: **mature** — 12 items, 4 supported, 2 FP rules, 1 chains

Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

**Aliases:** password spraying, spray, password attack, password quality, credential stuffing, password reuse, lockout evasion

## Technique

- **The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.**  
  `high_confidence` · score 0.772 · disproved by: Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The badPasswordTime attribute complements these events: if several user objects ”) does not occur under a test that isolates that control.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## Test

- **Password spraying is detected by correlating failed authentications across many accounts that share a narrow time window and a common source, not by a single failed logon.**  
  `high_confidence` · score 0.8655 · disproved by: The spray finding fails when the failures involve only one account, when each account is tried with many different passwords, or when the failed events have no common source or narrow time window.
  sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>

## Fp Rule

- **One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.
  sources: <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.**  
  `high_confidence` · score 0.844 · disproved by: Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
  sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
