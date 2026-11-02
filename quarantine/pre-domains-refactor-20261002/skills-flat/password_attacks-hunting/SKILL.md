---
name: password_attacks-hunting
description: Use when hunting Password Attacks against Active Directory in a ad target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Password Attacks against Active Directory — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `ad` · CWE CWE-521 · OWASP —
> evidence: 3 items, 3 supported, 2 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, chain

Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

**Also called:** password spraying, spray, password attack, password quality, credential stuffing, password reuse, lockout evasion


## Techniques (what to change)

- Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.
  - **Disproof:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
  - Sources: <https://attack.mitre.org/techniques/T1110/003/> · <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>

## False-positive rules (when to reject it)

- One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.
  - **Disproof:** Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.
  - Sources: <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying> · <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.
  - **Disproof:** Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
  - Sources: <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying> · <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>

---
Full class document: `skills/Network + AD/password_attacks/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id password_attacks`
