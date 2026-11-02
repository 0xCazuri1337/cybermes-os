# Password Attacks against Active Directory

## Definition

Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

- **CWE:** CWE-521
- **OWASP:** None
- **Surface:** ad
- **Aliases:** ["password spraying", "spray", "password attack", "password quality", "credential stuffing", "password reuse", "lockout evasion"]

Canonical home for `password_attacks`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **ad**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

Not yet researched.

## Exploitation

**Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.**

The reason spraying works is arithmetic about how the control is written. Account lockout counts failed attempts per account, so trying many passwords against one account trips it and trying one password against many accounts does not. A spray run is therefore invisible to a per-account threshold and visible only as a many-accounts-one-password pattern, or as a low per-account rate sustained for days — which is why throttling to avoid alerting thresholds is part of the technique rather than an afterthought. Two operational consequences: lockout is not an effective control against spraying at all, and alerting must be built on the cross-account view (distinct accounts failing from one source in a window) rather than the per-account view. Defence in depth is multi-factor, which defeats the technique because the sprayed password is only one of the required factors.

*Disproof:* If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.

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

**One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.**

Discard when a single account authenticated during the run: spraying is defined as trying a few passwords against a set of usernames to stay under the lockout threshold, so one hit proves nothing about breadth. It survives when the same password succeeded on multiple accounts, or when shared badPasswordTime values show the pattern.

*Disproof:* Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.

**Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.**

Discard when the report cites only that a spray was executed against the domain: spraying deliberately uses one password per account so no account locks, which is the technique's design and not a policy failure. It survives when accounts actually locked out or a real weak password was recovered.

*Disproof:* Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **attack.mitre.org** (taxonomy)
  - <https://attack.mitre.org/techniques/T1110/003/>
- **blog.marcfredericgomez.com** (writeup)
  - <https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- **pentestlab.blog** (writeup)
  - <https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/>
- **thehacker.recipes** (cheatsheet)
  - <https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying>
- **ttp.parzival.sh** (cheatsheet)
  - <https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
