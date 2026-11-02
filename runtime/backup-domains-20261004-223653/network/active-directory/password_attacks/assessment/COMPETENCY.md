# Methodology — Password Attacks against Active Directory

> Derived from 3 verified items. Regenerate with `python -m wks.methodgen --class password_attacks --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

**References.** CWE-521

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.**

The reason spraying works is arithmetic about how the control is written. Account lockout counts failed attempts per account, so trying many passwords against one account trips it and trying one password against many accounts does not. A spray run is therefore invisible to a per-account threshold and visible only as a many-accounts-one-password pattern, or as a low per-account rate sustained for days — which is why throttling to avoid alerting thresholds is part of the technique rather than an afterthought. Two operational consequences: lockout is not an effective control against spraying at all, and alerting must be built on the cross-account view (distinct accounts failing from one source in a window) rather than the per-account view. Defence in depth is multi-factor, which defeats the technique because the sprayed password is only one of the required factors.

- *Disproof:* If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.
- *Evidence:* high_confidence — [attack.mitre.org](https://attack.mitre.org/techniques/T1110/003/); [blog.marcfredericgomez.com](https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/)

## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.**

Discard when a single account authenticated during the run: spraying is defined as trying a few passwords against a set of usernames to stay under the lockout threshold, so one hit proves nothing about breadth. It survives when the same password succeeded on multiple accounts, or when shared badPasswordTime values show the pattern.

- *Disproof:* Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.
- *Evidence:* high_confidence — [blog.marcfredericgomez.com](https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/); [thehacker.recipes](https://www.thehacker.recipes/ad/movement/credentials/bruteforcing/spraying)

**Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.**

Discard when the report cites only that a spray was executed against the domain: spraying deliberately uses one password per account so no account locks, which is the technique's design and not a policy failure. It survives when accounts actually locked out or a real weak password was recovered.

- *Disproof:* Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
- *Evidence:* high_confidence — [pentestlab.blog](https://pentestlab.blog/2019/09/05/microsoft-exchange-password-spraying/); [ttp.parzival.sh](https://ttp.parzival.sh/pentesting/infrastructure/active-directory/password-spraying)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Reconnaissance signals, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
