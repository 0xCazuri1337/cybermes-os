# Methodology — Password Attacks against Active Directory

> Derived from 4 verified items. Regenerate with `python -m wks.methodgen --class password_attacks --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Directory authentication is online and per-account, so many accounts against one password succeeds where many passwords against one account triggers lockout.

**References.** CWE-521

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Reconnaissance signals

_No verified signal items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely.**

n failure over SMB, the default protocol of common tools 
 4648 Source workstation or server Logon with explicit credentials; absent if the actor tunnels in from their own infrastructure 
 4740 Domain Controllers Account lockout; several lockouts close together are an indicator 
 4771 Domain Controllers Kerberos pre-authentication failure, with Failure Code 0x18 for an incorrect password 
 
 
 

 The badPasswordTime attribute complements these events: if several user objects share the same date and time of last failure, or very close values, spraying is likely. On the mitigation side, the guidance calls for passwords of at least 30 characters for local administrator, service and break glass accounts, managed through Local Administrator Password Solution, LAPS (17), where possible; four random words and at least 15 characters for single-factor authentication; lockout after at most five failed attempts, except for break glass accounts; randomly generated

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“The badPasswordTime attribute complements these events: if several user objects ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [blog.marcfredericgomez.com](https://blog.marcfredericgomez.com/active-directory-the-2026-revision-of-the-cisa-guide/); [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)

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
