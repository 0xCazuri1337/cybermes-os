# password_attacks: observe, exercise, confirm

> goal: `Establish, exercise and confirm a password_attacks condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for password_attacks. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a password_attacks condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Password spraying succeeds where password brute force fails because it inverts the two axes — one password against many accounts — so per-account lockout thresholds never trigger while the total attempt count stays high.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The reason spraying works is arithmetic about how the control is written. Account lockout counts failed attempts per account, so trying many passwords against one account trips it and trying one...

**Requires:** an authorised target with a reachable surface for password_attacks, and permission to record responses

**Backed by:** `password_attacks.technique.spray_across_accounts_to_avoid_lockout`

**This step fails if:** If a spray-shaped run (one password, many distinct accounts, below per-account lockout) produces no successful authentication and every account still enforces multi-factor, then the technique found nothing and must not be reported as a compromise.

### 2. Exercise it against the target and capture the raw request and response: One successful authentication during a spray is not a spraying finding; discard unless the same password hit many accounts.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `password_attacks.fprule.single_success_is_not_spray`

**This step fails if:** Would be wrong where the single success landed on an account whose password was already known to the client, for example a documented test account.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Password spraying that stays under the lockout threshold is expected attack behaviour, not evidence that the password policy is weak.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `password_attacks.fprule.spray_under_lockout_threshold`

**This step fails if:** Would be wrong in a forest with no lockout policy configured at all, where the same spray becomes an unmitigated brute-force path.
