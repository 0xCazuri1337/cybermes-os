# pass_the_hash: observe, exercise, confirm

> goal: `Establish, exercise and confirm a pass_the_hash condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for pass_the_hash. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a pass_the_hash condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: The NT hash of a machine account is a first-class reusable credential, so a compromised workstation yields lateral movement to whatever the machine account is a member of without ever recovering a user password.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Machine accounts are routinely dismissed because no human chose their secret, yet they are ordinary domain principals with the same NTLM hash behaviour and, critically, group membership. The lab...

**Requires:** an authorised target with a reachable surface for pass_the_hash, and permission to record responses

**Backed by:** `pass_the_hash.chain_link.machine_account_ntlm_hash_is_reusable_credential`

**This step fails if:** Refuted if machine accounts are not members of any privileged group and network logons are enforced to reject their hashes, or if the host was not compromised to the point where its hash was readable.

### 2. Exercise it against the target and capture the raw request and response: NTLM and Kerberos protocols accept a key as the credential rather than a secret the user holds, so a captured NTLM hash or service ticket is itself a replayable authentication artifact and needs no password recovery.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `pass_the_hash.technique.replay_hash_as_credential`

**This step fails if:** If the hash or ticket is rejected by the target because channel binding, signing, or an authentication level requirement is enforced, then replay does not authenticate and the finding collapses to a failed logon.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A pass-the-hash finding requires a successful authentication made with the obtained hash, and recovering the hash alone - by replication or by capture - is not pass-the-hash.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `pass_the_hash.validation.hash-must-be-replayed-not-merely-recovered`

**This step fails if:** If every attempt to authenticate with the recovered NT hash against any target service fails and the target logs no NTLM authentication for that account from the operator's host, then no hash was used and the pass-the-hash claim is false even though credential recovery is real.
