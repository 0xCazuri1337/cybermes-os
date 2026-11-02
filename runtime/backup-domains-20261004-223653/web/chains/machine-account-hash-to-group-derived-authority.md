# Machine account NT hash to group-derived authority

> goal: `lateral_movement`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Gain administrative rights on a domain-joined workstation and extract the machine accounts NT hash, the collection step in pass_the_hash.chain_link.dumped_ntlm_hands_authenticated_channel_to_lateral_link

**Why it works:** Administrative rights on the host expose cached credentials including the machine account secret material

**Requires:** Administrative rights on one domain-joined host

### 2. Authenticate as the machine account against NTLM-accepting services, reusing the hash without knowing the plaintext

**Why it works:** Computer/machine accounts are essentially the same as user accounts, so their hash behaves identically under NTLM authentication

**Requires:** The hash from step 1

### 3. Inherit the privileges of whatever groups the machine account belongs to

**Why it works:** Their hashes can be used in pass the hash attacks to gain additional privileges depending on which groups the machine is a member of

**Requires:** Knowledge of the machine accounts group memberships

### 4. Escalate to domain administrator where the machine is a member of an administrative group

**Why it works:** The lab demonstrates elevating to domain admin by passing a machine accounts NT hash, so group derivation is the whole escalation

**Requires:** The authenticated session from step 2 plus favourable group membership
