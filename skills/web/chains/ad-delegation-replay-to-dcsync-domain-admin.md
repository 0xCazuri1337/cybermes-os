# Unconstrained delegation replay to DCSync domain compromise

> goal: `domain_admin`
> generated from `db/wks.db` — edit the rows, not this file

_Summary not yet written._

## Impact

_Impact not yet written._

## Sequence

### 1. Compromise one host that is trusted for unrestricted Kerberos delegation, establishing the foothold that ad_delegation.chain_link.unconstrained_delegation_replay_hands_hash_to_credential_access depends on

**Why it works:** Unrestricted delegation is a privilege that can be assigned to a domain computer or a user, so any one such host is a credential-collection point rather than a dead end

**Requires:** Initial execution on a delegation-trusted domain host

### 2. Use the delegation trust to capture and decrypt TGTs handed to that host by later interactive logons, the mechanism recorded as ad_delegation.chain_link.unconstrained_delegation_replay_hands_hash_to_credential_access

**Why it works:** The KDC encrypts the forwarded TGT with the delegation-trusted host's key, so an attacker holding that key recovers the ticket material of whoever logs on next

**Requires:** The foothold from step 1 plus a later victim logon to trigger the forward

### 3. Coerce a domain controller that runs a print server into authenticating to the attacker host so the controllers own TGT is exposed, extending the replay primitive to a tier-0 victim

**Why it works:** Calling the print-server change-notification API makes the controller authenticate outward, which is the same exposure mechanism applied to a tier-0 principal

**Requires:** The step 2 replay technique and a print-server-enabled victim

### 4. Impersonate the domain controller with the harvested ticket and run DCSync to dump domain member hashes, completing the escalation the print-server delegation lab publishes

**Why it works:** A controllers own ticket grants it the replication rights DCSync abuses, so domain hashes fall out of one ticket

**Requires:** The controllers decrypted TGT from step 3
