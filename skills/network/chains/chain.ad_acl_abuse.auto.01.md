# ad_acl_abuse: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ad_acl_abuse condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ad_acl_abuse. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ad_acl_abuse condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: An object whose DACL grants a low-privilege principal WRITE_DAC, WRITE_OWNER or a generic write right lets that principal rewrite the permissions on the object, converting read access into control of whatever the object governs.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: This is a privilege-escalation primitive, not a data leak. Because access control is itself an object whose access is controlled by the DACL, granting a principal the right to modify the DACL (or to...

**Requires:** an authorised target with a reachable surface for ad_acl_abuse, and permission to record responses

**Backed by:** `ad_acl_abuse.technique.writable_dacl_grants_control`

**This step fails if:** If no principal in the low-privilege set holds WRITE_DAC, WRITE_OWNER, GenericWrite, or an equivalent that permits rewriting the DACL, and the object is not writable by anyone outside its administrators, then no ACL path to control exists.

### 2. Exercise it against the target and capture the raw request and response: A BloodHound attack path or AdminTo-style edge is a capability finding and not an exploitation finding, because the graph records what is permitted rather than what was performed.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ad_acl_abuse.fp_rule.bloodhound-edge-is-capability-not-exploitation`

**This step fails if:** If the privileged route was never executed - no ticket request matching the edge, no DCSync replication event, no hash-authenticated logon on the downstream host - then the edge remains a latent misconfiguration and the exploitation claim built on it is unsupported.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A GenericWrite or GenericAll ACE on an object is not a takeover until the tester controls the principal named in that ACE.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ad_acl_abuse.fprule.genericwrite_needs_controlled_principal`

**This step fails if:** Would be wrong where the same principal is low-privilege and reachable, or where the ACE grants the right to a group the tester already belongs to.
