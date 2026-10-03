# ldap_enum: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ldap_enum condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ldap_enum. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ldap_enum condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: LDAP returns directory entries selected by a client-supplied filter, so a permissive base scope lets a client walk the tree and receive attributes without any per-object authorization decision being visible in the protocol.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The LDAP search operation is defined by the filter the client sends and the attributes it asks for; when the filter evaluates true for an entry, that entry's attributes come back subject to...

**Requires:** an authorised target with a reachable surface for ldap_enum, and permission to record responses

**Backed by:** `ldap_enum.technique.filter_tree_walk_returns_directory_structure`

**This step fails if:** If an (objectClass=*) subtree query from an unprivileged bind returns no entries, or the server rejects it with an insufficient-access error, then the directory structure is not enumerable through that path.

### 2. Exercise it against the target and capture the raw request and response: Directory enumeration is only possible where a bind is accepted without integrity protection, because a domain controller configured to enforce LDAP signing rejects SASL binds that do not request signing and rejects simple binds over unencrypted connections...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ldap_enum.prerequisite.unsigned_ldap_bind_is_the_read_precondition`

**This step fails if:** If the domain controller refuses unsigned and simple binds (LDAP signing set to Require signing, channel binding in use), an enumeration primitive never gets a response body and no chain that depends on a directory read can start; a TLS-only anonymous read that still returns data would disprove that specific claim, not the requirement.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A successful anonymous LDAP query is not expected behaviour; discard the enumeration finding when the bind only succeeded with supplied credentials.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ldap_enum.fprule.anonymous_bind_is_usually_disabled`

**This step fails if:** Would be wrong in a forest that permits anonymous binds by policy, where the same query without credentials is the anomaly.
