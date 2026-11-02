# mass_assign: observe, exercise, confirm

> goal: `Establish, exercise and confirm a mass_assign condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for mass_assign. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a mass_assign condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: "Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modification of multiple object attributes.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: ption If the object contains attributes that were only intended for internal use, then their unexpected modification could lead to a vulnerability. This weakness is sometimes known by the...

**Requires:** an authorised target with a reachable surface for mass_assign, and permission to record responses

**Backed by:** `mass_assign.auto.01`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: ""Mass assignment" is the name of a feature in Ruby on Rails that allows simultaneous modif".

### 2. Exercise it against the target and capture the raw request and response: A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `mass_assign.signal.role_field_in_post_body`

**This step fails if:** If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `mass_assign.fp_rule.blocklist_role_names`

**This step fails if:** If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
