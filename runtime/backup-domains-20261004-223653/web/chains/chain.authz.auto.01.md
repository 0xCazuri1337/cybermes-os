# authz: observe, exercise, confirm

> goal: `Establish, exercise and confirm a authz condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for authz. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a authz condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: An attacker could read sensitive data, either by reading the data directly from a data store that is not restricted, or by accessing insufficiently-protected, privileged functionality to read the data.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: equence is expected to be seen relative to the other consequences in the list. For example, there may be high likelihood that a weakness will be exploited to achieve a certain impact, but a low...

**Requires:** an authorised target with a reachable surface for authz, and permission to record responses

**Backed by:** `authz.auto.02`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "An attacker could read sensitive data, either by reading the data directly from a data sto".

### 2. Exercise it against the target and capture the raw request and response: Compromise of an internet-facing web application hands the next link whatever cloud scope that application's own identity carries, because application-held credentials and workload identity tokens are authorized independently of the user who reached the...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `authz.chain_link.app_service_identity_hands_broader_scope_to_cloud_link`

**This step fails if:** If the application's identity is scoped to nothing outside its own resource, or the identity endpoint is unreachable from the compromised context, or the token is rejected for the target resource, then authentication alone did not grant broader authorization and the chain stops inside the application.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: The product does not perform an authorization check when an actor attempts to access a resource or perform an action.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `authz.auto.01`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The product does not perform an authorization check when an actor attempts to access a res".
