# prototype_pollution: observe, exercise, confirm

> goal: `Establish, exercise and confirm a prototype_pollution condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for prototype_pollution. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a prototype_pollution condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A JSON body containing __proto__ that round-trips through the attacker's own browser or a client-side merge, with no server-side state change, is NOT server-side prototype pollution and must not be filed as this class.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: This looks like prototype pollution because the payload is textbook and the string __proto__ appears in the request, but the observable effect happens entirely client-side, in the attacker's own...

**Requires:** an authorised target with a reachable surface for prototype_pollution, and permission to record responses

**Backed by:** `prototype_pollution.fp_rule.client_side_roundtrip_is_not_server_pollution`

**This step fails if:** Send the identical payload from a fresh HTTP client that never loaded the app's JavaScript, then request an unrelated endpoint; if the inherited key appears in that server response the pollution is server-side after all and this fp_rule does not apply to it.

### 2. Exercise it against the target and capture the raw request and response: Prototype pollution alone is only a foothold: RCE requires a second gadget that consumes a polluted key, such as a child-process spawn whose env object inherits a NODE_OPTIONS value that adds --require.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `prototype_pollution.chain_link.polluted_key_consumed_by_spawn_env_gadget`

**This step fails if:** If the polluted key is never read by any code path - verified by an unchanged child-process environment and no additional module load in the request logs - then no gadget consumes it and the pollution stops at a DoS-or-nothing level, so the chain to RCE is false.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Prototype pollution requires an untrusted JSON body or query object to reach a sink that merges, extends, clones or deep-assigns it into a server-side object; where user input is only read as a scalar and never merged, no payload can pollute Object.prototype.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `prototype_pollution.prerequisite.untrusted_json_reaches_a_merge_sink`

**This step fails if:** Post {"__proto__":{"polluted":"yes"}} and then, in a SEPARATE request to an unrelated endpoint, read the value back on a fresh object: if ({}).polluted is undefined and no observable behaviour anywhere changes, there is no reachable merge sink and the prerequisite claim is false for that endpoint.
