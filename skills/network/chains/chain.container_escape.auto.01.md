# container_escape: observe, exercise, confirm

> goal: `Establish, exercise and confirm a container_escape condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for container_escape. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a container_escape condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Hypothesis under test: The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing...

**Requires:** an authorised target with a reachable surface for container_escape, and permission to record responses

**Backed by:** `container_escape.fp_rule.auto.derived`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A Docker authorization policy that filters container creation but igno" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 2. Exercise it against the target and capture the raw request and response: Reject a container_escape finding until it is distinguished from the adjacent behaviour this class also covers. "A Docker authorization policy that filters container creation but ignores docker exec, alternate JSON keys such as top-level Binds, or plugin...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `container_escape.fp_rule.auto.derived2`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Creating an unconfined container and then requesting a privileged exec" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: The enforcement surface a hunter must probe is the full set: container creation endpoints plus HostConfig Binds, Mounts, Privileged, CapAdd, PidMode and namespace-sharing options, docker exec behavior, and plugin management endpoints.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `container_escape.test.raw_common_plugin_targets_important_a`

**This step fails if:** Every one of those endpoints and HostConfig fields is validated against the policy and rejects out-of-model runtime actions.
