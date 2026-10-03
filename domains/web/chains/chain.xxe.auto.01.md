# xxe: observe, exercise, confirm

> goal: `Establish, exercise and confirm a xxe condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for xxe. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a xxe condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: An XXE filter that greps for a keyword in one encoding is a false-negative source, so a single clean probe never proves the target is safe.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: If the target halts XML processing when an external entity is detected, re-send the same document in a different encoding such as UTF-7 and compare. A filter matching decoded UTF-8 text can be...

**Requires:** an authorised target with a reachable surface for xxe, and permission to record responses

**Backed by:** `xxe.fp_rule.encoding_shifts_bypass_entity_blocklists`

**This step fails if:** If both the UTF-8 and alternate-encoding probes are rejected with the entity never resolved, the blocklist holds for the encodings tested and the bypass does not reproduce.

### 2. Exercise it against the target and capture the raw request and response: An XXE finding is validated only when an inbound HTTP request to the supplied entity URL was actually observed on a listener you control.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `xxe.validation.inbound_dtd_callback_confirms_resolution`

**This step fails if:** No inbound request to the entity URL means entity resolution did not occur and the XXE finding is not reproducible, no matter how alarming the submitted payload looked.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Submitting a DOCTYPE with an external SYSTEM or PUBLIC identifier is the probe that reveals whether the parser resolves entities at all.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `xxe.technique.external_dtd_reference_is_the_core_probe`

**This step fails if:** If no callback arrives and the response shows the DOCTYPE passed through unparsed, the parser has external entity resolution disabled and the probe is negative.
