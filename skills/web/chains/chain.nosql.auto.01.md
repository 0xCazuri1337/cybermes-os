# nosql: observe, exercise, confirm

> goal: `Establish, exercise and confirm a nosql condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for nosql. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a nosql condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: An endpoint that blocklists disallowed MongoDB field names but leaves top-level operators enabled is bypassed with {"$where":"..."}, which executes a JavaScript expression per document, is not covered by a field blocklist, and turns a stripped result set into...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Find the blocklist by diffing which fields a free-form filter accepts, then send a payload with no disallowed field at all: {"$where":"this.role==='admin'"}. If the result set changes, the blocklist...

**Requires:** an authorised target with a reachable surface for nosql, and permission to record responses

**Backed by:** `nosql.bypass.blocklist_bypass_via_top_level_where_operator`

**This step fails if:** If {"$where":"1==1"}, {"$expr":true} and a throwing expression inside $where are all rejected with a validation error before the query runs, and $where never appears to change the result set, then top-level operators are denied and the field blocklist is not bypassable this way.

### 2. Exercise it against the target and capture the raw request and response: A JSON list endpoint that returns every record to an anonymous caller because it is a public list is NOT NoSQL injection; the separating observation is whether an operator object changes the result set relative to a documented-field request.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `nosql.fp_rule.public_list_endpoint_returning_everything_is_not_injection`

**This step fails if:** If {"status":{"$ne":"deleted"}} returns a different or larger document set than {"status":"active"} on the same endpoint and credential, the operator changed the query and the finding is genuine NoSQL injection, not a public list.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A NoSQL endpoint counts as validated-guarded only when a field-level operator object, a top-level operator such as $where, and a non-allowlisted field name are each rejected, because any one of the three passing leaves an injection path.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `nosql.validation.three_probe_operator_and_field_allowlist_test`

**This step fails if:** If {"field":{"$ne":null}} is rejected with a 400 while {"$where":"1"} still changes the result set, the field blocklist is bypassable and the endpoint is NOT guarded; the validation only passes when both the field-level and the top-level operator probes are rejected.
