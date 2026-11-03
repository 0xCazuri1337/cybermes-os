# rate_limit: observe, exercise, confirm

> goal: `Establish, exercise and confirm a rate_limit condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for rate_limit. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a rate_limit condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two halves of the same control rather than two independent ones.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Resource consumption is bounded by constraining allocation per unprivileged user and by rejecting oversized payloads at the protocol edge, so the per-user cap and the maximum-size refusal are two...

**Requires:** an authorised target with a reachable surface for rate_limit, and permission to record responses

**Backed by:** `rate_limit.w11.technique.3b7ae590`

**This step fails if:** Refuted if every oversized request is refused with 413 before any allocation, and if a single unprivileged account cannot raise its own ceiling by re-authenticating, changing address, or issuing a second session.

### 2. Exercise it against the target and capture the raw request and response: Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP or issues a password-recovery token stays abusable even when a global per-timeframe limit is present and...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `rate_limit.w11.technique.9a52c7d6`

**This step fails if:** Refuted if repeatedly triggering one operation at a rate well inside the documented global request limit is still rejected or delayed by a per-operation counter, or if the operation is inherently single-use and the second use is rejected on state rather than on a counter.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Reject a rate_limit finding until it is distinguished from the adjacent behaviour this class also covers. "Throttling a single expensive operation per client is a distinct control from limiting overall request frequency, so an endpoint that validates an OTP...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `rate_limit.fp_rule.auto.derived2`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A high volume of failed logon attempts followed by a single success fr" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
