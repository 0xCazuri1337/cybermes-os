# cmd: observe, exercise, confirm

> goal: `Establish, exercise and confirm a cmd condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for cmd. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a cmd condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A command-injection finding cannot be dismissed because a sanitizer appears on the tainted variable's path, since sanitizers, permissions, and routing conditions in enterprise applications are typically distributed across modules rather than co-located with...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The naive triage error: grep the code, find an escaping or validation call upstream of the sink, close the ticket. The falsifiable test is to trace the value across every hop, because the sanitizing...

**Requires:** an authorised target with a reachable surface for cmd, and permission to record responses

**Backed by:** `cmd.prereq.taint-reaches-sink-despite-distributed-sanitizers`

**This step fails if:** Enumerate every code path from every request-controlled input to the process-spawn sink and show each terminates at an escaping call that provably neutralises shell metacharacters before the spawn, with no bypass via encoding, double-decoding, or an alternate branch. If that holds, the claim is false for that target.

### 2. Exercise it against the target and capture the raw request and response: A command-injection report is confirmed when the baseline request produces no connection to a test listener and the variant produces exactly one unsolicited connection, and is falsified when the baseline produces the same connection.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `cmd.validation.outbound-callback-with-baseline-control-confirms-execution`

**This step fails if:** The benign baseline request produces the same inbound connection to your listener. Then the callback is application behaviour rather than proof of injected execution, and the finding is not validated.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A command-injection endpoint whose payload stops working past a fixed character count is NOT evidence of a working metacharacter filter; it is an unresolved length constraint and the injection remains fully exploitable.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `cmd.fp.fixed-length-truncation-is-not-a-metacharacter-filter`

**This step fails if:** Show that the server rejects rather than silently truncates any request exceeding the ceiling, or that a short payload placed after the ceiling boundary still fails. Then the length limit is an enforced control rather than a truncation artefact.
