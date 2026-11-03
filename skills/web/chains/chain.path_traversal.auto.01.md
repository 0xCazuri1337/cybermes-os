# path_traversal: observe, exercise, confirm

> goal: `Establish, exercise and confirm a path_traversal condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for path_traversal. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a path_traversal condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: chances of success. If errors must be captured in some detail, record them in log messages, but consider what could occur if the log messages can be viewed by attackers. Highly sensitive information...

**Requires:** an authorised target with a reachable surface for path_traversal, and permission to record responses

**Backed by:** `path_traversal.auto.01`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In the context of path traversal, error messages which disclose path information can help ".

### 2. Exercise it against the target and capture the raw request and response: A traversal allowlist is bypassed when the filter compares the raw request path but the backend normalizes percent-encoded octets before resolving the file.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `path_traversal.bypass.percent_encoding_normalization_defeats_allowlist`

**This step fails if:** If the percent-encoded form is rejected identically to the literal form, or if the backend serves neither variant outside the intended directory, no allowlist bypass exists and the payload is simply blocked.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Traversal requires a request-controlled string concatenated into a filesystem path with no canonicalisation or prefix check; a vulnerable version alone is not enough.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `path_traversal.prerequisite.user_controlled_path_component`

**This step fails if:** If the response is identical for a traversal payload and for a nonexistent file, or the value is canonicalised and stripped of parent segments before the open, there is no traversal sink.
