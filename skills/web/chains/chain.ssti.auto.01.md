# ssti: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ssti condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ssti. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ssti condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: If an attacker can influence input into a template before it is processed, then the attacker can invoke arbitrary expressions, i.e. perform injection attacks.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: ert externally-influenced values into free text or messages in order to generate a full web page, document, message, etc. Such engines include Twig, Jinja2, Pug, Java Server Pages, FreeMarker...

**Requires:** an authorised target with a reachable surface for ssti, and permission to record responses

**Backed by:** `ssti.auto.01`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If an attacker can influence input into a template before it is processed, then the attack".

### 2. Exercise it against the target and capture the raw request and response: The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ssti.auto.03`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: The programmer might not use engine's built-in sandboxes or other capabilities to escape or otherwise prevent template injection from untrusted input.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ssti.auto.04`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The programmer might not use engine's built-in sandboxes or other capabilities to escape o".
