# smuggling: observe, exercise, confirm

> goal: `Establish, exercise and confirm a smuggling condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for smuggling. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a smuggling condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation is a tiny HTML attachment that appears inert to mail and web filters, contains an encoded blob, and reconstructs a payload client-side, which is filed under smuggling because the...

**Requires:** an authorised target with a reachable surface for smuggling, and permission to record responses

**Backed by:** `smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync`

**This step fails if:** A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.

### 2. Exercise it against the target and capture the raw request and response: It basically enables you to hide a payload in plain sight.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `smuggling.auto.01`

**This step fails if:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `smuggling.signal.admin-path-probe-as-recon-signal`

**This step fails if:** If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
