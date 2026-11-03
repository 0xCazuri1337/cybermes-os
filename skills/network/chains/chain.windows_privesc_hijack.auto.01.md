# windows_privesc_hijack: observe, exercise, confirm

> goal: `Establish, exercise and confirm a windows_privesc_hijack condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for windows_privesc_hijack. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a windows_privesc_hijack condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Hypothesis under test: For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the...

**Requires:** an authorised target with a reachable surface for windows_privesc_hijack, and permission to record responses

**Backed by:** `windows_privesc_hijack.fp_rule.auto.derived`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "Trace service startup with Procmon to catch DLLs that are tried and no" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 2. Exercise it against the target and capture the raw request and response: Reject a windows_privesc_hijack finding until it is distinguished from the adjacent behaviour this class also covers. "Trace service startup with Procmon to catch DLLs that are tried and not found, then check whether a user-writable directory sits in the...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `windows_privesc_hijack.fp_rule.auto.derived2`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The hijack condition is a more-privileged process failing to find a DL" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: For an unpackaged application on the standard search order, the system PATH is consulted only after redirection, API sets, SxS, the loaded-module list, KnownDLLs, the application and Windows directories, and the current directory all fail, which narrows...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `windows_privesc_hijack.prerequisite.raw_for_an_unpackaged_application_usin`

**This step fails if:** The target is a packaged application using redirection or API sets, so the system PATH is never reached.
