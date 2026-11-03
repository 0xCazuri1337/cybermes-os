# linux_privesc: observe, exercise, confirm

> goal: `Establish, exercise and confirm a linux_privesc condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for linux_privesc. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a linux_privesc condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Hypothesis under test: Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object...

**Requires:** an authorised target with a reachable surface for linux_privesc, and permission to record responses

**Backed by:** `linux_privesc.fp_rule.auto.derived`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "If sudoers grants broader privileges on a named host that is neither t" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 2. Exercise it against the target and capture the raw request and response: Reject a linux_privesc finding until it is distinguished from the adjacent behaviour this class also covers. "If sudoers grants broader privileges on a named host that is neither the current hostname nor ALL, that host identity can be spoofed locally with...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `linux_privesc.fp_rule.auto.derived2`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A process whose euid differs from its ruid is evidence that a set-user" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Comparing an object's resolution with and without ldconfig's --inhibit-cache --list proves whether /etc/ld.so.cache, rather than an ordinary search-path rule, chose the object.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `linux_privesc.test.raw_compare_that_output_with_inhibit`

**This step fails if:** The resolved object list is identical with and without the cache, so no cache-based selection occurred.
