# windows_privesc_service: observe, exercise, confirm

> goal: `Establish, exercise and confirm a windows_privesc_service condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for windows_privesc_service. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a windows_privesc_service condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Hypothesis under test: Because FILE_CREATE_PIPE_INSTANCE shares its access bit with FILE_APPEND_DATA, a low-privilege user can squat a second server instance under a privileged pipe's name and, since...

**Requires:** an authorised target with a reachable surface for windows_privesc_service, and permission to record responses

**Backed by:** `windows_privesc_service.fp_rule.auto.derived2`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 2. Exercise it against the target and capture the raw request and response: Reject a windows_privesc_service finding until it is distinguished from the adjacent behaviour this class also covers. "The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `windows_privesc_service.fp_rule.auto.derived`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "The Terminal Services RPC named pipe \pipe\LSM_API_service is itself a" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: The complete named-pipe client impersonation chain requires both SeImpersonatePrivilege and a privileged client such as a SYSTEM service that will connect to an attacker-created pipe, after which the resulting token is duplicated into a primary token for the...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `windows_privesc_service.technique.raw_in_practice_an_attacker_who_can_r`

**This step fails if:** SeImpersonatePrivilege is absent, or no privileged client can be coerced to connect to a rogue pipe instance.
