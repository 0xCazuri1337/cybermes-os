# windows_privesc_token: observe, exercise, confirm

> goal: `Establish, exercise and confirm a windows_privesc_token condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for windows_privesc_token. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a windows_privesc_token condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Hypothesis under test: After alternate credentials are supplied, whoami can still show the original local user and groups while outbound SMB, WinRM, LDAP, HTTP, Kerberos or NTLM access happens as the...

**Requires:** an authorised target with a reachable surface for windows_privesc_token, and permission to record responses

**Backed by:** `windows_privesc_token.fp_rule.auto.derived`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A failed potato-family run against a service account is often a filter" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 2. Exercise it against the target and capture the raw request and response: Reject a windows_privesc_token finding until it is distinguished from the adjacent behaviour this class also covers. "A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `windows_privesc_token.fp_rule.auto.derived2`

**This step fails if:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "SeImpersonatePrivilege lets a process impersonate any token it can get" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A failed potato-family run against a service account is often a filtered-token problem rather than a patched host: without SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege present, the account's default privilege set must be restored before retrying.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `windows_privesc_token.prerequisite.raw_modern_operator_notes_juicypot`

**This step fails if:** The token already lists both privileges and the potato run still fails to yield a SYSTEM process.
