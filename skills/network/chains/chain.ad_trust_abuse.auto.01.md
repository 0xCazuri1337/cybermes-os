# ad_trust_abuse: observe, exercise, confirm

> goal: `Establish, exercise and confirm a ad_trust_abuse condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for ad_trust_abuse. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a ad_trust_abuse condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: No cross-domain attack path can be evaluated until trust direction and SID filtering state are recorded per trust, because a one-way trust and a two-way trust produce the same graph edge while carrying opposite reachability.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Prerequisite: before scoring any privilege-escalation or lateral-movement claim that crosses a domain boundary, establish two facts for every trust object. First, direction and transitivity: one-way...

**Requires:** an authorised target with a reachable surface for ad_trust_abuse, and permission to record responses

**Backed by:** `ad_trust_abuse.prerequisite.trust_direction_and_sid_filtering_before_any_privilege_path`

**This step fails if:** The trust object is not in scope for the path at all, or the path stays entirely inside a single domain, in which case trust direction and SID filtering cannot be the enabling condition and a different mechanism must be named.

### 2. Exercise it against the target and capture the raw request and response: Testing whether the requesting principal actually holds domain replication rights, and whether the requesting host is a domain controller, separates a replication-credential abuse attempt from ordinary replication traffic.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `ad_trust_abuse.validation.replication_rights_check_separates_dcsync_from_legitimate_replication`

**This step fails if:** The requesting host is a domain controller and the requesting principal is an account legitimately entrusted with replication rights for that domain, with a matching service or backup schedule behind the traffic, in which case the requests are ordinary replication and the abuse hypothesis fails.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: A trust object that exists in configuration but shows no authentication traffic crossing it is a legacy or planned architecture relationship, not trust abuse.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `ad_trust_abuse.fp_rule.configured_but_never_traversed_trust_is_architecture_not_abuse`

**This step fails if:** Authentication traffic does cross the trust in the retention window, or a principal in the trusted domain is being accepted by a resource in the trusting domain, in which case the trust is in active use and must be assessed as a live cross-domain path rather than as dormant architecture.
