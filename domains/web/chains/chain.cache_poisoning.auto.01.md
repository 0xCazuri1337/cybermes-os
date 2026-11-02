# cache_poisoning: observe, exercise, confirm

> goal: `Establish, exercise and confirm a cache_poisoning condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for cache_poisoning. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a cache_poisoning condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: A response that echoes an unkeyed header or parameter back to the requester is ordinary reflection; web cache poisoning requires a second request with a different cache key to be served the injected value out of the cache.

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: The observation is a header or query parameter reflected into the response body without appearing in the cache key, which is the precondition for a family of attacks that includes unkeyed header...

**Requires:** an authorised target with a reachable surface for cache_poisoning, and permission to record responses

**Backed by:** `cache_poisoning.fp_rule.unkeyed_reflection_without_second_keyed_request_is_not_poisoning`

**This step fails if:** A second request carrying a different cache key and none of the injected input is served a response containing the primed header or parameter value, proving the value crossed from one client's request into another client's cached response.

### 2. Exercise it against the target and capture the raw request and response: A reflected value on a response that the cache is never told to store (no-store/private, or a Vary/keying that always separates the responses) is not web cache poisoning: poisoning requires a shared cache to store the attacker's response and serve it to a...

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `cache_poisoning.fp_rule.reflected_value_served_no_store_or_uncacheable_is_not_poisoning`

**This step fails if:** It IS poisoning when the attacker-supplied value is stored and then replayed verbatim to an independent victim request that did not send it - evidenced by a second request (fresh client, no attacker header) returning the attacker's payload, or an Age/X-Cache hit on an entry seeded by the attacker's request. The second, uncorrupted request is the whole test.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: Confirm poisoning by replaying a clean request from a fresh session and checking the malicious body is served until the entry's freshness lifetime expires.

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `cache_poisoning.validation.replay_and_ttl`

**This step fails if:** If a clean request from a fresh session receives the original unmodified body, or the poisoned body disappears immediately, nothing was stored and there is no poisoning.
