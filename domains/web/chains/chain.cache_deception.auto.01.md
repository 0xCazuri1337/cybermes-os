# cache_deception: observe, exercise, confirm

> goal: `Establish, exercise and confirm a cache_deception condition on an authorised target without relying on anyone else's data.`
> generated from `db/wks.db` — edit the rows, not this file

A three-step single-class chain for cache_deception. Each step is grounded in a gated knowledge item from this class rather than asserted, so the chain records what the corpus actually supports.

## Impact

Proves a cache_deception condition is present and reproducible, which is the minimum for a reportable finding.

## Sequence

### 1. Establish the precondition and record the baseline: When a shared cache keys only on method and target URI and the origin varies a personalised page on an unkeyed input, one attacker-requested URI stores the attacker's own rendered session for every later visitor, converting a cache-key weakness into...

**Why it works:** Without a recorded baseline you cannot show what changed, and the later steps have nothing to compare against. Source context: Three published facts compose into the chain. First, the shared-store precondition: a cache sits between the client and the web server and serves the same resource from local storage on subsequent...

**Requires:** an authorised target with a reachable surface for cache_deception, and permission to record responses

**Backed by:** `cache_deception.chain_link.cached_personal_response_to_cross_user_session_takeover`

**This step fails if:** The chain is refuted if any link fails: the deployment has no shared cache in front of the personalised path, so the stored copy never reaches a second user; the response carries Cache-Control: private or Set-Cookie with no-store, which stops the shared tier storing it; Vary correctly names the unkeyed input and the cache honours it, splitting the stored responses by that header; or the personalised page carries no session-dependent content, so the second visitor receives an identical body and nothing is disclosed. Demonstrate the cross-identity read before asserting takeover.

### 2. Exercise it against the target and capture the raw request and response: Web cache deception requires a shared intermediary cache sitting between the client and the origin, because a browser-local cache is dedicated to one user and can never hand one identity's response to another.

**Why it works:** In this class the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, which is why it is worth exercising directly. An exercise without a captured raw request and response is an opinion.

**Requires:** two accounts or two privilege levels you control, and a repeating request you can diff

**Backed by:** `cache_deception.prerequisite.shared_intermediary_cache_in_front_of_origin`

**This step fails if:** The claim is wrong, and no shared cache is in front of the path, if: every response to the authenticated request carries a restrictive Set-Cookie directive and no Age or cache-hit header on any fetch; a second, unrelated user session receives their own distinct personalised body rather than the first user's; or the origin is reached directly with no intermediary hop visible in response headers, timing, or server configuration, so nothing outside the browser holds a copy. Any of those removes the shared-store precondition the whole class rests on.

### 3. Confirm the result reproduces and crosses the boundary you claim, using only accounts you own: When a cache keys only on method and target URI while the origin varies its response on an unkeyed request header or a path segment below a dynamic one, requesting an attacker-chosen suffix under a victim-visible URI stores the attacker's personalised body...

**Why it works:** Here the corpus records no numeric evidence score for this item, so treat it as a lead to exercise rather than a proven behaviour, and confirmation is what separates a reportable finding from a theoretical one. Using only your own accounts keeps the test inside authorised scope while still proving the boundary is missing.

**Requires:** the captured evidence from the previous step, and a second run proving it is not a one-off

**Backed by:** `cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key`

**This step fails if:** The claim is wrong, and this is not cache deception, if the origin refuses or strips the unkeyed input rather than reflecting it into the body; the response carries a Vary that includes the reflected header and the cache honours it, so the poisoned response is stored under a different key; the response carries Cache-Control: private or no-store, or the request carried a session the shared cache refuses to store; the canary never reappears on a clean fetch from a second session; or the appended path suffix is routed by the origin to a handler that ignores the dynamic segment entirely. Reproduce the cross-identity read before calling it deception.
