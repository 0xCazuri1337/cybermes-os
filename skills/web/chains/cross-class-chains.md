# Shared-cache key omission to cross-user session compromise

## Objective

Goal: **account_takeover**.

A shared cache keyed on method and URI alone stores one requester's personalised response under a key other users request, delivering the wrong principal's session context.

## Preconditions

1. Two authenticated sessions and an Age or cache-hit header on a repeat fetch
2. A personalised page whose body varies on a reflected header or an unkeyed path suffix
3. A second, unrelated authenticated session to diff the response against
4. A victim session issuing a real request to the poisoned URI

## Initial Weakness

**Step 1.** Confirm a shared intermediary cache stores responses for reuse by more than one user on the target path, which is the precondition behind cache_deception.prerequisite.shared_intermediary_cache_in_front_of_origin.

- Why: A private cache is dedicated to a single user and is often deployed inside the user agent, so without a shared store no entry can ever be served to a second principal.

## Chain Steps

**1. `None` — Confirm a shared intermediary cache stores responses for reuse by more than one user on the target path, which is the precondition behind cache_deception.prerequisite.shared_intermediary_cache_in_front_of_origin.**

- Why: A private cache is dedicated to a single user and is often deployed inside the user agent, so without a shared store no entry can ever be served to a second principal.
- Requires: Two authenticated sessions and an Age or cache-hit header on a repeat fetch

**2. `None` — Identify an input the origin honours but the cache key ignores, so a poisoned response is stored under a key other users will request, which is the mechanism in cache_deception.technique.unkeyed_reflection_below_a_dynamic_segment_becomes_a_shared_key.**

- Why: The cache key is composed from, at a minimum, the request method and target URI; caches differentiate content-negotiated responses only by request header fields named in Vary, so anything outside that set is invisible to the cache.
- Requires: A personalised page whose body varies on a reflected header or an unkeyed path suffix

**3. `None` — Request the poisoned URI, let the cache store it, then fetch the clean URI from an unrelated session and confirm the first session's rendered body is returned.**

- Why: Web cache poisoning leads otherwise unexploitable vulnerabilities to be weaponized against a massive number of victims, and a reflected weakness becomes a dangerous stored one once the cache serves the poisoned response to other users.
- Requires: A second, unrelated authenticated session to diff the response against

**4. `None` — Escalate the delivered content into session compromise if the replayed body carries a session identifier, a CSRF token bound to the attacker's session, or script that executes in the victim's origin context.**

- Why: The replayed response is generated inside the victim's authenticated request by the origin, so anything the origin embeds for the attacker's session arrives already scoped to the wrong principal.
- Requires: A victim session issuing a real request to the poisoned URI

## Required Conditions

- Two authenticated sessions and an Age or cache-hit header on a repeat fetch
- A personalised page whose body varies on a reflected header or an unkeyed path suffix
- A second, unrelated authenticated session to diff the response against
- A victim session issuing a real request to the poisoned URI

## Impact

The impact is bounded by nothing the victim's session could do, because the delivered content is generated inside the victim's authenticated request by the origin and merely replayed from the wrong stored entry; a single poisoned request converts a self-only reflection into compromise of every later visitor to that URI.

## Detection Strategy

Not yet researched.

## Validation

Not yet researched.

## Real-World Examples

Not yet researched.

## Related Bug Classes

- `None`

## References

Not yet researched.
