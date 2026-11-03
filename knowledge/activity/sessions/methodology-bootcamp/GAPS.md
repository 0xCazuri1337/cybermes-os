# GAP — C3 class selection is structurally incomplete (measured 2026-10-03)

## What was measured

`orch.hypothesis.classify_behaviour()` is the class-selection path. It is
CORRECT for what it covers: 8/8 probe cases classified correctly, including two
that correctly refused (a novel behaviour and an ambiguous csrf/csrf_bypass tie
returned UNKNOWN with a reason, never a guess). The ambiguity refusal is
§30 working as designed.

The defect is COVERAGE, not correctness.

## Finding 1 — 55 of 70 corpus classes are unselectable by observation

```
corpus classes             : 70
classes in SIGNATURES      : 20
UNSELECTABLE by observation: 55
```

An entire target can be mapped — a full AD environment, a JWT/OAuth stack, an
SMB/credential-attack surface — and the classifier returns UNKNOWN for all of
it, because the signals have no declared signature. `jwt`, `oauth`, `smb`,
`ldap`, `rate_limit`, `file_upload`, `cmd`, `clickjacking`, `subdomain_takeover`,
`crlf`, `websocket`, `cache_poisoning`, `prototype_pollution`, `supply_chain`
and 41 more are invisible to observation-driven selection.

## Finding 2 — 5 signature keys name classes that DO NOT EXIST in the corpus

```
auth            -> not registered   near: authn, authz, oauth
business_logic  -> not registered   near: (none)
csrf_bypass     -> not registered   near: csrf
nosqli          -> not registered   near: nosql, sqli
request_smuggling -> not registered near: smuggling
```

So `classify_behaviour()` can RETURN a class id that no page, no chain, no skill
and no methodology exists for. A hunt that selected `auth` would look correctly
classified while pointing at nothing.

**Only 15 of 70 corpus classes are actually reachable by observation.**

## Finding 3 — the coverage gap is invisible in every count that exists

`wks.cli gaps` measures corpus maturity. `masterprompt_score.py` measures engine
enforcement. `wks.mastery status` measures gates. None of them measures
"can this class ever be selected from a target?". Nothing went red when the 5
phantom keys were introduced, and nothing goes red now. This is the same shape as
the measured lesson *"a filter that matches nothing returns a clean, confident,
EMPTY report"* — a missing check reads exactly like health.

## Why this matters to the session GOAL

C3 requires choosing the right classes from target observations alone. Against
this baseline, the correct class set is available for 15 of 70 classes. The fix
is not to loosen the classifier — it is to close the coverage, and then assert
the closure with a test that can FAIL.

## Next subgoal

1. Map every unregistered SIGNATURES key to the real corpus class that owns the
   behaviour, and record why in a comment (never guess; measure).
2. Extend SIGNATURES for the highest-value unselectable classes, prioritised by
   corpus size — `jwt` (30 items), `oauth` (33), `smuggling` (34), `file_upload`
   (32), `subdomain_takeover` (35), `host_header` (24), `session` (21),
   `cmd` (27).
3. Write `eval/test_hunt_classification.py` asserting BOTH directions:
   - a real signal set for each declared class selects that class (PASS case)
   - a deliberately wrong signal set does NOT select it (FAIL case, so the
     check cannot pass by disabling matching)
   - every class selected is REGISTERED in `bug_class` (kills Finding 2)
   - no class is unselectable without a stated reason (kills Finding 3)

## Boundary

Read-only so far — nothing was written to `orch/hypothesis.py`. This gap is
recorded here and in `learning/sessions/methodology-bootcamp/GOAL.md`; the fix
is a later wave, after wave 1 lands.