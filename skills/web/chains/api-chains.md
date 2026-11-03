# sqli-boolean-oracle-to-row-count-enumeration

## Objective

Goal: **data_disclosure**.

A blind boolean SQL injection in a sort or comparison parameter is used as a two-valued oracle to reconstruct a column value one character at a time without ever returning it in the response.

## Preconditions

1. an injectable parameter that produces a visible, stable, two-valued difference between a true and a false condition
2. an oracle that survives repeated sampling
3. a working oracle, a position-extraction expression, and a character range to search
4. knowledge of which tables hold credentials or sessions, and an authentication endpoint to test the recovered values against

## Initial Weakness

**Step 1.** Establish a boolean oracle: find a parameter where a true condition returns a measurably different response than a false condition, using a differential response such as row count, ordering, or a matching row.

- Why: Everything after this step depends on having a two-valued signal. Without a reliable oracle the attacker can only confirm that a payload changes behaviour, not extract data from it.

## Chain Steps

**1. `sqli` — Establish a boolean oracle: find a parameter where a true condition returns a measurably different response than a false condition, using a differential response such as row count, ordering, or a matching row.**

- Why: Everything after this step depends on having a two-valued signal. Without a reliable oracle the attacker can only confirm that a payload changes behaviour, not extract data from it.
- Requires: an injectable parameter that produces a visible, stable, two-valued difference between a true and a false condition

**2. `sqli` — Measure the baseline variance of the oracle first by repeating both the true and false condition many times, confirming the signal is not produced by caching, rate limiting or connection reuse.**

- Why: Caches, WAF rate limits and connection pooling all produce response differences that mimic a boolean oracle. Building extraction on an unverified signal yields a long, slow extraction of pure noise.
- Requires: an oracle that survives repeated sampling

**3. `sqli` — Binary-search each character position with a comparison expression, using the oracle response to determine whether the guessed character is above or below the true value, repeating until the whole value is recovered.**

- Why: Binary search reduces the number of requests per character from a full character-set sweep to a logarithmic number, which keeps the extraction inside rate limits and makes it complete in a usable time.
- Requires: a working oracle, a position-extraction expression, and a character range to search

**4. `info_disclosure` — Repeat the extraction against the credential or session tables, and test whether any recovered value is accepted by an authentication endpoint elsewhere in the application.**

- Why: Recovered data only becomes impact when it is used. A database read that discloses password hashes escalates to account takeover if any endpoint accepts them, and discloses session material directly if sessions live in the same store.
- Requires: knowledge of which tables hold credentials or sessions, and an authentication endpoint to test the recovered values against

## Required Conditions

- an injectable parameter that produces a visible, stable, two-valued difference between a true and a false condition
- an oracle that survives repeated sampling
- a working oracle, a position-extraction expression, and a character range to search
- knowledge of which tables hold credentials or sessions, and an authentication endpoint to test the recovered values against

## Impact

The attacker reconstructs arbitrary data from tables the application can read, including credentials, without producing a single error or any visible injected value.

## Detection Strategy

Not yet researched.

## Validation

Not yet researched.

## Real-World Examples

Not yet researched.

## Related Bug Classes

- `info_disclosure` — canonical: [`skills/web/info_disclosure/CLASS.md`]
- `sqli` — canonical: [`skills/web/sqli/CLASS.md`]

## References

Not yet researched.
