# Methodology — IDOR / BOLA (Object-Level Authorization)

> Generated 2026-10-01T18:41:23Z. Competency id: `idor`.
> Aligned with `CONTROL/CONTROL.md` §4 (separation of claims) and
> `CONTROL/rules.md` R2 (scanner output is an observation, not proof).

## What this establishes

A subset of authorization failures where the object reference itself crosses a boundary. Highest-yield API finding and the most frequently mis-validated.

## Procedure

 1. **Enumerate object references** — IDs in paths, bodies, and GraphQL selections. Note the pattern: sequential, UUID,
opaque, or composite.
 2. **Determine predictability** — Sequential integers mean the object space is enumerable; opaque ids mean you must obtain
a foreign id by another route.
 3. **Obtain a foreign identifier legally** — From a second account you legitimately control, or from an endpoint that discloses it.
Never take identifiers from a third party.
 4. **Replay under the lower-privilege session** — Substituting only the identifier.
 5. **Differentiate 404 from 403** — 403 means the object exists and is refused — that is existence disclosure. 404 may be
concealment. Both are reportable, differently.
 6. **Check for field-level leakage** — A partial response can still disclose PII even when the object body is refused.
 7. **Check write paths too** — PUT/PATCH/DELETE are frequently guarded less carefully than GET.
 8. **Check mass-assignment adjacency** — If the object accepts a user-supplied owner field, ownership itself is writable.
 9. **Confirm against the negative control** — Your own object must still be accessible to you. If it is not, the test is invalid.
10. **Assess impact honestly** — Read one record to prove access. Do not enumerate the whole set.

## What would disprove the hypothesis

A finding here is wrong if any of the following holds. Check them before
reporting, and record which one applied.

- The identifier is bound to the session server-side and substitution fails.
- The response is identical for existing and non-existent ids (no disclosure).
- The object does not belong to a different principal.

## Gates before this becomes a finding

- two distinct principals
- identifier varied alone
- access demonstrated on a read that should have been refused

## Authority

`CONTROL/CONTROL.md` outranks this page. If this procedure suggests an action
outside the recorded scope, the scope wins — see `CONTROL/state.md`.

Tools are sensors. A tool that reports a finding here has satisfied none of
the gates above by itself.
