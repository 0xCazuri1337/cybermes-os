# Severity

Severity is a claim about **impact**, and it is the easiest part of a report to
get wrong in either direction.

## The rule

Severity follows from what you **demonstrated**, not from what the flaw could
theoretically enable. An unproven escalation chain is not a high-severity IDOR;
it is an IDOR with a note attached.

## Factors, in the order they matter

1. **What crosses the boundary** — data read, data written, or a capability
   gained. Integrity loss and account takeover outrank confidentiality loss at
   equal reach.
2. **Who can do it** — unauthenticated, any authenticated user, or a privileged
   user. Requiring authentication lowers severity; note that this is a property
   of the *flaw*, not a mitigation you implemented.
3. **Reach and scale** — one record, one tenant, or enumerable across the
   installation. State the enumeration argument separately from the demonstrated
   scope.
4. **Prerequisites** — a race needs concurrency; SSRF needs a reachable internal
   target. State the prerequisite in the impact; do not discount it silently.

## Two corrections that are routinely needed

- **Quantified scope beats adjectives.** "Enumerated cross-tenant records per
  account class and per operation" survives triage. "Severe" does not.
- **Do not claim bulk extraction you did not perform.** The demonstrated record
  count is the finding; extrapolation is labelled as extrapolation.

## Chain severity

Report the primitive and the chain as two things. A race condition that lets a
coupon apply ten times is not a financial bug until you show discounted orders
that shipped. The chain raises severity; it does not replace the proof.

## Related

- [report-structure.md](report-structure.md)
- [evidence-requirements.md](../validation/evidence-requirements.md)
- [business-logic-chains.md](../domains/web/chains/business-logic-chains.md)