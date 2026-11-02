# Methodology — Mass Assignment / Excessive Data Exposure

> Derived from 3 verified items. Regenerate with `python -m wks.methodgen --class mass_assign --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** The server binds client-supplied fields straight onto a model, so a client can set properties the UI never exposes — including privilege fields.

**References.** CWE-915 · API3:2023

## Preconditions

_No verified prerequisite items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 1. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A registration or update POST whose body is bound wholesale to the model is exploitable the moment the body carries an extra role or flag field.**

Look for endpoints where the entire request body is passed to the model constructor or an ORM create/update call with no field allowlist; that is the precondition. Replay a legitimate request with one additional key whose name is a plausible role or verification flag, and watch both the response and any subsequent authenticated read of the record. Also probe with a truthy non-boolean value, because frameworks frequently coerce any non-empty string into true for boolean-typed attributes. Roles that survive the write are the finding; roles echoed back in the response without persisting are not.

- *Disproof:* If the added field is silently dropped on write and never appears in any later authenticated read of the record, the endpoint filters the input and mass assignment is not present.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis); [snyk.io](https://snyk.io/blog/avoiding-mass-assignment-node-js/)

## Test sequence

_No verified technique items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Validation

_No verified validation items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 2. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.**

Discard the finding when a single request carrying the privileged field and one benign field shows the benign field applied and the privileged field silently ignored, because a typed request schema validated the body before the handler and never handed it the extra key. The finding survives when the privileged field actually changed in server state, verified by reading it back from a second session rather than from the response that echoed your request back to you.

- *Disproof:* If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.**

A handler that drops a handful of well-known privileged keys is trivially defeated by renaming the attribute, since the guessable-name list is public. Test by sending the same privilege intent under several plausible alternate names and confirming that none of them persists. The durable check is whether an explicit allowlist of permitted fields is applied before the model is constructed, not whether a denylist of role words exists somewhere in the code. If the framework performs strict schema validation with unknown keys rejected, that is the real control and the finding does not hold.

- *Disproof:* If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis); [snyk.io](https://snyk.io/blog/avoiding-mass-assignment-node-js/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Test sequence, Validation, Known bypasses, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
