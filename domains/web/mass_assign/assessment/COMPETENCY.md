# Methodology — Mass Assignment / Excessive Data Exposure

> Derived from 8 verified items. Regenerate with `python -m wks.methodgen --class mass_assign --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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


## 2. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A convincing mass-assignment proof is a successful response paired with a readback showing the privileged field changed — a follow-up GET, or the object returned by the same request echoing the new value — because a 2xx on its own does not show the attribute reached the database.**

Mechanism: A convincing mass-assignment proof is a successful response paired with a readback showing the privileged field changed — a follow-up GET, or the object returned by the same request echoing the new value — because a 2xx on its own does not show the attribute reached the database. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band channel (a second account observing the change, an email or webhook triggered by the field, or a database log), and without one the finding is unproven rather than disproven.

- *Disproof:* The claim is false when the endpoint has no read path available to the tester and the response body never echoes model state; there the evidence must come from an out-of-band channel (a second account observing the change, an email or webhook triggered by the field, or a database log), and without one the finding is unproven rather than disproven.
- *Evidence:* high_confidence — [laravel.com](https://laravel.com/docs/eloquent); [symfony.com](https://symfony.com/doc/current/forms.html)

## 3. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Sending a privileged field and seeing it unchanged is a false mass assignment: the request schema whitelist dropped the field before the handler ran.**

Discard the finding when a single request carrying the privileged field and one benign field shows the benign field applied and the privileged field silently ignored, because a typed request schema validated the body before the handler and never handed it the extra key. The finding survives when the privileged field actually changed in server state, verified by reading it back from a second session rather than from the response that echoed your request back to you.

- *Disproof:* If the response echoes your submitted privileged value while the database column is untouched, the 200 you saw is your own input reflected, not confirmation of assignment, and the report must be re-run against committed state before it counts.
- *Evidence:* high_confidence — [httpwg.org](https://httpwg.org/specs/rfc9110.html); [projectdiscovery.io](https://projectdiscovery.io/blog/inside-the-benchmark-pp-architectures-finding-walkthroughs-and-what-each-scanner-actually-caught)

**An API that accepts a body containing fields it does not know is not automatically vulnerable: the finding only exists once a submitted field maps to a server-side attribute the caller must not control, typically an ownership, role, price or verification flag.**

Mechanism: An API that accepts a body containing fields it does not know is not automatically vulnerable: the finding only exists once a submitted field maps to a server-side attribute the caller must not control, typically an ownership, role, price or verification flag. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a denormalised duplicate used for authorisation — in which case the same unexpected field is already attacker-controlled and produces an effect even without touching the protected column.

- *Disproof:* The rule is wrong when the ignored field is not simply inert — for example it feeds a logging/audit sink, a cache key, a search index, a downstream webhook payload, or a denormalised duplicate used for authorisation — in which case the same unexpected field is already attacker-controlled and produces an effect even without touching the protected column.
- *Evidence:* high_confidence — [laravel.com](https://laravel.com/docs/eloquent); [symfony.com](https://symfony.com/doc/current/forms.html)

**A submitted field that the framework silently discards — because it is absent from the model's fillable list — is not a mass-assignment finding; the mass-assignment defect requires the unexpected field to actually change persisted state or a privilege-bearing attribute.**

Mechanism: A submitted field that the framework silently discards — because it is absent from the model's fillable list — is not a mass-assignment finding; the mass-assignment defect requires the unexpected field to actually change persisted state or a privilege-bearing attribute. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the attribute on a different code path (a fillable check that is bypassed for nested JSON keys, or a direct column write outside the mass-assignment call), in which case the same request that looks discarded in one flow mutates state in another.

- *Disproof:* The rule is wrong when the discarded-attribute behaviour is a development-only diagnostic that is switched off in production, or when the framework logs and then applies the attribute on a different code path (a fillable check that is bypassed for nested JSON keys, or a direct column write outside the mass-assignment call), in which case the same request that looks discarded in one flow mutates state in another.
- *Evidence:* high_confidence — [laravel.com](https://laravel.com/docs/eloquent); [symfony.com](https://symfony.com/doc/current/forms.html)

**Filtering a known list of role field names such as isAdmin, admin or role is not a mass-assignment fix; an allowlist must be enforced server-side.**

A handler that drops a handful of well-known privileged keys is trivially defeated by renaming the attribute, since the guessable-name list is public. Test by sending the same privilege intent under several plausible alternate names and confirming that none of them persists. The durable check is whether an explicit allowlist of permitted fields is applied before the model is constructed, not whether a denylist of role words exists somewhere in the code. If the framework performs strict schema validation with unknown keys rejected, that is the real control and the finding does not hold.

- *Disproof:* If every alternate field name is rejected by strict schema validation that errors on unknown keys, and only allowlisted fields ever reach the model, the blocklist concern is moot.
- *Evidence:* high_confidence — [bishopfox.com](https://bishopfox.com/blog/design-considerations-for-secure-graphql-apis); [snyk.io](https://snyk.io/blog/avoiding-mass-assignment-node-js/)

## 4. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A fillable/guarded allowlist is only a defence as strong as its contents: because the allowlist is an explicit enumeration of attribute names, a single over-broad entry (a whole table of columns, a prefix pattern, or a nested JSON path that includes a privileged sub-key) re-opens mass assignment without weakening the mechanism itself.**

Mechanism: A fillable/guarded allowlist is only a defence as strong as its contents: because the allowlist is an explicit enumeration of attribute names, a single over-broad entry (a whole table of columns, a prefix pattern, or a nested JSON path that includes a privileged sub-key) re-opens mass assignment without weakening the mechanism itself. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the mass-assignment path never reaches, so the over-broad entry still cannot set it.

- *Disproof:* The rule is false when the privileged field is stored in a different model or table from the allowlisted one, or when the ORM writes it through a dedicated setter that the mass-assignment path never reaches, so the over-broad entry still cannot set it.
- *Evidence:* high_confidence — [laravel.com](https://laravel.com/docs/eloquent); [symfony.com](https://symfony.com/doc/current/forms.html)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Preconditions, Test sequence, Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
