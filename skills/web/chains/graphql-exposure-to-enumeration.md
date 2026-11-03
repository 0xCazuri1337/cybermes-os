# GraphQL excessive exposure to account enumeration to mass assignment

> goal: `data_exposure`
> generated from `db/wks.db` — edit the rows, not this file

One flexible endpoint removes the per-route authorization that REST provides for free, so fields the UI never requests are still resolved — and the same resolver often writes whatever the selection set contains.

## Impact

Bulk enumeration of user records, escalating to modification of protected fields such as role or email.

## Sequence

### 1. Confirm a single query endpoint accepting a JSON body

**Why it works:** Without one universal resolver path there is no shared authorization gap to exploit.

**Backed by:** `graphql.prereq.single_universal_endpoint`

**This step fails if:** Every candidate path returns HTML, 404, or a JSON error with no __typename key, meaning no GraphQL service is mounted there.

### 2. Enumerate the schema, then request a field the frontend never asks for on an object you already own

**Why it works:** A field returning for an object you are entitled to shows the resolver has no field-level check, which is the mechanism.

**Backed by:** `graphql.signal.universal_query_and_schema_fields`

**This step fails if:** Both primitives return an error such as "query not present" or "Cannot query field __schema" with no data object, indicating no GraphQL schema is exposed there.

### 3. Extend the selection set with the protected fields and confirm they resolve

**Why it works:** The frontend omitting a field is not an authorization control; the server must reject it regardless.

**Backed by:** `graphql.bypass.frontend_only_field_authz`

**This step fails if:** The hidden field is returned as null or the request errors regardless of method, alias, or transport, so the resolver itself enforces field-level authorization.

### 4. Chain the exposed fields into enumeration and then a write, if the mutation accepts arbitrary properties

**Why it works:** Read and write share the missing check, so one gap commonly yields both.

**Backed by:** `graphql.chain.exposure_to_enumeration_to_mass_assignment`

**This step fails if:** The enumeration batch errors or returns nulls for other users' ids, and every guessed sensitive input field is rejected by the resolver or ignored by the model.
