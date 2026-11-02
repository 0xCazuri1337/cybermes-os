# Authorization — proving *what you may touch*

## What this directory represents

Flaws where the subject is correctly identified and the wrong decision is still
made about an object or a function.

## What belongs inside it

- Object-level: `idor.md` (**canonical for IDOR/BOLA**)
- Vertical: `privilege-escalation.md`
- Function-level: `function-level-authorization.md`
- The multi-tenant boundary: `tenant-isolation.md`

## What does NOT belong inside it

- Being the wrong user → `../authentication/`
- The same IDOR seen through GraphQL or REST → pointer stubs under `../../api/`
- Chaining an authorization bug into takeover → `../../attack-chains/authorization-chains.md`

## How children are organised

By the *granularity* of the decision that failed: object, function, role,
tenant. Each is a separate check in a separate place in the code.

## Related bug classes

`../injection/` (a session token read out of a page) and `../business-logic/`
(state transitions that skip an approval) both reach this directory.

## How new entries should be added

Check `idor.md` first — most "new" authorization classes are a granularity of
it. Only add a file when the missing check has no existing home.
