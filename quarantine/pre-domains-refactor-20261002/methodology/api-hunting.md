# API hunting — entry point

The ordered approach for an API target. The classes are mostly the same as web;
what differs is **where the authorization decision is made**.

## Order

1. **Map the surface** — every route, verb and content type. The verb is part
   of the authorization decision, so a gateway rule on `POST` is not a rule on
   `PATCH`. Test `X-HTTP-Method-Override`, `_method`, and a form-encoded replay
   of a JSON mutation.
2. **Authentication** — [authentication.md](authentication.md). Note where the
   credential travels: a header leaks differently from a cookie.
3. **Authorization, by granularity** — object-level
   ([idor.md](idor.md)) and function-level
   ([function-level-authorization.md](../bug-classes/web/authorization/function-level-authorization.md))
   are different checks in different places.
4. **Schema-bound binding** —
   [mass-assignment.md](../bug-classes/api/rest/mass-assignment.md) and
   [excessive-data-exposure.md](../bug-classes/api/rest/excessive-data-exposure.md).
5. **Resource consumption** — [rate-limit.md](../bug-classes/api/rest/rate-limit.md).
6. **Non-REST shapes** — [graphql/](../bug-classes/api/graphql/README.md),
   [websocket/](../bug-classes/api/websocket/README.md).

## API-specific rules

- Every object-level claim needs **two accounts you control**, fully separated.
- Identifiers come from responses, not from arithmetic.
- A field the frontend never requests may still resolve — the omission is not an
  authorization control.

## Related

- Classes: [`skills/Web/areas/api/`](../skills/Web/areas/api/README.md)
- Chains: [`api-chains.md`](../attack-chains/api-chains.md)