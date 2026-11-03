# GraphQL

## What this directory represents

One endpoint, one schema, many resolvers. Authorization must hold per resolved
field rather than per route, and one request can carry many operations.

## What belongs inside it

`../../../topics/graphql/introspection.md`, `../../../../skills/api/rest/topics/authorization.md`, `../../../idor/CLASS.md`, `../../../topics/graphql/batching.md`,
`../../../topics/graphql/alias-abuse.md`, `../../../topics/graphql/query-complexity.md`, `../../../../skills/api/graphql/topics/injection.md`.

`../../../../skills/api/rest/topics/authorization.md`, `../../../idor/CLASS.md` and `../../../../skills/api/graphql/topics/injection.md` are **pointers** — the
canonical homes are `../../web/authorization/`, `../../web/injection/`.

## What does NOT belong inside it

- The general exposure problem → `../../learning/knowledge/`
- Node-ID decoding as a technique → it is a `../../../idor/CLASS.md` variant here and a
  technique in the canonical class

## How children are organised

By what the schema lets you do that REST does not: enumerate it
(`../../../topics/graphql/introspection.md`), resolve more than the UI asked for (`../../../../skills/api/rest/topics/authorization.md`,
`../../../idor/CLASS.md`), multiply one request (`../../../topics/graphql/batching.md`, `../../../topics/graphql/alias-abuse.md`), or make it
expensive (`../../../topics/graphql/query-complexity.md`).

## Related bug classes

`../../attack-chains/api-chains.md` — excessive exposure chains directly into
enumeration and mass assignment, because read and write share one missing check.

## How new entries should be added

Only for a capability inherent to the GraphQL surface. A REST-only flaw is not a
GraphQL class.
