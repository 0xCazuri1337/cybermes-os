# IDOR / BOLA — Topical Reference

Promoted topical reference for Insecure Direct Object Reference / Broken Object Level Authorization in APIs.

## Focus

- Numeric, UUID, and GraphQL global ID (GID) object identifiers.
- Cross-account and cross-tenant access.
- Mutation arguments that select source/destination objects.
- Nested and batched object access (GraphQL aliases, REST nested routes).

## Test pattern

- Account A creates/owns object O1; Account B attempts read/update/delete O1.
- Vary IDs sequentially and predictably; decode base64 GIDs.
- Compare responses and side effects; repeat with fresh sessions.
- For GraphQL, test `node(id:)`, relay connections, and mutation input IDs.

## Provenance

- Source capability: `skills/capabilities/api`
- Related canonical references: `hunt-graphql.md`, `hunt-fintech-graphql.md`, `hunt-api-misconfig.md`
- Related scripts: see `api-scripts.md`
"