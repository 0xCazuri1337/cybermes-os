# BFLA — Topical Reference

Promoted topical reference for Broken Function Level Authorization in APIs.

## Focus

- Admin, internal, debug, and privileged endpoints reachable by low-privilege users.
- HTTP method and verb tampering on the same path.
- GraphQL mutations/queries lacking resolver-level authorization.
- Framework-specific route/controller authorization gaps (ASP.NET, Laravel, Spring Boot, Node, Next.js).

## Test pattern

- Enumerate functions from docs, JS bundles, OpenAPI, and introspection.
- Replay privileged functions with a low-privilege token.
- Compare against an admin baseline and document status/body differences.
- Check method overrides and alternate content types.

## Provenance

- Source capability: `skills/capabilities/api`
- Related canonical references: `hunt-api-misconfig.md`, `hunt-aspnet.md`, `hunt-laravel.md`, `hunt-nodejs.md`, `hunt-springboot.md`, `hunt-nextjs.md`
"