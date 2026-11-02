# API Authorization — Topical Reference

Promoted topical reference for API authorization testing. Preserves provenance from the canonical API capability and its legacy authorization sub-skills.

## Scope

- Object-level authorization (BOLA/IDOR): whether a user can access another user's object by changing an identifier.
- Function-level authorization (BFLA): whether a low-privilege user can invoke admin/privileged operations.
- Property-level authorization (BOPLA): whether responses or writes expose/accept fields beyond the caller's role.
- Business-flow authorization: whether multi-step workflows enforce state and role transitions.

## Core method

1. Capture baseline requests for at least two accounts/roles.
2. Replay object identifiers, function names, and privileged fields across roles.
3. Diff status codes, response bodies, and side effects.
4. Confirm with a clean reproduction and, where possible, a third role.

## Provenance

- Source capability: `skills/capabilities/api`
- Related legacy material: `api-authorization/*`, `rest/*`, `graphql/*`
- Related canonical references: `exploiting-mass-assignment-in-rest-apis.md`, `testing-api-for-mass-assignment-vulnerability.md`, `testing-for-sensitive-data-exposure.md`

## Nested references

See `nested-api-references.md` for the preserved nested `references/api-reference.md` content.
"