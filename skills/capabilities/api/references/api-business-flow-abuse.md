# Business-Flow Abuse — Topical Reference

Promoted topical reference for API business-logic and workflow abuse.

## Focus

- Multi-step workflow bypass and state manipulation.
- Price, quantity, discount, and currency manipulation.
- Race conditions and idempotency-key replay/double-spend.
- CAPTCHA, OTP, and rate-limit bypass on business actions.

## Test pattern

- Map the intended state machine and required transitions.
- Skip, reorder, or repeat steps; submit stale or duplicate tokens.
- Manipulate numeric and enum fields; test concurrency.
- Validate server-side state and persistence, not just responses.

## Provenance

- Source capability: `skills/capabilities/api`
- Related canonical references: `performing-api-rate-limiting-bypass.md`
- Related capability: `skills/capabilities/business-logic` (kept intact; not modified)
"