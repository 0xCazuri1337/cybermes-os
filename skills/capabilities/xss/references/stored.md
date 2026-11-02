# Stored XSS — Reference

Source provenance: `hunt-xss`, `xss-hunter`, `domains/web/xss/topics/stored-xss.md`.

## How it works
Stored XSS requires the payload to persist in a server-side store and later render in another user's response. Proof needs two distinct steps: store, then render for a second user/role.

## False positives
- Payload executes only in the submitting user's own session and never renders for any other user or role.
- Store-only write with no second-user render is not cross-site script execution.

## High-payout patterns
- Stored XSS in feature autocomplete/popups (see `references/high-payout-patterns.md`).
- Stored XSS via markdown/diagram renderers with attribute breakout.

## Validation
- Submit payload, then view as a different user/role and confirm execution.
- Confirm persistence across sessions.
