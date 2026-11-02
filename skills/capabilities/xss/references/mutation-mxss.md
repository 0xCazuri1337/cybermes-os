# Mutation XSS (mXSS) — Reference

Source provenance: `hunt-dom` (DOMPurify bypasses), `domains/web/xss/topics/mutation-xss.md`.

## Core concept
Mutation XSS exploits differences between the HTML parser used for sanitization and the parser used for rendering. The sanitizer sees one tree; the browser mutates it into another.

## Techniques
- DOMPurify clobbering bypasses (Michał Bentkowski research).
- Closing an enclosing script tag works because HTML is parsed before JS.
- innerHTML sink will not execute injected `<script>`; use event-handler elements.

## Validation
- Confirm sanitizer output differs from rendered DOM.
- Confirm execution after mutation.
- Test across browsers (parser differences).

## Kill conditions
- Application escapes closing sequences.
- Value sits in external JS file (no re-parse as markup).
- Trusted Types enforcement blocks assignment.
