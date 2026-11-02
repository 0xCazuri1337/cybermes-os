# Filter Bypass — Reference

Source provenance: `hunt-xss` (bypass ladders), `xss-hunter`.

## Ladders
- Parens-free and template-literal probes.
- Entity decoding of attribute values.
- Backslash/entity probe sequences.
- HTML entity decoding of attribute values.
- New event handler without angle brackets.

## Techniques
- Break out of quoted JS strings with unescaped backslashes.
- Use `javascript:` pseudo-protocol in href.
- Use event handlers when angle brackets are blocked.
- Use mutation (mXSS) to evade sanitizers.

## Validation
- Confirm which characters are filtered vs allowed.
- Confirm execution after bypass (not just reflection).
- Test across contexts (body, attribute, JS string, URL).
