# Reflected XSS — Reference

Source provenance: `hunt-xss`, `domains/web/xss/topics/reflected-xss.md`, `quarantine/.../bug-classes/web/xss/reflected-xss.md`.

## How it works
Reflected XSS requires attacker data from the current HTTP request to be embedded unneutralized in that same immediate response. If the probe value is absent from the immediate response, or appears only after a separate later request, it is not reflected.

## Signals
- A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal.
- Reflection in a 302 body does not count (browser never renders it).

## Techniques
- Inline script: `<script>alert(CANARY)</script>` when HTML context allows new tags.
- Attribute breakout: terminate value and add event handler (`" onmouseover="alert(CANARY)`).
- URL/href: `javascript:alert(CANARY)`.
- JS string: break out and repair syntax; unescaped backslash defeats quote escaping.
- Template literal: expression without terminating delimiter.

## False positives
- Marker absent or only encoded in a non-decodable form.
- Marker reflected only after a separate later request (stored, not reflected).
- Proper contextual encoding present (`&lt;script&gt;`).
