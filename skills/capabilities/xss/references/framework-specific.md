# Framework-Specific XSS — Reference

Source provenance: `domains/web/xss/topics/framework-xss.md`.

## Technique
- In HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
- `href` attribute is already script-capable: `javascript:` pseudo-protocol executes without terminating the attribute.
- In HTML body context, payload must introduce entirely new tags.
- Inside a quoted JS string literal, payload must escape the delimiter and repair trailing script.
- Template literal: expression without terminating delimiter.

## Framework notes
- React: `dangerouslySetInnerHTML` is the sink; auto-escaping covers text nodes.
- Vue: `v-html` is the sink.
- Angular: bypass sanitization via `bypassSecurityTrust*`.
- Account for framework auto-escaping and template syntax.

## Validation
- Identify framework and version.
- Locate sink APIs (`dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrustHtml`, etc.).
- Confirm execution in the framework's rendering context.
