# Prototype Pollution Gadgets

## Concept
A gadget is a property read from the prototype that reaches a dangerous sink (source-to-sink chain). Pollution alone is not impact; a gadget is required.

## Common gadgets
- EJS: `client`, `escapeFunction`.
- Pug: `block.type`, `block.line`.
- Handlebars: `allowProtoMethodsByDefault`, `allowProtoPropertiesByDefault`.
- child_process: `shell`, `NODE_OPTIONS`.
- JSON schema: `additionalProperties`.
- DOM: `innerHTML`, `html`, `transport_url`, `allowedTags`.

## Validation
Each finding must show source -> gadget -> sink with reproduction. Use test accounts; avoid destructive RCE without authorization.
