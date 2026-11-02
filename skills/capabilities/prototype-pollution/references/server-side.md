# Server-Side Prototype Pollution (Node.js)

## Sources
- JSON body merge/clone/extend: `{"__proto__": {"isAdmin": true}}`, `{"constructor": {"prototype": {"isAdmin": true}}}`.
- Deep merge of user-controlled objects, query/body parsers.

## Detection
- Status-code reflection: pollute `status` to 510; if response returns 510, vulnerable.
- JSON spacing: pollute `json spaces` to change indentation.
- Error-based: pollute `toString` to null causing 500.

## Exploitation
- Auth bypass: pollute `isAdmin`, `role`, `verified`, `emailVerified`.
- RCE via template engines: EJS `escapeFunction`, Pug `block`, Handlebars `allowProtoMethodsByDefault`.
- RCE via child_process: pollute `shell`, `NODE_OPTIONS`.
- JSON schema bypass: pollute `additionalProperties`.

## Tools
- ppfuzz, Nuclei prototype-pollution templates, Burp Server-Side Prototype Pollution check.
