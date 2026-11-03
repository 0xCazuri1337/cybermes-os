# API security classes

The same security boundaries as `web/`, observed through an API surface. The
API differs not in *what* is broken but in **where the decision is made**: one
universal resolver, one verb set, one schema.

## What belongs here

Classes whose detection depends on API mechanics — verb and content-type
handling, schema-driven resolution, batching, field-level authorisation.

## What does NOT belong here

A second copy of a web class. `../../idor/topics/idor-bola.md` is a **pointer** to
`../../idor/CLASS.md`, carrying only what is true of REST.

## How children are organised

| Directory | Why it is separate |
|---|---|
| `rest/` | verb + content-type are part of the authorization decision; mass assignment binds request JSON straight to a model |
| `graphql/` | authorisation must hold per *resolved field*, not per route; batching and aliases multiply one request |
| `websocket/` | the upgrade handshake carries auth once; messages after it do not re-authorise |
| `other/` | RPC and SOAP shapes that do not fit the above |

## Related

- Every API class links back to its canonical home under `web/`.
- `../../chains/api-chains.md` for cross-surface API chains.
