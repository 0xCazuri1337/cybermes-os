# Web security classes

Browser-and-server HTTP surfaces. Grouped by **the security boundary the flaw
breaks**, not by payload type — that grouping is what makes the map navigable
during a hunt.

## What belongs here

A class where the attacker and the victim share a browser-mediated HTTP
conversation: forms, cookies, sessions, rendered HTML, file uploads, state
transitions.

## What does NOT belong here

- API-only surfaces → `bug-classes/api/`
- Injection *payloads* → `methodology/injection-testing.md`
- Cross-class combinations → `attack-chains/`

## How children are organised

| Directory | The boundary broken |
|---|---|
| `authentication/` | proving **who you are** |
| `authorization/` | proving **what you may touch** |
| `injection/` | attacker data interpreted as a language |
| `xss/` | attacker data interpreted as a script |
| `request-forgery/` | the server making a request, or trusting its origin |
| `file-security/` | the filesystem boundary |
| `server-side/` | code execution and object graphs on the server |
| `client-side/` | browser state and navigation the server does not control |
| `business-logic/` | a correct step in the wrong order, or the wrong number |
| `miscellaneous/` | real classes with no better home — pointers only |

## Related

- Canonical classes referenced by the API side: `api/rest/` holds pointers here.
