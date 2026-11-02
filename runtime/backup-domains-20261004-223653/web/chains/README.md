# Attack chains

A chain is a **relationship between classes**: an initial weakness that makes a
later one reachable or severe. It is not a vulnerability and gets no bug-class
file.

## The families here

| File | Chains that |
|---|---|
| [authentication-chains.md](authentication-chains.md) | begin at identity — a failure to prove *who you are* becomes access |
| [authorization-chains.md](authorization-chains.md) | begin at an authorization decision — a refused object becomes the entry to something wider |
| [xss-chains.md](xss-chains.md) | begin with script execution in a victim's browser |
| [ssrf-chains.md](ssrf-chains.md) | begin with the server fetching a URL the attacker chose |
| [api-chains.md](api-chains.md) | sit on an API surface, where one missing check yields both a read and a write |
| [business-logic-chains.md](business-logic-chains.md) | turn a low-severity logic flaw into a priced outcome |
| [cross-class-chains.md](cross-class-chains.md) | cross domains — an injection yields a credential, which yields an object |

Per-chain evidence digests, rendered from the db one row at a time, live in
[`chains/`](../chains/); the narratives here are the canonical chain documents.

## What belongs here

Ordered sequences where each step is justified by *why* it is possible, and
every step references a bug class that already passed the evidence gate.

## What does NOT belong here

- A single vulnerability → `bug-classes/`
- An unproven sequence. A chain step on a missing or unpromoted item is a
  story, and a story in a knowledge base is worse than no chain.

## How children are organised

One file per chain family: authentication, authorization, xss, ssrf, api,
business-logic, and cross-class for chains that span domains.

## Related

- Each step names its class; each class links back here.
