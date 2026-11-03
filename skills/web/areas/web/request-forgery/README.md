# Request forgery — the server or the origin is misled

## What this directory represents

Flaws where a request the server makes, or a request's origin, is not what it
appears to be.

## What belongs inside it

`../../../csrf/CLASS.md`, `../../../ssrf/CLASS.md`, `../../../smuggling/CLASS.md`, `../../../cache_poisoning/CLASS.md`.

## What does NOT belong inside it

- The response being poisoned after the fact → `../xss/stored-xss.md`
- Desync exploited only as DoS → `../../../smuggling/CLASS.md` covers the class

## How children are organised

Grouped by **what is being forged**: the victim's intent (`csrf`), the
server's network position (`ssrf`), the request framing between hops
(`request-smuggling`), or the cache key (`cache-poisoning`).

## Related bug classes

`../../../cache_poisoning/CLASS.md` and `../../../smuggling/CLASS.md` are frequently the same
underlying framing disagreement; `../../../ssrf/CLASS.md` chains to cloud metadata access.

## How new entries should be added

Ask what is being forged. If the answer is "nothing, it is just malformed",
it is smuggling, not forgery.
