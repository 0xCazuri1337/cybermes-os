# Server-side — execution and object graphs on the server

## What this directory represents

Flaws whose consequence is reached inside the server process: code execution, or
an object graph whose type system invokes attacker-reachable behaviour.

## What belongs inside it

`../../../topics/server-side/rce.md`, `../../../deser/CLASS.md`, `../../../prototype_pollution/CLASS.md`.

## What does NOT belong inside it

- `../../../ssti/topics/ssti.md` — a **pointer stub**; the canonical page is
  `../injection/template-injection.md`, because SSTI is an interpreter
  injection, not a distinct weakness
- Prototype pollution in the *browser* → `../client-side/client-side-prototype-pollution.md`

## How children are organised

By what the attacker supplies: **code** (`../../../topics/server-side/rce.md`), a **serialised object
graph** (`../../../deser/CLASS.md`), or a **property write** that later resolves to
code (`../../../prototype_pollution/CLASS.md`).

## Related bug classes

`../injection/command-injection.md` is `../../../topics/server-side/rce.md` reached through input rather
than through a deserialiser; both are recorded, and the distinction is the
entry point, not the outcome.

## How new entries should be added

By the mechanism that yields execution. A new serialisation format is a section
in `../../../deser/CLASS.md`, not a new file.
