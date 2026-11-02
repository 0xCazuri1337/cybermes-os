# REST APIs

## What this directory represents

Classes whose detection depends on REST mechanics: the verb, the content type,
and the binding of request JSON onto a model.

## What belongs inside it

Canonical API classes: `../../../mass_assign/knowledge/CLASS.md`, `../../../topics/rest/parameter-pollution.md`,
`../../../topics/rest/excessive-data-exposure.md`, `../../../topics/authentication/rate-limit.md`.

Pointer stubs carrying the REST-specific delta: `../../../../domains/api/rest/topics/authentication.md`,
`../../../../domains/api/rest/topics/authorization.md`, `../../../idor/topics/idor-bola.md`, `../../../../domains/api/rest/topics/business-logic.md`.

## What does NOT belong inside it

A full copy of a web class. `../../../idor/topics/idor-bola.md` says: canonical home is
`../../web/authorization/idor.md`, and then only what is true of REST.

## How children are organised

Canonical API-native classes first, then pointers. `../../../idor/topics/idor-bola.md` exists because
OWASP names BOLA separately — the *name* differs even when the *concept* does
not, and an agent searching "BOLA" must find the file.

## Related bug classes

`../../attack-chains/api-chains.md` for API-specific chains.

## How new entries should be added

Ask whether the class exists for web. If yes, add a pointer; if the REST
mechanic genuinely differs (verb override, content-type confusion), that delta
belongs in the pointer.
