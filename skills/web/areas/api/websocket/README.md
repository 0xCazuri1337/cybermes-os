# WebSocket

## What this directory represents

A connection that authenticates **once** at the upgrade handshake, then carries
messages that are never re-authorised.

## What belongs inside it

`../../../../skills/api/rest/topics/authentication.md`, `../../../../skills/api/rest/topics/authorization.md` (both **pointers** to
`../../web/authentication/` and `../../web/authorization/`),
`../../../topics/websocket/message-manipulation.md`.

## What does NOT belong inside it

Handshake and framing specifics that are transport, not vulnerability.

## How children are organised

By lifecycle position: the handshake (`../../../../skills/api/rest/topics/authentication.md`, `../../../../skills/api/rest/topics/authorization.md`)
versus the message stream (`../../../topics/websocket/message-manipulation.md`).

## Related bug classes

`../../attack-chains/authentication-chains.md` — a stolen or unvalidated
upgrade token chains to every message the socket accepts.

## How new entries should be added

Only for a capability unique to a persistent connection. Anything expressible
over plain HTTP is not a WebSocket class.
