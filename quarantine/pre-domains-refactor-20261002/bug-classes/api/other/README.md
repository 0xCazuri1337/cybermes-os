# Other API shapes

## What this directory represents

RPC and SOAP surfaces that do not fit the REST/GraphQL/WebSocket mechanics.

## What belongs inside it

`grpc.md`, `soap.md`.

## What does NOT belong inside it

Anything that is REST-shaped with a different content type.

## How children are organised

One file per protocol shape, focusing on where the authorization decision is
made in that protocol.

## Related bug classes

The authorization and injection concepts are canonical under `../../web/`; these
files carry only the protocol-specific mechanics.

## How new entries should be added

When a protocol's *authorisation model* differs from REST's, not merely its
encoding.
