# Hessian Deserialization

## Scope
Hessian/Burlap remoting protocols.

## Signals
- Content-Type x-application/hessian.
- Hessian endpoints (Spring HttpInvoker).

## Detection
- Hessian object injection; Map/List abuse.
- RCE via Spring/ROME gadgets.

## OOB validation
Use callback_host.

## False positives
- Type whitelist; method allowlists.
