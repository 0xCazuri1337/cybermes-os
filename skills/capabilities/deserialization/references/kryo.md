# Kryo Deserialization

## Scope
Kryo serialization in Java apps (Spark, Akka).

## Signals
- Kryo serialized blobs; class registration.

## Detection
- Unregistered class injection; gadget chains.

## OOB validation
Use callback_host.

## False positives
- Registration required; no default constructor.
