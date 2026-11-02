# Go Deserialization (gob / encoding)

## Scope
encoding/gob, json with interface{}, xml.

## Signals
- Gob stream magic; type registration endpoints.
- Reflection-based decoding into interface{}.

## Detection
- Type confusion via registered types.
- RCE via registered factory functions.

## OOB validation
Use callback_host where applicable.

## False positives
- Strict type decoding.
