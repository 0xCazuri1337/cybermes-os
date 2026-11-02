# Python Deserialization

## Scope
pickle, marshal, yaml.load (unsafe), jsonpickle, dill.

## Signals
- Base64 blobs decoding to 0x80 (pickle protocol).
- YAML with !!python/object tags.
- jsonpickle $type fields.

## Detection
- Send OOB pickle probe (__reduce__ invoking nslookup/callback).
- yaml !!python/object/apply:os.system.

## OOB validation
Use callback_host for DNS/HTTP callbacks.

## False positives
- yaml.safe_load; pickle restricted unpickler.
