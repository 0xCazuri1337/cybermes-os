# Ruby Deserialization (Psych / Marshal)

## Scope
YAML.load (Psych), Marshal.load, Oj.load.

## Signals
- YAML with !ruby/object tags.
- Marshal magic bytes.

## Detection
- Psych gadget chains (ERB, Gem::Requirement).
- OOB via open-uri or system.

## OOB validation
Use callback_host.

## False positives
- YAML.safe_load; permitted classes list.
