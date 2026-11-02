# AMF Deserialization

## Scope
Action Message Format (AMF0/AMF3) in Flash/Java remoting.

## Signals
- Content-Type application/x-amf.
- BlazeDS/LCDS endpoints.

## Detection
- AMF object injection; externalizable objects.
- RCE via Factory/Proxy gadgets.

## OOB validation
Use callback_host.

## False positives
- Type whitelist in remoting.
