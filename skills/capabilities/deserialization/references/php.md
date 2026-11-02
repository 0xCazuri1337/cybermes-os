# PHP Deserialization

## Scope
PHP unserialize() on user-controlled input; object injection; phar deserialization.

## Signals
- Patterns like O:4:"User":... in cookies/params.
- PHP stack traces mentioning unserialize.
- File uploads with phar:// wrappers.

## Detection
- Send role-escalation objects: O:4:"User":2:{s:4:"name";s:4:"test";s:4:"role";s:5:"admin";}.
- Test arrays and scalars for logic changes.
- phar metadata injection via file upload.

## OOB validation
Use callback_host for OOB (e.g. __destruct triggering curl/nslookup).

## False positives
- allowed_classes restriction.
- No magic methods reachable.
