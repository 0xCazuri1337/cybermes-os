# Authentication — proving *who you are*

## What this directory represents

Flaws in the credential-checking step itself: how a subject is established,
how that establishment is re-checked, and how it is recovered when lost.

## What belongs inside it

- Bypasses of the check: `../../../topics/authentication/authentication-bypass.md`
- The token lifecycle after authentication: `../../../session/knowledge/CLASS.md`
- The second factor as an attack surface: `../../../topics/authentication/mfa-bypass.md`
- The weakest link — usually the recovery path: `../../../topics/authentication/account-recovery.md`
- Token *validation* failures: `../../../jwt/knowledge/CLASS.md`
- Federated-issuer configuration: `../../../oauth/knowledge/CLASS.md`

## What does NOT belong inside it

- *What you may touch* once authenticated → `../authorization/`
- Token theft via XSS → `../xss/`, chained in `../../attack-chains/authentication-chains.md`
- Identity provider internals → not in scope for a web/API taxonomy

## How children are organised

One file per mechanism, ordered by the stage of the login lifecycle it breaks.

## Related bug classes

`../../../session/knowledge/CLASS.md` chains to every class in `../authorization/`; a session
that cannot be revoked turns any single authorization bug into a persistent one.

## How new entries should be added

Only for a mechanism distinct from those above. "Credential stuffing" is a
technique under `../../../topics/authentication/authentication-bypass.md`, not a new file. Add to
`TREE` in `tools/taxonomy/build_taxonomy.py` and regenerate.
