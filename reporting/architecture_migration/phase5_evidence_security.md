# Phase 5 — Evidence Security

## Encryption design

- Algorithm: Fernet (AES-128-CBC + HMAC-SHA256) from `cryptography.fernet`, an audited library. No custom crypto.
- Key source: environment variable `HUNT_EVIDENCE_KEY` (32 url-safe base64 bytes). No hardcoded keys. Keys never stored in SQLite or repo.
- Unique nonce per encryption: Fernet generates a fresh IV per `encrypt()` call.
- Fail-closed: `encrypt_raw()` raises `RuntimeError` if key is missing/invalid. No plaintext fallback.
- Authenticated: Fernet provides authenticated encryption; tampering raises on decrypt.

## Raw vs sanitized

- Raw: complete original bytes, encrypted at rest, outside searchable plaintext indexes.
- Sanitized: redacts Authorization, Cookie, Set-Cookie, token/password/api_key/api-key in headers, query params, and body strings. Structural info preserved.
- Manifest records: raw_sha256_plaintext, sanitized_sha256, raw_encrypted_sha256, key version implicit via env.

## Access policy

- Normal search and agent context use sanitized evidence only.
- Raw evidence requires explicit authorized retrieval (`history evidence --raw` requires key + authorization).
- Raw access is audit-logged without logging secrets.
- No unredacted credentials in LLM context.

## Integrity verification

- `verify_evidence(evidence_id)` checks decryption + raw plaintext hash + sanitized file hash + encrypted file hash.
- `verify_all()` aggregates per session.
- Evidence corruption reported explicitly (returns `ok: False` with reasons).

## Tests (eval/test_hunt_history.py)

- test_evidence_encrypt_decrypt: PASS (encrypted file exists, decrypt verifies, plaintext absent from file).
- test_no_key_fail_closed: PASS (RuntimeError raised).
- test_sanitize: PASS (Authorization redacted).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase5_evidence_security.md