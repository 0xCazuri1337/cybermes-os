# CSP Interactions — Reference

Source provenance: `hunt-xss`, `xss-hunter`, `domains/web/xss/topics/*`.

## Analysis steps
1. Read `script-src` (and `default-src`) on the landing page.
2. Check for `unsafe-inline`, `unsafe-eval`, nonce, hash, `strict-dynamic`.
3. Inline event handlers require `unsafe-inline` (or matching hash/nonce) — `unsafe-eval` alone is insufficient.
4. Nonce must be checked on the landing page, not assumed.

## Bypass angles
- Nonce reuse / predictable nonce.
- Hash-based bypass via allowed script.
- `strict-dynamic` propagation through trusted scripts.
- JSONP / callback endpoints as script sources.
- Dangling markup / data exfiltration when script execution is blocked.

## Validation
- Fetch and parse the actual CSP on the landing page.
- Test payload execution under the policy.
- Document CSP effectiveness if no bypass exists.
