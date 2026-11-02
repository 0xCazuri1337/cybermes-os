# jwt — recognize: the observations that justify investigating

The class description ("fails to verify signature/algorithm/claims") tells me nothing to look for. What I can
act on is the set of *observations* that put this class on the board. Each entry below states what I SEE and
why it makes the class worth time.

## Observations that justify investigation

**S1 — A bearer-token API surface exists and a token's contents are readable.** The JWT header is
client-readable and names the algorithm used for signing, which makes the `alg` value the first field to
inspect and the first one to tamper with [jwt.signal.hth_header_jwt_header_consists_of_to]. Seeing an
`Authorization: Bearer <three dot-separated segments>` where segment one decodes to a JSON object containing
`alg` is the entry condition. I do not need the secret; I need the field to exist.

**S2 — The issued tokens advertise which algorithm they use, and I cannot yet tell whether that value is
merely read or obeyed.** Because `alg` is client-readable, every legitimate token tells me which algorithm the
deployment expects. That is reconnaissance, not a finding — but it is what lets me construct the first probe
in `test.md` with only a captured token.

**S3 — An `alg:none` token is honoured.** A token with header `{"alg":"none"}` (and, correctly formed, a
trailing dot and empty signature) that the server honours indicates the verifier accepts unsecured JWTs
[jwt.signal.none_alg_accepted]. This is the highest-signal observation in the class: it means the token named
its own verification method.

**S4 — The server accepts a key I supplied inside the token.** A server that accepts a token signed with a
key you supplied inside the token itself (jwk, jku, x5u, x5c) is resolving its trust anchor from
unauthenticated token input [jwt.signal.header_supplied_key_material]. Seeing `jwk`, `jku`, `x5u` or `x5c`
in *attacker-authored* headers is the observation. Seeing them in *legitimately issued* tokens is not — that
is normal key selection, not a vulnerability; only unauthenticated resolution is
[jwt.fp_rule.key_headers_present_is_not_a_vuln].

**S5 — Multiple keys are in play and the token names one.** `kid` present in issued tokens tells me key
selection is happening. This makes the KEY SELECTION step in `explain.md` reachable, which is where
[jwt.technique.kid_path_traversal_empty_file_secret] and
[jwt.technique.stale_or_foreign_kid_key_acceptance] live.

**S6 — An asymmetric algorithm is in use, which means a public key is retrievable.** RS256 implies a JWKS
endpoint or a published certificate. That makes the RS256->HS256 type-binding family reachable, subject to the
prerequisite that the verifier's key/algorithm choice is taken from the attacker-controlled `alg` header rather
than a server-side allowlist bound to the key [jwt.prerequisite.alg_driven_generic_verify].

**S7 — One issuer mints more than one kind of token.** When one issuer mints more than one kind of JWT, the
validation rules for those kinds must be mutually exclusive; overlapping rule sets let a token of one kind be
presented where another kind is expected
[jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules]. Seeing an access token, an
ID token and a refresh token from the same issuer, all verifiable by the same application, is the signal.

**S8 — The endpoint is one where a 200 would mean something.** This is the observation I am most often
missing when I start, and the one that produces the most false positives. If the route returns the same body
with no `Authorization` header at all, then no JWT observation about that route can ever be a finding. I need
at least one endpoint whose response demonstrably differs between an authenticated and an unauthenticated
caller.

## What is deliberately NOT on this list

- **A JWT whose claims I can read.** Reading JWT claims is not a finding: a signed JWT provides integrity and
  authenticity but not confidentiality, so only forgery or failed verification is a vulnerability
  [jwt.impact.base64_claims_disclosure_vs_integrity]. "I decoded the token and saw the role" is not an
  observation.
- **Absence of `kid` pinning.** As established in `explain.md`, `kid` is a selector rather than a control, and
  its presence in legitimate tokens is normal key selection [jwt.fp_rule.key_headers_present_is_not_a_vuln].
  Nothing to see.
- **A symmetric algorithm in use.** HS256 with a strong shared secret is a deliberate design choice, not a
  weakness. It becomes this class only via the RS256->HS256 type binding
  [jwt.technique.rs256_to_hs256_public_key_hmac], which requires an asymmetric deployment in the first place.
- **An expired token being rejected.** That is the control working
  [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].

## Ordering the signals by cost

S8 is free and gates everything else — take it first, because without it every other observation is
uninterpretable. S1/S2 cost one captured token. S5 and S6 cost one base64url decode. S3, S4 and S7 require
sending something, so they belong in `test.md` rather than in the recognition pass.