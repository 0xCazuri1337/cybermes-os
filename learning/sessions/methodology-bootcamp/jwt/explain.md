# jwt — explain: the failing invariant, traced per algorithm family

Class: JWT / Token Validation Failures. CWE-347. Surface: identity.

A JWT exists to establish authenticity, not to hide data [jwt.impact.hth_so_the_integrity_and_authenticity].
Every claim in the token is client-readable and rewritable, so a JWT decoder is not an attack surface at
all — decoding is exactly what the format invites [jwt.impact.base64_claims_disclosure_vs_integrity]. The
only thing that carries security weight is the signature check, and that check is the only place a JWT
finding can originate.

The consequence that governs everything below: **the token names the algorithm used to verify itself.** The
header is client-readable and names the signing algorithm, which makes the `alg` value the first field to
inspect and the first one to tamper with [jwt.signal.hth_header_jwt_header_consists_of_to]. So the verifier,
not the token, must decide what a token *is allowed* to be. The corpus states the required shape of that
decision precisely: a verifier passes only if the accepted algorithm set is a server-side allowlist, the key
type matches that algorithm, and the whole token is rejected if any check fails
[jwt.validation.allowlist_algorithm_and_key_binding].

## The generic chain

    attacker input   -> parser -> normalisation -> validation -> trust decision -> internal operation -> observable result

For this class the stages map as follows.

- **attacker input**: a compact-serialised token, three base64url segments, supplied in an `Authorization`
  header, a cookie, or a query parameter. The header segment is fully attacker-authored.
- **parser**: the JOSE library splits on `.`, base64url-decodes the header, and exposes `alg`, `kid`, `jku`,
  `jwk`, `x5u`, `x5c` as ordinary fields. Parsing succeeding proves nothing about trust.
- **normalisation**: where the vulnerability lives. Case-folding of `alg`, tolerance of missing trailing
  dots, tolerance of unencoded or whitespace-padded headers, and any string-matching rather than
  allowlist-matching of the algorithm identifier.
- **validation**: signature verification (does the bytes match?), then claim checks (`exp`, `aud`, `iss`).
  These are separate gates and failing either one must reject the whole token.
- **trust decision**: "which key verifies this, and was this token minted by someone I trust for this
  recipient?" This is the step that `alg:none` destroys.
- **internal operation**: the handler resolves the subject claim to an account and acts — issuing a session,
  returning that account's data, applying a role.
- **observable result**: an authenticated response, a reissued session cookie, or another user's data.

The invariant that fails is not "the signature check is missing" in the abstract. It is the specific
binding that the verifier should have enforced and did not.

## Family 1 — `alg:none`: the TRUST DECISION fails

**What the attacker supplies**: `{"alg":"none"}` with a trailing dot and an empty signature.

**Chain**: attacker input (unsigned token) -> parser accepts three segments -> normalisation is not even
reached in a good verifier -> the trust decision returns "valid" because the verifier was told by the token
which verification to perform, and the token said "perform none" -> the handler attributes the request to
the `sub` claim the attacker wrote -> observable result: a session or another user's data.

**The failing invariant**: *a token must never be able to select its own verification method.* The verification
method is a property of the deployment, chosen out of band, not a property of the document being verified.
The corpus frames the observable precisely: a token with header `{"alg":"none"}` that the server honours
indicates the verifier accepts unsecured JWTs [jwt.signal.none_alg_accepted], and the server here is
"resolving its trust anchor from unauthenticated token input"
[jwt.signal.header_supplied_key_material].

This family has a second, subtler variant. A verifier that string-parses to *reject* `none` has not fixed
the problem; it has replaced a check with a pattern match, and mixed capitalisation, unexpected encodings or
an omitted trailing dot reopen it [jwt.bypass.none_alg_filter_obfuscation]. The invariant is an allowlist,
not a denylist.

Note what is *not* a failure here: unsecured JWTs are a legitimate construct where content is secured by a
means outside the JWT, so a verifier that accepts `alg:none` only where that is the intended design is not in
violation. The burden falls on showing the design did not intend it.

## Family 2 — `kid` injection: the KEY SELECTION step fails

**What the attacker supplies**: a `kid` (or `jku`) header value they control, naming a location rather than a
key in a trusted set.

**Chain**: attacker input (valid-looking token with an attacker-chosen `kid`) -> parser exposes `kid` ->
the verifier uses it to *locate* a key -> the location resolves to attacker-influenced bytes -> signature
verification runs against bytes the attacker supplied -> trust decision is satisfied by construction ->
observable result: forged identity accepted.

**The failing invariant**: *the trust anchor must be selected from a server-side set, not from a
dereference of token input.* When `kid` selects a key from the filesystem and symmetric algorithms are
allowed, pointing `kid` at an empty file yields a known zero-length HMAC secret
[jwt.technique.kid_path_traversal_empty_file_secret]. The invariant broken is that key resolution must not
be an outbound dereference of an unauthenticated value.

## Family 3 — RS256 -> HS256: the TYPE BINDING fails

**What the attacker supplies**: `alg` changed from RS256 to HS256, and a signature computed with the server's
own *public* key used as an HMAC secret.

**Chain**: attacker input (header says HS256) -> the verifier reads `alg` from the token instead of from its
own configuration -> the verifier dispatches to its MAC routine and hands it the RSA public key as key
material -> a MAC computed over the public key verifies -> trust decision satisfied -> observable result:
forged payload accepted.

**The failing invariant**: *the declared algorithm must be bound to the actual type of the key it is used
with.* Two prerequisites must both hold for this to be possible. First, the verifier's key/algorithm choice
must be taken from the attacker-controlled `alg` header rather than from a server-side allowlist bound to the
key [jwt.prerequisite.alg_driven_generic_verify]. Second, the attacker's copy of the public key must be
byte-identical to the server's stored copy, including PEM formatting and newlines
[jwt.prerequisite.obtainable_exact_public_key_bytes]. When both hold, re-signing a modified payload with
HS256 using the server's own RSA public key as the HMAC secret yields a token the confused verifier accepts
[jwt.technique.rs256_to_hs256_public_key_hmac]. This is a *type* confusion, not a cryptographic weakness of
either algorithm.

## Family 4 — key distribution: stale or foreign keys

**What the attacker supplies**: nothing forged. A `kid` that legitimately names a key the verifier still
accepts.

**Chain**: attacker input (a token signed by a key the issuer retired but still publishes, or one belonging to
another trusted issuer) -> parser reads `kid` -> the multi-key set resolves it -> signature verification is
genuine and succeeds -> trust decision asks only "did this key sign it", never "is this key current for this
issuer" -> observable result: a token from a retired or foreign key is honoured.

**The failing invariant**: *key acceptance must be bound to the validated issuer and the current key version,
not merely to membership in a key set.* A verifier that resolves the key by header `kid`/`jku` against a
multi-key set still accepts tokens signed with retired-but-still-published keys or keys belonging to another
trusted issuer [jwt.technique.stale_or_foreign_kid_key_acceptance].

## Family 5 — missing `kid` pinning: NOTHING fails

This must be stated plainly because it is the most over-reported item in the class. `kid` is a *selector*, not
a security control. The presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is
normal key selection, not a vulnerability; only unauthenticated resolution is
[jwt.fp_rule.key_headers_present_is_not_a_vuln]. The corpus is even more specific: legitimate tokens may carry
`kid` while the server still rejects a token signed with an attacker-supplied `jwk` or fetched from an
attacker `jku` host, because the header is being used as a selector within an already-trusted set.

So "the tokens do not pin `kid`" is **not a finding on its own**. It becomes a finding only when one of the
four families above is simultaneously demonstrated — that the injected key is actually the key used for
verification, proven by a forged token being accepted. Absent that, a missing-`kid` observation is a note
about hygiene, not a vulnerability, and filing it is the single most common way a JWT report loses
credibility.

## The cross-cutting distinction

Families 1, 3 and 4 all end with a signature check that either did not run, ran against attacker bytes, or ran
against a key that should not have been eligible. Family 5 runs a perfectly good signature check and still
yields nothing. That is why the corpus insists the observable is the *protected response*, never the absence
of an exception: a library that raises on an unsupported `alg` is doing exactly what the spec requires
[jwt.evidence.a_verification_path_that_throws_returns_a_li], and a verification path that throws or falls
through to an anonymous identity is a rejection unless the request then proceeds to the protected resource
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].