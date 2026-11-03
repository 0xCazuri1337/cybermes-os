# jwt — generalize: common, uncommon and defensive variants

The variant map is organised by *which invariant is at stake*, so that a new observation can be placed by
asking "which of the four families in `explain.md` does this touch, and does it touch any at all?"

---

## 1. COMMON variants — the ones that account for nearly all real reports

### C1. Unsecured JWT accepted (Family 1: trust decision)
Header `{"alg":"none"}`, trailing dot, empty signature, honoured. The variant space within this one family is
what makes it tedious: `None`, `NONE`, `none ` with a trailing space, percent- and unicode-escaped header bytes,
`alg` omitted entirely, and missing-vs-present trailing dot. A verifier that string-parses to reject `none` has
replaced a check with a pattern match, and mixed capitalization, unexpected encodings or an omitted trailing
dot handling difference reopen it [jwt.bypass.none_alg_filter_obfuscation]. Coverage requires the full
obfuscation set, not one probe.

### C2. Algorithm / type confusion (Family 3: type binding)
RS256->HS256 is the canonical form, but the family generalises along two axes: **the asymmetric algorithm**
(RS256, RS384, RS512, PS256, ES256, ES384) and **the MAC variant** (HS256, HS384, HS512). A disproof must cover
all of them, which is exactly why the corpus item states rejection "on every attempt, including HS384/HS512
variants" [jwt.prerequisite.alg_driven_generic_verify]. Note ES256 is special: the public key is a curve point,
so the byte-identity prerequisite
[jwt.prerequisite.obtainable_exact_public_key_bytes] applies to the specific serialisation, not the raw point.

### C3. `kid` injection into key selection (Family 2: key selection)
Three sub-forms: filesystem path (`kid` as a path → empty file → known zero-length HMAC secret
[jwt.technique.kid_path_traversal_empty_file_secret]); URL (`jku`/`x5u` as an unauthenticated dereference
[jwt.signal.header_supplied_key_material]); and inline material (`jwk`/`x5c` embedded in the token itself).

### C4. Multiple token kinds, one issuer (Family 4: rule-set separation)
Access tokens, ID tokens and refresh tokens from the same issuer, verified by the same application. The
invariant: when one issuer mints more than one kind of JWT, the validation rules for those kinds must be
mutually exclusive; overlapping rule sets let a token of one kind be presented where another kind is expected
[jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules]. Distinct key sets, distinct
issuers, distinct audiences, or a required claim set unique to one kind, are all sufficient separations.

### C5. Missing claim enforcement — signature valid, claims never checked
Distinct from C1-C4 and genuinely reportable: the app validates the signature and never checks `exp`, `aud` or
`iss`. A mutably signed token with `exp` six months past, or `aud` set to a different relying party, still
drives an authorization decision. Proof requires establishing which claims the app demonstrably consumes
[jwt.fprule.unread_claims_prove_nothing] — a claim the server never reads yields identical behaviour whether
validation is correct or entirely missing.

---

## 2. UNCOMMON variants — real, but they break differently

### U1. Stale and foreign key acceptance (Family 4: key distribution)
A verifier that resolves the key by header `kid`/`jku` against a multi-key set still accepts tokens signed
with retired-but-still-published keys or keys belonging to another trusted issuer
[jwt.technique.stale_or_foreign_kid_key_acceptance]. Uncommon because it requires a key-rotation history to
have left old keys published — which is common in practice but rarely reported.

### U2. Type-bound keys as an accidental defence
A key usable with exactly one algorithm prevents the confusion regardless of what the header says
[jwt.validation.algorithm_allowlist_is_the_only_test_that_distinguishes_a_rejecting_verifier]. Worth knowing
because it changes the test: if the deployment uses type-bound keys, C2 is unreachable and time spent on it is
wasted.

### U3. `typ` as an insufficient defence
The RFC 8725 caveat: `typ` may not achieve disambiguation from existing kinds of JWTs because the validation
rules for existing kinds often do not use the `typ` value, so typing only helps when the validator actually
reads it [jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules]. A team that added a
`typ` header and believes it fixed C4 has added nothing.

### U4. Sender-constrained tokens collapsing the audience question
Sender-constrained access tokens scope an access token's applicability to a certain sender, obliged to
demonstrate knowledge of a secret as a prerequisite for acceptance — so a token replayed by a different holder
fails on the proof, not on the audience
[jwt.fp_rule.a_valid_signature_on_a_token_meant_for_a_different_recipient_is_not_a_pass]. This *removes* B11 as
a finding rather than adding one.

### U5. Remote key headers behind a cache
The variant that produced a live field false positive: a `jku`/`x5u` acceptance that was really a cached key.
A remote-key header is only proven fetched when changing the hosted key changes the validation outcome;
unchanged behaviour proves a cache or a hardcoded key. Rare as a vulnerability, common as a *misreading*.

### U6. Swallowed errors as a genuine bypass
The documented exception where a thrown verification error IS a finding: the error is swallowed but a side
effect has already occurred — a signature check that fails *after* a database write, or an algorithm rejection
that happens *after* the token's claims have been used to select a tenant or an account
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass]. Rare, and only findable by reading code.

### U7. Unsecured JWTs as intended design
Unsecured JWTs are legitimately created for use cases where the content is secured by a means outside the JWT,
so a verifier that accepts `alg:none` only where that is the intended design is not in violation — the burden
is on showing the design did not intend it
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass]. The variant that makes C1 a design question
rather than a mechanical one.

---

## 3. DEFENSIVE variants — what a correct deployment looks like, and how to tell

### D1. Server-side algorithm allowlist bound to the key
The pass condition: the accepted algorithm set is a server-side allowlist, the key type matches that algorithm,
and the whole token is rejected if any check fails [jwt.validation.allowlist_algorithm_and_key_binding]. All
seven matrix variants except the unmodified control are rejected with the same error, and no variant returns
authenticated content or a session cookie.

### D2. Deployment-level restriction instead of code-level pinning
The algorithm set can be restricted by deployment rather than by request — a JOSE header built server-side with
the field stripped or normalised before verification, or an HSM/provider API that accepts only one algorithm
identifier [jwt.validation.algorithm_allowlist_is_the_only_test_that_distinguishes_a_rejecting_verifier]. This
is a real defence that a code-reading tester can miss and a black-box tester correctly credits.

### D3. Type-bound keys
Covered in U2 — a defence, listed here because it is the one that makes the strongest-sounding attack
impossible rather than merely rejected.

### D4. Mutual exclusion by issuer / audience / required claim set
The separations that make C4 unreachable, per
[jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules].

### D5. Key sets bound to issuer and version
Only keys bound to the validated issuer and current key version verify; retired and foreign `kid` values yield a
lookup failure and a rejected token [jwt.technique.stale_or_foreign_kid_key_acceptance].

### D6. Uniform rejection with a specific error
A 400/401 carrying a signature-verification message is the *expected* rejection
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass]. Defensive behaviour looks exactly like "nothing happened", which is
why the test in `test.md` defines acceptance before testing rather than after.

---

## 4. The variant that is NOT a variant — restated because it is the most over-reported

**Missing `kid` pinning breaks nothing by itself and must never be reported on its own.** `kid` is a selector,
not a control. The mere presence of `jku`, `jwk`, `x5u`, `x5c` or `kid` in legitimately issued tokens is
normal key selection, not a vulnerability; only unauthenticated resolution is
[jwt.fp_rule.key_headers_present_is_not_a_vuln]. Placing this in the *generalize* file as well as `explain.md`
is deliberate: generalization is exactly where an over-broad rule propagates. The correct generalisation is
narrower than the intuitive one — it is not "key headers are risky", it is "a token must not be able to choose
the material that verifies it".

## 5. Placement procedure for a novel observation

Given an observation that matches nothing above, place it with these three questions in order:

1. **Does the token select the verification method, the key, or neither?** `alg:none` → Family 1. `kid`/`jku`/
   `jwk` → Family 2. `alg` vs key type → Family 3. Neither, but key set membership → Family 4. **Neither →
   not this class.**
2. **Did a protected response actually change, or did an error/status change?** An error change is a control
   detail [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].
3. **Is there a credential-free baseline for this exact endpoint?** If not, the observation is uninterpretable
   and no finding may be asserted from it.