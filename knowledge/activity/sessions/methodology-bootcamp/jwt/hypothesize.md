# jwt — hypothesize: each hypothesis keyed to an observed signal, each falsifiable

Format per hypothesis: the signal I actually observed, the hypothesis, and **the specific observation that
would refute it**. A hypothesis I cannot kill is not a hypothesis, it is a belief.

---

## H1 — the token is selecting its own verification method (`alg:none` accepted)

**Observed signal:** a token with header `{"alg":"none"}` and an empty signature returned an authenticated
response on an endpoint that differs for unauthenticated callers.

**Hypothesis:** the trust decision reads the verification method from the token, so the token can name "no
verification" and the verifier obliges. The failing invariant is that a token must never select its own
verification method.

**Falsifier:** the same unsigned token is rejected with 401/403 or an 'invalid signature' response, *identical
to a token whose payload was tampered with* [jwt.signal.none_alg_accepted]. Equivalently, if the 200 was
reproduced by a request carrying no `Authorization` header at all, the route was public and this hypothesis is
dead [jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline].

**Falsifier for the obfuscation sub-family:** all case and encoding variants of the `none` header are rejected
identically to a well-formed signature error, and no variant authenticates
[jwt.bypass.none_alg_filter_obfuscation].

---

## H2 — the verifier dispatches on the attacker-controlled `alg` header (RS256->HS256 confusion)

**Observed signal:** the deployment issues RS256 tokens; a public key is retrievable from a JWKS endpoint; a
token re-signed HS256 with that public key as the HMAC secret was accepted.

**Hypothesis:** the key/algorithm choice is taken from the `alg` header rather than from a server-side
allowlist bound to the key, so the same key bytes serve as an RSA public key and as an HMAC secret.

**Falsifier:** every HS256 token signed with the published or derived public key is rejected, and the server
never verifies a MAC against a key whose type is public
[jwt.technique.rs256_to_hs256_public_key_hmac]. The prerequisite item is even sharper: an RS256->HS256 token
signed with the server's public key is rejected with an explicit signature/algorithm error on every attempt,
including HS384/HS512 variants [jwt.prerequisite.alg_driven_generic_verify].

---

## H3 — `kid` is being dereferenced rather than resolved inside a trusted set

**Observed signal:** a `kid` naming a path (`../../../../dev/null`) changed the server's behaviour relative to
a normal `kid`.

**Hypothesis:** the verifier uses `kid` to *locate* key material, so token input steers a filesystem read (and,
with symmetric algorithms allowed, an empty file yields a known zero-length HMAC secret).

**Falsifier:** traversal payloads produce an error or fall back to a default key, and the same forged token is
rejected on replay [jwt.technique.kid_path_traversal_empty_file_secret]. The sharper control: a `kid` naming a
file that certainly does not exist, with **no traversal characters**, produces the same failure — then the 500
is a missing-key-file error, not a traversal.

---

## H4 — `jku`/`x5u` is fetched, giving the attacker the trust anchor

**Observed signal:** a token whose `jku`/`x5u` pointed at a URL I control was accepted.

**Hypothesis:** the server dereferences an unauthenticated URL to obtain the key, so my hosted key becomes the
trust anchor [jwt.signal.header_supplied_key_material].

**Falsifier:** every attacker-supplied key location is ignored, and the server verifies only against keys it
resolved out of band from its own pinned or discovered key set
[jwt.signal.header_supplied_key_material]. The decisive control is dynamic, not static: **re-host the key with
a different modulus, re-request, and see whether the outcome tracks my key.** Unchanged behaviour proves a
cache or a hardcoded key, which means my URL was never fetched.

---

## H5 — the key set is not bound to issuer or key version (stale/foreign `kid` accepted)

**Observed signal:** a token signed by a retired-but-still-published key, or by a key belonging to a different
trusted issuer, verifies.

**Hypothesis:** the trust decision asks only "did some key in the set sign this", never "is this key current
for this validated issuer", so retired and foreign keys remain eligible.

**Falsifier:** only keys bound to the validated issuer and current key version verify; retired and foreign
`kid` values yield a lookup failure and a rejected token
[jwt.technique.stale_or_foreign_kid_key_acceptance].

---

## H6 — token kinds are not mutually exclusive (access token accepted where an ID token belongs)

**Observed signal:** one issuer mints both an access token and an ID token, and a token of one kind verifies at
the endpoint that expects the other.

**Hypothesis:** overlapping validation rules let a token of one kind be presented where another kind is
expected [jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules].

**Falsifier:** the wrong-kind token is rejected because the kinds are already separated by distinct key sets,
distinct issuers, distinct audiences, or a validator enforcing a required claim set unique to one kind. Note
the typing caveat: `typ` may not achieve disambiguation, because existing validators often do not read it — so
typing only helps when the validator actually reads it. And the hypothesis additionally requires reachability:
an ID token obtained through the authorization code flow with a matching `nonce` generally is not
[jwt.bypass.multiple_token_kinds_from_one_issuer_with_shared_validation_rules].

---

## H7 — signature is verified but `exp` / `aud` / `iss` are never enforced

**Observed signal:** a validly signed token whose `exp` is six months past, or whose `aud` names a different
relying party, still drives an authorization decision.

**Hypothesis:** the validator performs only the cryptographic check. This is a *real* finding and is
deliberately separated in `interpret.md` from the claims that are not — signature success with no claim
enforcement is a different defect from signature failure.

**Falsifier:** the expired token is rejected, or the foreign-audience token is rejected, and a control with
only the mutable claim changed behaves identically to the untampered token
[jwt.fprule.unread_claims_prove_nothing]. Critically: changing `aud` and observing **no** behavioural difference
is not evidence of absence unless the token is otherwise validly signed *and* reaches an endpoint whose
authorization decision depends on that claim.

---

## The hypotheses I am explicitly refusing to hold

- **"The endpoint returned 200 with a modified token, therefore validation is broken."** The endpoint may never
  have consulted the token. This is not a hypothesis; it is the failure mode that produces most of this class's
  noise.
- **"The tokens carry `jku`/`jwk`/`x5u`/`x5c`/`kid`, so key resolution is unsafe."** Their mere presence in
  legitimately issued tokens is normal key selection, not a vulnerability; only unauthenticated resolution is
  [jwt.fp_rule.key_headers_present_is_not_a_vuln].
- **"The application uses a symmetric algorithm, so the crypto is weak."** HS256 with a strong shared secret is
  the deployment's deliberate choice. This class reaches symmetric deployments only through the type binding
  in H2.
- **"The library threw / logged the header / echoed it back, so it processed the attacker value."** A
  verification path that throws, returns a library error object, or falls through to an anonymous identity is a
  rejection unless the request then proceeds to the protected resource
  [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].