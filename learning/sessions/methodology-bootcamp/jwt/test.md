# jwt — test: ordered plan, each step with its expected information gain

Order is chosen by information gain per request, not by alphabetical convenience. Steps 0-2 are prerequisites
that make every later result interpretable; running them late is how hunts produce unwinnable ambiguity.

---

## Step 0 — Establish the credential-free baseline (do this FIRST)

**Action.** Pick one endpoint. Send four requests: (a) no `Authorization` header and no cookies; (b) a
deliberately malformed token, `Bearer not.a.jwt`; (c) the captured valid token unmodified; (d) the valid token
with only the `sub` claim edited and **not** re-signed.

**Expected information gain: maximal, because it partitions the entire endpoint into "token-governed" and
"not token-governed".** Only requests whose responses differ are governed by token validation; without this
control every later observation may come from a route that was never protected, which is the most common way a
JWT finding turns out to be nothing. Outcome: if (a), (b) and (c) are identical, stop — this endpoint cannot
produce a JWT finding and every result from here is noise. If (d) returns a body echoing the ORIGINAL subject,
the server re-read a trusted source rather than trusting presented claims.

---

## Step 1 — The verifier-passes matrix

**Action.** Against the endpoint confirmed protected in Step 0, send: correct token (control), payload-tampered
token, RS256->HS256, ES256->HS256, `alg:none`, `alg:NONE` / `alg:None` casing, and a token signed by an
unrelated key you generated. This is the corpus's own prescribed matrix
[jwt.test.a_verifier_passes_only_if_the_accepted_algorithm].

**Expected information gain: high and broad.** One pass separates all three signature-verification families at
once. A rejection with a signature/algorithm error on the RS256->HS256 variants kills H2 outright, including
the HS384/HS512 sub-variants [jwt.prerequisite.alg_driven_generic_verify]. Uniform 401s across all seven
variants means the verifier has an allowlist and this endpoint is not vulnerable
[jwt.validation.allowlist_algorithm_and_key_binding].

**Prerequisite to state before running:** define acceptance *now*, before any probe. Acceptance is a request
carrying **only** the forged token, with no other credential, reaching a resource that a credential-less request
demonstrably cannot [jwt.fprule.alg_none_acceptance_needs_a_credential_free_baseline] — observed as a
`Set-Cookie` establishing a session, or an API response body containing another user's data. A 400/415 in reply
is filtering working, not partial success [jwt.fp_rule.none_alg_obfuscation_attempts_failing]. Defining this
first prevents the inversion in which an error status is read as evidence of a flaw.

---

## Step 2 — `alg:none` obfuscation set (only if Step 1 showed any variant behaving differently from the
control)

**Action.** Run the full set: `None`, `NONE`, `none ` with a trailing space, percent- and unicode-escaped
header bytes, alg omitted entirely, missing vs present trailing dot.

**Expected information gain: high conditional value.** If all variants are rejected, close as not vulnerable
and record the library default — 400/415 responses to `None`, `NONE`, whitespace or unencoded variants are
filtering working [jwt.fp_rule.none_alg_obfuscation_attempts_failing]. If **exactly one** encoding is accepted,
the finding is real but impact still depends on whether that endpoint issues sessions or gates data. This step
exists because a verifier that string-parses to reject `none` has replaced a check with a pattern match
[jwt.bypass.none_alg_filter_obfuscation].

---

## Step 3 — `kid` handling: missing-file control before traversal

**Action.** Send three tokens differing *only* in `kid`: (a) the real `kid` from a captured token; (b) a plain
nonsense name that certainly does not exist, containing no traversal characters; (c) `../../../../dev/null`.
If (b) and (c) behave identically, stop — it is a missing-file error, not traversal. Only a divergence between
(b) and (c) is informative. Then, if traversal survived: point `kid` at an empty file and attempt the
zero-length HMAC secret, and replay the forged token to confirm the secret is stable
[jwt.technique.kid_path_traversal_empty_file_secret].

**Expected information gain: the control is the whole step.** Without (b), a 500 is indistinguishable from a
traversal finding. With it, one extra request eliminates the most common false positive in this family.

---

## Step 4 — `jku` / `x5u` / `jwk`: the callback, and the re-host test

**Action.** Point `jku`/`x5u` at a host I control and wait for a request. If a callback arrives, **change the
hosted key material** (different modulus) and re-request.

**Expected information gain: decisive, and the second half is what makes it so.** A header value appearing in a
stack trace or error message is not proof of an outbound fetch — many stacks echo the header while the actual
key lookup uses a static or pre-resolved key set. Only a received request establishes that the value reached a
network sink; and only a *change in validation outcome after re-hosting* establishes that the fetched key was
actually used [jwt.fprule.kid_and_jku_need_a_callback_not_reflection]. Unchanged behaviour proves a cache or a
hardcoded key.

---

## Step 5 — audience and issuer, against a mutably signed token only

**Action.** Using a key I control (self-signed, or a dev environment's signing key), present a
validly-signed token with `aud` set to a *different* relying party's resource, and separately with `iss`
altered. Present the same claim edits against the real signature as a second arm.

**Expected information gain: conditional and one-sided.** Audience confusion is a finding only when the
relying party fails to check the claim it was supposed to check. Modifying a claim the server never reads yields
identical behaviour whether validation is correct or entirely missing, so the observation carries no
information [jwt.fprule.unread_claims_prove_nothing] — establish which claims the app demonstrably consumes
before attributing behaviour to claim validation.

---

## Step 6 — token-kind cross-presentation (only if the issuer mints more than one kind)

**Action.** Present an ID token at the API resource expecting an access token, and vice versa.

**Expected information gain: narrow.** Worth running only when S7 from `recognize.md` fired. A valid signature
on a token meant for a different recipient is not evidence the endpoint accepts it; RFC 8725 requires the
audience to be present and associated with the recipient, and absence of `aud` must be a rejection
[jwt.fp_rule.a_valid_signature_on_a_token_meant_for_a_different_recipient_is_not_a_pass].

---

## Stop conditions

- Step 0 shows the endpoint is not token-governed -> **stop**, and pick a different endpoint.
- Step 1 shows uniform rejection across all seven variants -> the verifier has an allowlist; record the
  library default and close the endpoint
  [jwt.validation.algorithm_allowlist_is_the_only_test_that_distinguishes_a_rejecting_verifier].
- Every step produces identical responses with no observable difference -> this test does not apply where the
  surrounding behaviour is unobservable; the evidence cannot be produced, so no finding may be asserted
  [jwt.test.a_verifier_passes_only_if_the_accepted_algorithm].

## Rate discipline

Every step is a handful of requests against an authenticated surface, not a sweep. Peak concurrency is low and
sequential, because an interpretation that depends on comparing two responses (Steps 3 and 4 above) breaks
entirely if the server's behaviour varies under load between them.