# jwt — interpret: result -> meaning -> next action

The ambiguous and negative rows are the point of this file. Almost every JWT hunt dies on one of them, and
each is a trap where a plausible reading inverts the truth.

## Unambiguous positives

| Result | Meaning | Next action |
|---|---|---|
| Forged token (`alg:none`, own-key, or confusion variant) returns 200 with a session cookie or another user's data, **and** the credential-free baseline for that endpoint returns 401/403 | Signature enforcement is absent. The finding is real. | Capture the exact request/response pair; go to `validate.md` |
| `alg:none` honoured with only the token and no other credential, reaching a resource a credential-less request demonstrably cannot | The token named its own verification method — the trust decision failed | Report as trust-decision failure [jwt.signal.none_alg_accepted] |
| Callback arrives at my `jku`/`x5u` host **and** re-hosting a different modulus changes the validation outcome | The header was dereferenced and the fetched key was used for verification | Report as unauthenticated trust-anchor resolution [jwt.fprule.kid_and_jku_need_a_callback_not_reflection] |
| `kid` traversal reaches a file that does not exist while an equivalent plain missing name does not change behaviour, and the empty-file secret forges successfully and replays | `kid` steers a filesystem read into an attacker-known secret | Report as key-selection failure [jwt.technique.kid_path_traversal_empty_file_secret] |

## THE AMBIGUOUS ROWS — where hunts actually die

| Result | Meaning | Next action |
|---|---|---|
| **Token A (my forged shape) rejected with 401, but token B — same shape, different `scope`/`role` — accepted** | **NOT crypto.** The signature path is doing its job and the difference is authorization: token B was legitimately signed for a different scope or role. This is a scope/role finding in a different class, not a JWT validation failure | Stop pursuing algorithm confusion. Compare the two tokens' claim sets; if B's claims were legitimately issued, this is authz, not `jwt` |
| **My token rejected 401, but a token I obtained legitimately works** | Establishes which token is actually the invalid one. If mine differs only in `kid`, the key lookup failed; if only in `alg`, the algorithm allowlist rejected it. Either way the control is working | Read the error body: an explicit signature/algorithm error vs a key-lookup failure distinguishes an allowlist from a key-resolution gap |
| **`kid` points to a key that 404s** | **Ambiguous and usually benign.** A 404 on the key URL means the key was *resolved by dereference* — that is a positive signal about key resolution — but a 404 is also just a stale `kid` in a token I legitimately hold | Do not report. A lookup failure is a rejection [jwt.technique.stale_or_foreign_kid_key_acceptance]. Only escalate if a *reachable, attacker-controlled* key location both fetches **and** is used |
| **The server rejects an `alg` I offered that it does not support (e.g. `HS512` where the deployment issues RS256)** | **The allowlist is present and working.** This is the desired outcome | Close H2. An RS256->HS256 token rejected with an explicit signature/algorithm error on every attempt, *including* HS384/HS512 variants, is exactly the disproof for the confusion hypothesis [jwt.prerequisite.alg_driven_generic_verify] |
| **An expired token is rejected** | **The control is working.** This is explicitly *not* a validation bypass — the third commonest misreport | Close the `exp` line entirely; a rejection needs no explanation |
| **`kid` header value appears echoed in a stack trace or error body** | **Not proof of dereference.** Many stacks echo the header while the actual key lookup uses a static or pre-resolved set | Wait for the callback, or run the re-host test. Reflection alone leaves the SSRF claim resting on reflection [jwt.fprule.kid_and_jku_need_a_callback_not_reflection] |
| **Library raises an exception / returns a library error object / falls through to an anonymous identity** | **A rejection, not a bypass.** The observable is the protected response, not the absence of an exception — and a library that raises on an unsupported `alg` is doing exactly what RFC 8725 requires | Close unless the fallthrough path serves protected data. Also check for the swallowed-error variant: a signature check that fails *after* a database write, or an algorithm rejection that happens *after* claims were used to select a tenant or account [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass] |
| **Changing `aud`/`iss` produced no behavioural difference** | **Carries no information.** A claim the server never reads yields identical behaviour whether validation is correct or entirely missing | Discard the observation. Mutate a claim the app demonstrably consumes instead [jwt.fprule.unread_claims_prove_nothing] |
| **A token validly signed for another relying party verified at this resource** | **Not necessarily a pass.** RFC 8725 requires `aud` to be present and associated with the recipient, and absence of `aud` must be a rejection — but a single-resource single-audience deployment has nothing to compare against, and a sender-constrained deployment fails on the proof, not the audience | Check whether this deployment has >1 resource and >1 audience. If it has one, substitution is not expressible and there is no finding [jwt.fp_rule.a_valid_signature_on_a_token_meant_for_a_different_recipient_is_not_a_pass] |

## THE REAL FINDING THAT LOOKS LIKE THE FALSE POSITIVES — keep these separate

This is the distinction I most often collapse. Both cases are "a token verified and was honoured". One is a
vulnerability; the other is a correctly-signed token used outside its intended lifetime or recipient.

| Result | Meaning | Next action |
|---|---|---|
| **The app validates the signature and NEVER checks `exp`, `aud` or `iss`** — demonstrated by a mutably signed token with `exp` six months past, or `aud` set to a different relying party, still driving an authorization decision | **This IS a real finding.** The cryptographic layer is intact and the claim layer is absent. Signature success with no claim enforcement is a different defect from signature failure, and it is reportable | Report it. Do **not** file it as "algorithm confusion" — the mechanism is missing claim validation, and the evidence is a validly signed token with a mutated claim reaching an endpoint whose authorization decision depends on it [jwt.fprule.unread_claims_prove_nothing] (as the finding condition, not its disproof) |
| **A token the app rejected as expired** | **NOT a finding.** This is the third commonest misreport: "expired token rejected by the app" reported as a validation bypass | Close. A 401 here is the control working |

## Negative results worth recording

| Result | Meaning | Next action |
|---|---|---|
| All seven matrix variants (control, tampered, RS256->HS256, ES256->HS256, none, case variants, unrelated key) return the same rejection, no variant returns authenticated content or a session cookie | The verifier pins an allowlist and binds key type to algorithm | Record the library default as a hardening observation; do not report [jwt.validation.allowlist_algorithm_and_key_binding] |
| Response is byte-identical in every case | The observable cannot be produced. This test does not apply | No finding may be asserted from this endpoint; state that limitation in the report rather than inferring a verdict [jwt.test.a_verifier_passes_only_if_the_accepted_algorithm] |
| Re-hosting my `jku` key with a different modulus leaves validation tracking the *original* public key | The server used a cached key and never fetched my URL | H4 is dead. Do not report SSRF or key injection [jwt.signal.header_supplied_key_material] |
| All `alg:none` obfuscation variants return client errors, never an authenticated response | Filtering is working, whether by denylist or by library default | Close as not vulnerable and note the library's default [jwt.fp_rule.none_alg_obfuscation_attempts_failing] |
| Only error statuses with signature-verification messages; no forged token ever produced an authenticated response or a session cookie | There is no finding — this is what a verifier with a server-side allowlist looks like | Close the class on this endpoint entirely [jwt.validation.allowlist_algorithm_and_key_binding] |

## The interpretive rule I now apply by default

Never ask "did the server return 200?". Ask **"which identity did the server act on, and what else was in the
request?"** The status code alone has produced every false positive in this class; the identity the response
echoes and the presence of a `Set-Cookie` are what actually separate a bypass from a public page.