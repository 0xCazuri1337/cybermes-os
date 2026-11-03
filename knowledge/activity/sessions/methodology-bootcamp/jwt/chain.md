# jwt — chain model: prerequisites, transition, escalation, blocker

Corpus chain: `jwt-weak-verification-to-impersonation`, goal `account_takeover`.

The corpus summary: a token flaw that lets an attacker influence or bypass signature verification is combined
with a predictable or disclosed subject identifier to mint a token the server accepts as another user. Impact:
the attacker authenticates as an arbitrary account, inheriting that user's sessions, data and any
administrative privileges attached to the role.

The corpus stores this as four ordered steps. Each is reproduced below with its stated prerequisite, then given
the **blocker** — the single condition that most often stops the chain dead at that step.

---

## Step 1 — Establish the verification behaviour with a negative control

**Action (corpus).** Send a request with no token, with a malformed token, and with a well-formed token signed
by a key you control; record which of the three produce a different response.

**Prerequisite.** A protected endpoint that visibly differs between authenticated and unauthenticated callers.

**Transition.** This step converts the endpoint from *unknown* to *token-governed*. Everything after it is
measured against a baseline that is known to mean something.

**Blocker.** *The endpoint is not token-governed.* If all three responses are identical, nothing in the request
path consulted the token, and every subsequent step produces uninterpretable noise. Only the requests whose
responses differ are governed by token validation; without this control every later observation may come from a
route that was never protected, which is the most common way a JWT finding turns out to be nothing.

**Live evidence this blocker fires.** The field record where a valid-looking token, an invalid one, and no token
all returned the same 200 and the same body — the endpoint never verified anything.

---

## Step 2 — Identify the trust anchor the server actually uses

**Action (corpus).** Determine whether it is a fixed key, a key selected by the `kid` or `jku` header, a
per-user key, or a session store that overrides the presented claims.

**Prerequisite.** The ability to compare two tokens that differ only in the header field under test.

**Transition.** This is the branch point of the whole chain. The trust anchor determines which of the four
families in `explain.md` is even reachable:

| Trust anchor | Reachable family | Corpus item |
|---|---|---|
| Fixed key, alg from token | Family 3 — type binding | [jwt.prerequisite.alg_driven_generic_verify] |
| Fixed key, alg pinned server-side | none — chain stops here | [jwt.validation.allowlist_algorithm_and_key_binding] |
| `kid` dereferenced to filesystem/URL | Family 2 — key selection | [jwt.technique.kid_path_traversal_empty_file_secret] |
| Multi-key set, membership only | Family 4 — key distribution | [jwt.technique.stale_or_foreign_kid_key_acceptance] |
| Session store overriding claims | none — claim tampering has no effect at all | [jwt.impact.hth_so_the_integrity_and_authenticity] |

**Blocker.** *Token-embedded key material is ignored.* If every attacker-supplied `jwk`, `jku` and `x5u`
location is ignored and the server verifies only against keys it resolved out of band from its own pinned or
discovered key set, there is no key selection to abuse
[jwt.signal.header_supplied_key_material]. Equally, if `kid` is a selector within an already-trusted set — the
server still rejects a token signed with your own embedded key — the header is being used as designed
[jwt.fp_rule.key_headers_present_is_not_a_vuln]. A `kid` that 404s is a *lookup failure*, i.e. a rejection.

**Second blocker at this step.** *Byte-identity is unavailable.* Even in the confusion branch, the attacker's
copy of the public key must be byte-identical to the server's stored copy, including PEM formatting and
newlines [jwt.prerequisite.obtainable_exact_public_key_bytes]. A JWKS-served base64 DER key against a stored PEM
key is not byte-identical, and the chain stops here for a reason that has nothing to do with the verifier's
logic.

---

## Step 3 — Exploit the trust anchor

**Action (corpus).** If the secret is weak or guessable, forge a token; if the key is selected by a header,
supply your own key; if verification is skipped for a code path, omit the signature entirely.

**Prerequisite.** Control over the key material, the secret, or the algorithm the server will accept.

**Transition.** This converts a parsing weakness into a **signing capability** — the precondition for
impersonation. The forged token must be accepted by the *same verification path* a legitimate token takes.

**Blocker.** *The forged token is accepted on a route that is permissive for everyone.* Algorithm-confusion
proof needs a protected endpoint that rejects the forged token as a comparison; acceptance on a route that
accepts no token at all is not a finding. A 400/401 on a forged JWT is the expected rejection, not evidence of
a flaw — the observable is the protected response, not the absence of an exception
[jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].

**Second blocker.** *The forgery is not stable.* Pointing `kid` at an empty file only yields a signing capability
if traversal payloads produce neither an error nor a fallback to a default key, and the same forged token is
accepted on replay [jwt.technique.kid_path_traversal_empty_file_secret]. A key that works once and then fails
is a cache artefact, not a signing capability.

**Third blocker.** *A library error read as success.* A verification path that throws, returns a library error
object, or falls through to an anonymous identity is a rejection unless the request then proceeds to the
protected resource [jwt.fp_rule.a_library_raising_an_error_is_a_reject_not_a_bypass].

---

## Step 4 — Set the identity claim and confirm the server reissues a session

**Action (corpus).** Set the subject or user identifier claim to a target account, discovering the identifier
format from the application's own responses, and confirm the server reissues a session bound to that identity.
*(Corpus class: `idor` — the final step is an object-level authorization question.)*

**Prerequisite.** Knowledge of the claim that carries identity, and an endpoint that returns target-specific
data.

**Transition.** This is where the chain changes class. The corpus states the condition for impact explicitly: a
verified forgery becomes account takeover, not info disclosure, **only when the edited claim drives server-side
identity or authorization decisions** [jwt.chain_link.forgery_to_account_takeover].

**Blocker.** *The server re-derives identity from server-side state.* If the forged token is accepted
syntactically but the server re-reads a session store, or the edited claim grants no additional access, then
there is no impact to report. Concretely: if the response echoes the ORIGINAL subject rather than the forged
one, the claims are not the source of truth and the chain terminates at step 3 with no impact.

**Second blocker.** *Admin-shaped page, empty data.* If the privileged route renders an identical shell for
every role — admin, auditor, and role-claim-deleted alike — then privileged DATA or an action was never
obtained, and the "escalation" is a routing artefact.

---

## Chain diagram with blockers

```
   [Step 1] negative control
        |  BLOCKER: endpoint not token-governed (all responses identical)
        v
   [Step 2] identify trust anchor
        |  BLOCKER A: token-embedded key material ignored / kid is a selector only
        |  BLOCKER B: public key not byte-identical to stored copy
        v
   [Step 3] forge a token
        |  BLOCKER A: acceptance only on a route permissive for everyone
        |  BLOCKER B: forgery not stable on replay (cache)
        |  BLOCKER C: library error mistaken for success
        v
   [Step 4] set identity claim, confirm reissued session
        |  BLOCKER A: server re-derives identity from server-side state
        |  BLOCKER B: privileged page shell identical for every role
        v
   ACCOUNT TAKEOVER  (jwt-weak-verification-to-impersonation)
```

## Where the escalation could go next

The corpus does not record a second chain for this class, and I will not invent one. The honest statement of the
escalation surface is bounded by what step 4's blocker says: if the identity claim drives authorization, the
attacker inherits that user's data, sessions and any administrative privileges attached to the role — that is
the top of this chain, and it is reached in one step from a signing capability. Where a forged token grants only a
narrow scope, the chain's next move is not a JWT technique at all; it is the `idor` step the corpus already
attaches to step 4.

## The chain-level lesson

Six of the eight blockers above are the same blocker wearing different clothes: *an observation that changes
without the trust decision changing*. Step 1's identical responses, step 2's ignored key material, step 3's
cache, step 4's echoed original subject — all are "the server behaved differently, therefore the server trusted
me", which is the inference this class punishes hardest. The chain does not proceed on a status code. It
proceeds on a protected response that reflects **the identity I chose**, and not one step before that has a
credential-free baseline.