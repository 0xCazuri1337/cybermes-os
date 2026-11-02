# chain — prerequisites, transition, escalation, and the blocker at each step

Each step below names its prerequisite, the transition that gets you to the
next step, the escalation, and — critically — **the blocker**: the condition
that stops the step dead. A chain without blockers is a story.

---

## Step 0 — Prerequisite: a disagreeing parser pair exists

**Precondition.** At least two HTTP/1.1 parsers read the same bytes: an edge
(proxy, CDN, WAF, gateway) and an origin (app server, framework). This is the
class's precondition — the test is one request whose `Content-Length` and
`Transfer-Encoding` disagree, then checking which value the back end uses to
find the request boundary [smuggling.technique.ht_http_request_smuggling_attacks_are].

**Blocker.** A single proxy in front of the app. One parser cannot disagree with
itself, so ambiguous framing is either handled consistently or refused with a
400 — there is nothing to smuggle. This blocker is terminal for the whole chain
and is detectable from topology before a single request is sent.

**Second blocker.** An HTTP/2-only path with no downgrade: frames carry explicit
lengths, so there is no framing ambiguity for a classic desync to exploit in the
H2 layer itself, and any H2 attempt has to originate at the downgrade boundary
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr].

---

## Step 1 — Transition: get the ambiguous request past the front end

**Transition.** The front end must *accept and forward* a request whose framing
metadata is self-contradictory, while the back end resolves it the other way.

**Blocker.** Spec-mandated rejection. A 400 on a request carrying both
`Transfer-Encoding` and `Content-Length` is exactly what HTTP/1.1 message
parsing requires, and it is a negative control, not a failed attack
[smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack];
likewise an invalid or duplicated `Content-Length` with no TE, which must yield
400 and whose 400 closes off the CL.CL variant at that hop
[smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive].
When this blocker fires, the chain stops — unless a *different* hop (a
downgrade boundary, or another host in the chain) tolerates the ambiguity.

**Escalation fork.** If CL and TE are refused, the chain does not die; it
escalates to the TE.TE sub-chain, where both hops read Transfer-Encoding and
disagree on the *normalisation* — duplicate headers, whitespace before the
colon, a coding list, or a non-chunked final coding that leaves the body length
underivable [smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked].

---

## Step 2 — Transition: the residue becomes a request

**Transition.** The bytes the front end counted as part of request N are read by
the back end as the start of request N+1. Because the smuggled request is
prepended to the next legitimate user's request, it is executed as a real one
[smuggling.technique.http_request_smuggling_arises_where_a_front_end_and_back_e].

**Blocker — the hard one.** A front end that strips the offending header before
forwarding, so the back end never sees the ambiguity at all. Conversely, a
header the edge drops is not a disagreement: if it exists in only one layer,
the layers never disagreed and the header-name variant must be discarded rather
than reported [smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync].

**Second blocker — definitional.** If the residue never reaches the back end
because the front end closes the connection on the malformed message, there is
no second request. Confirm by log, not by the client-visible status code.

---

## Step 3 — Escalation: from desync to response control

**Escalation.** A confirmed desync is a mechanism. The impact is response
control: the attacker makes the shared connection deliver a response computed
for their own smuggled request to a *different client*, which is both the proof
of the desync and the theft of the victim's response
[smuggling.impact.ht_response_desynchronisation_up_to]. The same defect exists
in the response direction on modern stacks, where one hop dechunks or strips
Transfer-Encoding while another trusts Content-Length
[smuggling.technique.ht_when_auditing_modern_stacks_also].

**Blocker.** Response control is refuted if the smuggled request's response
always returns on the connection that sent it, or if the desync only ever shows
up as connection errors with no cross-client response delivery observed
[smuggling.impact.ht_response_desynchronisation_up_to].

**Safety blocker (non-negotiable).** The escalation step is where this chain
would harm a third party. The maximum-safe-proof rule forbids demonstrating
cross-client response delivery against traffic you do not own. Demonstrate the
desync as a **self-inflicted desync on your own connection**, or by passive
log evidence; state the cross-client consequence as the mechanism's meaning, not
as a captured exploit.

---

## Step 4 — Transition: the downgrade path

**Transition.** If an H2→H1 hop exists, the smuggling-relevant boundary there is
body-length metadata — the translating hop must regenerate `Content-Length` and
`Transfer-Encoding` rather than copy attacker values into the HTTP/1.1 request
[smuggling.technique.ht_strip_and_regenerate_body_length_m].

**Blocker.** A conforming downgrade path. RFC 9113 makes an HTTP/2 message
carrying connection-specific headers such as `transfer-encoding` or `upgrade`
malformed, and requires `Content-Length` to equal the sum of DATA frame
payloads; a path that rejects such a message at the first hop exactly as the
spec prescribes refutes the finding
[smuggling.test.ht_rfc_9113_is_stricter_than_many_dow]. Attacker-chosen values
surviving verbatim downstream is the finding; a regenerating hop blocks it.

---

## Step 5 — Transition: off-framing sub-forms

**Transition.** When framing is clean, the chain does not end. A chain that
shows no CL.TE or TE.CL ambiguity still has sub-forms relying on connection
reuse, connection state, or the client, so a clean header-desync result does not
close the hunt [smuggling.variant.ht_legitimate_reuse_required_cases_st].
Separately, an unexpected encoding value such as `Transfer-Encoding: gzip` can
desynchronise a chain with no classic split at all, because one hop still
honours Content-Length while another treats the message as illegally framed
[smuggling.variant.ht_transfer_encoding_gzip_was_enough].

**Blocker.** A front end and back end that disagree about *connection reuse*
rather than message framing produce a connection-state or routing mismatch that
CL.TE/TE.CL header testing will never surface
[smuggling.variant.ht_http_connection_request_smuggling]; and the reuse forms
are absent only if no desync can be induced by any manipulation of connection
reuse or by a client-side mismatch
[smuggling.variant.ht_legitimate_reuse_required_cases_st].

---

## Chain summary

```
[disagreeing parser pair]  --blocker: single proxy, or H2-only with no downgrade
        |
        v
[front end forwards ambiguity]
        --blocker: spec-mandated 400 at the edge
        |                     (escalation fork -> TE.TE normalisation variants)
        v
[residue executes as request N+1]
        --blocker: header stripped before forwarding; connection closed
        v
[response control]  <-- SAFETY BLOCKER: only self-inflicted desync may be demonstrated
        |
        v
[downgrade / reuse-dependent sub-forms]  --blocker: conforming regenerating hop
```

The chain terminates only when framing, response direction, any downgrade
boundary and the reuse-dependent forms have each returned an evidence-backed
negative with its disproof recorded.
