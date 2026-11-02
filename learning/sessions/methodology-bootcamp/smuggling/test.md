# test — ordered plan, each step with its expected information gain

Ordered cheapest-and-most-decisive first. Every step names what it *learns*,
not just what it sends. All traffic is confined to connections and accounts I
control.

## Step 0 — Baseline capture (do this before any payload)

Send a single ordinary, well-formed HTTP/1.1 request and record the full raw
request and response, plus the origin-side log line for it.
**Information gain:** establishes what a normal aligned request looks like on
this connection, so every later anomaly is attributable. Without a baseline, a
400 is unreadable — it could be the framing rejection you expect or the
endpoint's ordinary behaviour, and those are indistinguishable.

## Step 1 — Framing-control probe: invalid/duplicated Content-Length, no TE

Send a bare request with an invalid or duplicated `Content-Length` and no
`Transfer-Encoding`.
**Information gain:** identifies which layer performs framing validation. A 400
confirms the endpoint's framing validation and **closes off the CL.CL variant
there** [smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive].
It is also the cheapest way to tell an edge-generated error page from the
application's own — and the useful next question is which layer decided, not
what the status code was [smuggling.evidence.a_front_end_returning_400_for_a_request_carr].
**Trap:** the spec's exception — a value parsing as a comma-separated list
where every element is valid and all identical is processed as that single
value, so a probe using a *consistent* list is not invalid framing and a 400
there means something else. Retry with a genuinely conflicting list before
concluding.

## Step 2 — Conflict probe: both TE and CL, one hop's choice

Send one request carrying both `Transfer-Encoding: chunked` and a
`Content-Length`.
**Information gain:** tells you whether the edge accepts ambiguity or refuses
it. A 400 here is the spec-mandated outcome and a negative control, not a failed
attack [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].
An accepted-and-forwarded request is the precondition for every CL.TE and
TE.CL hypothesis; a refusal at the edge with no forwarded request closes both
at that hop.

## Step 3 — Which boundary did the back end use?

Read the origin's received headers / access log for the Step 2 request: was
`Content-Length` rewritten to match what was actually forwarded, was
`Transfer-Encoding` stripped, and did the header even arrive?
**Information gain:** discriminates CL.TE from TE.CL directly, from evidence
rather than inference. A header that never reached the origin proves nothing
about disagreement — a header dropped at the edge never reaches the tier you
were comparing [smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync].
The same read on a downgrade hop shows whether attacker-chosen values survived
verbatim [smuggling.technique.ht_strip_and_regenerate_body_length_m].

## Step 4 — Header-normalisation probes (TE.TE)

With `chunked` confirmed accepted, vary the *spelling*: duplicated
`Transfer-Encoding` headers, whitespace before the colon, a coding list such as
`x, chunked`, and a final coding that is not `chunked`.
**Information gain:** separates "both hops disagree about CL vs TE" from "both
hops read TE but normalise it differently". The non-chunked final coding is
the highest-value probe because it leaves the body length underivable, defeating
a front end that only special-cases the literal `chunked`
[smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked].
**Stop condition:** if both hops reject every variant, stop — many modern
servers normalise or hard-code the strict behaviour, so verify the deployed
version rather than assuming the classic bypass still applies.

## Step 5 — Unexpected coding probe

Send `Transfer-Encoding: gzip` with no classic CL.TE split.
**Information gain:** tests whether an unexpected encoding value alone desyncs
the chain, because one hop may still honour `Content-Length` while another
treats the message as illegally framed
[smuggling.variant.ht_transfer_encoding_gzip_was_enough]. A clean 400 at both
hops for attacker and victim alike kills this probe cheaply.

## Step 6 — Self-inflicted desync (the only proof-shaped step)

On a connection **you** control and that no other client will be handed, send a
single request whose framing metadata is ambiguous, and read the origin's access
log for that connection.
**Information gain:** this is the decisive test. A second request appearing in
the back-end log for a connection where you sent one is the proof
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
**Scope rule:** never run this on a connection shared with unowned traffic, and
never send a residue whose next recipient is a stranger. Keep it on your own
connection so the only victim of a desync is you.
**Negative:** exactly one log entry for that connection means no
desynchronisation occurred, whatever status code you received.

## Step 7 — Response-direction check

Audit the response path: does one hop dechunk or strip `Transfer-Encoding`
while another trusts `Content-Length`?
**Information gain:** modern stacks desynchronise in the response direction
too, so a hunt that only probes requests can be blind to the more damaging form
[smuggling.technique.ht_when_auditing_modern_stacks_also].

## Step 8 — Reuse-dependent forms, before declaring the hunt over

A chain that showed no CL.TE or TE.CL ambiguity still has sub-forms left —
those relying on connection reuse, connection state, or the client — so a clean
header-desync result does not close the hunt
[smuggling.variant.ht_legitimate_reuse_required_cases_st].
**Information gain:** separates "no framing bug" from "no desync bug at all".

## Step 9 — Downgrade-boundary confirmation (only if the topology has one)

Confirm at the H2→H1 hop that connection-specific headers such as
`transfer-encoding` or `upgrade` are treated as malformed per RFC 9113, and that
`Content-Length` equals the sum of DATA payload bytes.
**Information gain:** a hop that TOLERATES these is exactly where H2-to-H1
smuggling hides [smuggling.test.ht_rfc_9113_is_stricter_than_many_dow], because
H2's explicit frame lengths leave no ambiguity to exploit inside H2 itself
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr].

## Ordering rationale

Steps 0–2 are three requests and eliminate the majority of targets. Steps 3–5
are log reads and header variants. Step 6 is the only step that can produce
evidence, and it is also the only step with any safety cost — which is why it
sits after every cheap elimination and is scoped to your own connection.
