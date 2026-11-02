# hypothesize — falsifiable hypotheses, each keyed to an observation actually seen

A claim is not a hypothesis. Each one below names the signal it was generated
from and the observation that would refute it. If you cannot write the refuter,
you have written a claim.

---

**H1 — CL.TE: the front end honours Content-Length, the back end honours chunked.**
*Signal:* a 400-at-edge observation showed the proxy validating framing
[smuggling.evidence.a_front_end_returning_400_for_a_request_carr] while
topology shows a second parser behind it
[smuggling.technique.ht_http_request_smuggling_attacks_are].
*Claim:* a request carrying both a short `Content-Length` and
`Transfer-Encoding: chunked` is forwarded whole by the front end but truncated
at the chunk terminator by the back end, leaving the tail as the next request.
**Refuted if:** both hops resolve the same request boundary for the conflicting
message, or the front end strips the offending header before forwarding so the
back end never sees the ambiguity — in which case there is nothing left to
smuggle.

**H2 — TE.CL: the front end dechunks, the back end trusts the stale Content-Length.**
*Signal:* the same conflicting-header observation, with the edge evidently
rewriting bodies rather than refusing them.
*Claim:* the front end forwards only the dechunked body while the back end
reads `Content-Length` bytes, so the difference is the next request.
**Refuted if:** the front end also rewrites `Content-Length` to match what it
actually forwards — the residue is then empty and no desync is possible. Test
by reading the origin's received `Content-Length`, not by inferring it.

**H3 — TE.TE: both hops read Transfer-Encoding but normalise the header
differently.**
*Signal:* a front end whose documentation or behaviour shows special-casing on
the literal value `chunked`.
*Claim:* one hop honours an encoding list the other truncates — for example a
final coding that is not `chunked`, which leaves the body length underivable
and pushes a front end that only special-cases `chunked` into framing with a
different layer than the back end uses
[smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked].
**Refuted if:** the front end's parser correctly identifies the coding list and
either honours it or rejects the message with a 400 at the edge and no
forwarded request — and note that many modern servers normalise or hard-code
the strict behaviour, so verify the deployed version rather than assuming the
classic bypass still applies.

**H4 — An unexpected Transfer-Encoding value desyncs without any classic split.**
*Signal:* a stack that is known to be strict about `chunked` but was observed to
handle other codings leniently.
*Claim:* `Transfer-Encoding: gzip` can desynchronise a chain with no CL.TE
split at all, because one hop still honours `Content-Length` while another
treats the message as illegally framed — the unexpected encoding value is a
desync probe on its own
[smuggling.variant.ht_transfer_encoding_gzip_was_enough].
**Refuted if:** both hops reject the gzip-coded message identically with a 400
for attacker and victim alike, or the intermediary strips the encoding and the
back end sees clean framing.

**H5 — The defect is connection reuse, not message framing.**
*Signal:* a desync-shaped symptom (queue offset, odd response, hang) with *no*
header ambiguity in any request sent.
*Claim:* front end and back end disagree about connection reuse rather than
about where a message ends, so testing CL.TE and TE.CL ambiguity will never
surface it [smuggling.variant.ht_http_connection_request_smuggling].
**Refuted if:** the desync reproduces from a single unambiguous request with
consistent framing and no `Transfer-Encoding`, which puts the cause straight
back into message framing.

**H6 — The desync is in the response direction.**
*Signal:* response bodies that do not match the request, or a response delivered
on a connection where no matching request was sent
[smuggling.impact.ht_response_desynchronisation_up_to].
*Claim:* one hop dechunks or strips `Transfer-Encoding` on responses while
another still trusts `Content-Length`
[smuggling.technique.ht_when_auditing_modern_stacks_also].
**Refuted if:** every hop applies identical dechunking and honours a consistent
`Content-Length` on responses, or the front end rejects the mismatched response
before a second hop can re-frame it.

**H7 — The downgrade hop is the vulnerable one.**
*Signal:* HTTP/2 at the edge, HTTP/1.1 at the origin.
*Claim:* attacker-chosen framing values survive the translation and reach the
HTTP/1.1 request, because the hop copies rather than regenerates body-length
metadata [smuggling.technique.ht_strip_and_regenerate_body_length_m]; RFC 9113
would have made such a message malformed
[smuggling.test.ht_rfc_9113_is_stricter_than_many_dow].
**Refuted if:** the downgrade path rejects the message at the first hop exactly
as the spec prescribes, or attacker-chosen values are observed NOT to survive
verbatim downstream.

**H8 — The edge validates framing correctly, and there is no finding here.**
*Signal:* a clean 400 on every ambiguous probe
[smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].
*Claim:* both hops resolve the conflict the same way.
**Refuted if:** any probe is accepted AND forwarded while the other hop resolves
it the other way — which you demonstrate by smuggling a second request and
observing a response the attacker never sent. Note that a clean 400 is only a
true negative when the request genuinely never reached the back end,
verifiable by the absence of any second request in back-end logs.

---

**Standing caveat on scope.** A hypothesis about queue poisoning is a
hypothesis about *other people's traffic*. Formulate and test it so that the
desync is observed only on a connection you own — never by prepending a
malformed request to a shared connection and hoping the next legitimate
requester receives the residue.
