# generalize — common, uncommon and defensive variants

## Common — the forms you will meet first

| Variant | The disagreement | Where it lives |
|---|---|---|
| **CL.TE** | Front end uses `Content-Length`, back end uses `Transfer-Encoding: chunked` | Classic front end strict-on-CL, back end lenient-on-TE stacks [smuggling.technique.ht_http_request_smuggling_attacks_are] |
| **TE.CL** | Front end dechunks and forwards, back end trusts the stale `Content-Length` | Classic front end lenient-on-TE, back end strict-on-CL stacks [smuggling.technique.ht_http_request_smuggling_attacks_are] |
| **CL.CL** | Two `Content-Length` values the two hops resolve differently | Closed off quickly: an invalid or duplicated `Content-Length` with no TE must yield 400, so the 400 confirms framing validation and closes this variant there [smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive] |

## TE.TE — the header-normalisation family

Both hops read `Transfer-Encoding`; they disagree on the **value**, not on the
choice of CL vs TE. The failing invariant is header normalisation differing
between hops.

- **Duplicate `Transfer-Encoding` headers** — one hop takes the first, the other
  the last.
- **Whitespace before the colon** — `Transfer-Encoding : chunked`.
- **Coding lists** — `Transfer-Encoding: x, chunked`: one hop honours the whole
  list, the other truncates at the first recognised token.
- **Non-chunked final coding.** The highest-value member of the family. A final
  coding that is not `chunked` makes the body length underivable, so a front end
  that only special-cases the literal value `chunked` can be pushed into framing
  with a different layer than the back end uses
  [smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked]. Many modern servers normalise or hard-code the strict behaviour, so verify the deployed version.

## Uncommon — the forms that survive a clean header-desync result

**1. Unexpected encoding values.** `Transfer-Encoding: gzip` can desynchronise
a chain with no classic CL.TE split at all, because one hop still honours
`Content-Length` while another treats the message as illegally framed — the
unexpected encoding value is a desync probe on its own
[smuggling.variant.ht_transfer_encoding_gzip_was_enough].
**Disproof:** both hops reject it identically with a 400 for attacker and
victim alike, or the intermediary strips the encoding and the back end sees
clean framing.

**2. Connection-reuse / HTTP connection request smuggling.** When front end and
back end disagree about *connection reuse* rather than message framing, the
defect is a connection-state or routing mismatch — so testing CL.TE and TE.CL
header ambiguity will never surface it
[smuggling.variant.ht_http_connection_request_smuggling].
**Disproof:** the desync reproduces from a single unambiguous request with
consistent framing and no `Transfer-Encoding`, which puts the cause back in
message framing.

**3. The reuse-dependent tail.** A chain that shows no CL.TE or TE.CL ambiguity
still has sub-forms left to test — the ones relying on connection reuse,
connection state, or the client — so a clean header-desync result does **not**
close the hunt [smuggling.variant.ht_legitimate_reuse_required_cases_st].
**Disproof:** no desync can be induced by any manipulation of connection reuse
or by a client-side mismatch.

**4. HTTP/2 downgrade smuggling.** H2's explicit frame lengths leave no framing
ambiguity inside H2, so the defect has to originate at the downgrade boundary
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr]. The
smuggling-relevant boundary there is body-length metadata: the translating hop
must rewrite `Content-Length` and `Transfer-Encoding` rather than copy the
attacker's values [smuggling.technique.ht_strip_and_regenerate_body_length_m].
RFC 9113 makes connection-specific headers such as `transfer-encoding` or
`upgrade` in an HTTP/2 message malformed and requires `Content-Length` to equal
the sum of DATA frame payloads, so a downgrade path that *tolerates* these is
exactly where it hides [smuggling.test.ht_rfc_9113_is_stricter_than_many_dow].

**5. Response-direction desync.** Modern stacks desynchronise in the response
direction too, so the audit must cover the response translation layer and look
for one hop that dechunks or strips `Transfer-Encoding` while another still
trusts `Content-Length` [smuggling.technique.ht_when_auditing_modern_stacks_also].
Its payoff is response control: a response computed for the attacker's smuggled
request delivered to a different client — simultaneously the proof of the
desync and the theft of the victim's response
[smuggling.impact.ht_response_desynchronisation_up_to].

## Defensive variants — behaviours that LOOK like this class and are not

These are not smuggling; recognizing them prevents bad reports.

- **HTML smuggling.** A ~1KB HTML file downloading an image polyglot and
  reconstructing an XOR-obfuscated payload in the browser. One client-side
  reconstruction, zero HTTP parsers disagreeing
  [smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync]. Disproof: a
  replayed pair with conflicting CL and TE framing where the back end serves the
  second request under the first request's connection.
- **Spec-mandated 400.** A front end returning 400 for a request carrying both
  TE and CL is behaving correctly and is a negative control, not a failed
  attack [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].
- **Header dropped at the edge.** One tier ignoring a malformed header the other
  never received is not a disagreement
  [smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync].
- **Appliance admin-path probing.** Requests to administrative asset paths and
  the repetition of a mundane static-path request from changing infrastructure
  are early reconnaissance fingerprints
  [smuggling.signal.admin-path-probe-as-recon-signal]. They raise the value of
  testing this class; they are not a desync.

## Generalization rule

Do not treat "CL.TE returned 400" as "class closed". The corpus's own position
is that a clean header-desync result leaves the reuse-dependent sub-forms
untested [smuggling.variant.ht_legitimate_reuse_required_cases_st], the response
direction still needs its own audit
[smuggling.technique.ht_when_auditing_modern_stacks_also], and a downgrade
hop is a separate surface from the one you just probed
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr]. Close the class
only when framing, reuse, response direction and any downgrade boundary have all
returned evidence-backed negatives.
