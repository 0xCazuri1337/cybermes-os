# explain — request smuggling from first principles, and the exact invariant that fails

A class name is not an explanation. This one explains what breaks: **the
failing invariant is that two HTTP parsers on the same byte stream agree on
where a message ends.** Everything else follows from that single disagreement
[smuggling.technique.http_request_smuggling_arises_where_a_front_end_and_back_e].

## The chain, step by step

**Attacker input.** One HTTP/1.1 request whose body-length metadata is
self-contradictory or whose framing header is written in a form that not every
parser canonicalises identically. The attacker controls every byte up to the
ambiguity and nothing after it.

**Parser.** The front end (reverse proxy, CDN, load balancer, WAF) parses the
request and decides the body boundary. The back end (application server,
framework) then parses what the front end forwards and may decide it
differently [smuggling.technique.ht_http_request_smuggling_attacks_are]. Two
independent parsers, two independent implementations, two independent notions
of "end of message".

**Normalisation.** This is where the class forks into three distinct claims,
and the fork is the substance of this class because the three fail at
different boundaries:

1. **CL.TE** — the front end honours `Content-Length`, the back end honours
   `Transfer-Encoding: chunked`. The request is forwarded whole, but the back
   end stops reading at the chunk terminator, leaving the tail of the
   `Content-Length` region as the beginning of the *next* message.
2. **TE.CL** — the reverse pairing: the front end dechunks and forwards only
   the dechunked body, while the back end trusts the `Content-Length` value the
   front end failed to rewrite. The residue becomes the next request.
3. **TE.TE** — both hops read `Transfer-Encoding`, but they do not agree on the
   *value*: which occurrence wins when the header appears twice, whether a
   space before the colon counts, whether an unrecognised coding before
   `chunked` is honoured or discarded, and whether a final coding other than
   `chunked` leaves the length underivable at all
   [smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked].
   Here the failing invariant is *header normalisation*, not the choice
   between CL and TE.

**Validation.** This is where most hunts correctly die. A front end that
rejects ambiguous framing outright removes the whole class at that hop: both a
400 on a request carrying both headers
[smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack]
and a 400 on an invalid or duplicated `Content-Length` with no
`Transfer-Encoding` are the spec-mandated, correct behaviour
[smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive].

**Trust decision.** The residue is now a complete, syntactically valid request
line on a connection the front end believes is idle and aligned. Nothing
re-validates it: it was "already inside" a message the front end closed. The
smuggled request therefore inherits the front end's authorisation decisions —
including, usually, the fact that the WAF never saw it.

**Internal operation.** The back end executes the smuggled request as a
legitimate one. Because it is prepended to whatever legitimate message is next
on that shared connection, the smuggled prefix rides in on the next user's
traffic [smuggling.technique.http_request_smuggling_arises_where_a_front_end_and_back_e].

**Observable result.** Two directions, and they need different evidence:

- *Request direction.* A request the attacker never sent appears in the
  back-end access log for that connection
  [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
- *Response direction.* The shared connection delivers a response computed for
  the smuggled request to a different client — which is simultaneously the
  proof of desynchronisation and the theft of the victim's response
  [smuggling.impact.ht_response_desynchronisation_up_to].

## The invariant, stated once

> For every byte on a connection, **exactly one** parser must assign it to
> **exactly one** message. Smuggling exists iff the assignment is not a
> function of the bytes.

Two corollaries that decide most hunt outcomes:

- A **single** parser in front of the app cannot smuggle against itself. You
  need a disagreeing *pair*; one reverse proxy that both validates and
  forwards with one parser produces a 400, not a desync.
- The failure is a property of the **chain**, not the endpoint. An origin that
  is perfectly strict is still vulnerable when a laxer tier forwards to it.
  Refuted, and the class closes, only if both hops resolve the same boundary
  for the same request, or the front end strips the offending header before
  forwarding so the back end never sees the ambiguity.

## The boundary beyond HTTP/1.1

HTTP/2 removes the precondition rather than fixing the bug: frames carry
explicit lengths, so there is no framing ambiguity for a classic desync to
exploit, and any H2 smuggling attempt has to originate at a **downgrade
boundary** rather than in the H2 layer itself
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr]. At such a hop
the relevant boundary is body-length metadata: the translating hop must
regenerate `Content-Length` and `Transfer-Encoding` rather than copy the
attacker's values into the HTTP/1.1 request
[smuggling.technique.ht_strip_and_regenerate_body_length_m], and RFC 9113 makes
an HTTP/2 message carrying connection-specific headers malformed while
requiring `Content-Length` to equal the sum of DATA payloads — so a downgrade
path that tolerates those is where the smuggling hides
[smuggling.test.ht_rfc_9113_is_stricter_than_many_dow].

Modern stacks also desynchronise in the **response** direction, so the audit
must cover the response translation layer and look for one hop that dechunks
or strips `Transfer-Encoding` while another still trusts `Content-Length`
[smuggling.technique.ht_when_auditing_modern_stacks_also].
