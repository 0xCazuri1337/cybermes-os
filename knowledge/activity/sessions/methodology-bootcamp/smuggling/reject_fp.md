# reject_fp — misleading cases and the disproof test for each

Every case below has a disproof. A rejection without a disproof test is just an
opinion; the test is what makes the rejection reproducible.

---

## FP1 — A single reverse proxy in front of the application

**The misleading case.** The topology shows an edge proxy and an origin server,
so it *looks* like the two-parser precondition for smuggling
[smuggling.technique.ht_http_request_smuggling_attacks_are].

**Why it is a false positive.** One proxy in front of the app is not a
*disagreeing pair* — it is one parser that both validates and forwards. It has
no second implementation to disagree with, so ambiguous framing is either
accepted consistently (no desync) or refused (a 400). The precondition requires
two parsers reading the same bytes under different rules, and a single proxy
supplies one rule.

**Disproof test.** Identify the actual parser count by reading what the origin
received for one request: if the origin's request shows exactly one consistent
framing decision made by a single component, the pair does not exist. To make it
a real finding you must find a *second* independent parser (CDN edge + origin,
WAF + app server, gateway + framework) and show they resolve the same request
differently. **Only** a successful desynchronisation — smuggling a second
request and observing a response the attacker never sent — upgrades this from
false positive to finding.

---

## FP2 — A normal 400 "invalid request" from the front end

**The misleading case.** A 400 on an ambiguous request *looks* like a desync
signal, and a 400 on a malformed request looks like the edge noticing something
wrong. It is neither.

**Why it is a false positive.** A front end returning 400 for a request
carrying both `Transfer-Encoding` and `Content-Length` is behaving exactly as
HTTP/1.1 message parsing requires. It must be logged as a **negative control**,
not as an unexploitable smuggling attempt
[smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].
The same holds for an invalid or duplicated `Content-Length` with no
`Transfer-Encoding`: that is an unrecoverable framing error that must yield 400,
so the 400 confirms framing validation and closes the CL.CL variant
[smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive].

**Disproof test.** It is a real finding only if the front end *accepts the
ambiguous request and forwards it* while the back end resolves the conflict the
other way. The disproof is the successful desynchronisation, not the absence of
one: a 400 is only a clean negative when the request genuinely never reached
the back end, verifiable by the fact that no second request appears in
back-end logs [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].

**Sub-trap.** A 400 on a *consistent* comma-separated `Content-Length` list is
not even invalid framing — such a list is processed as the single value, so the
400 means something else entirely. Retry with a genuinely conflicting list
before concluding anything
[smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive].

---

## FP3 — HTTP/2 front end where HTTP/1.1 smuggling is not expressible

**The misleading case.** The target advertises HTTP/2 and `h2c` upgrade, so an
HTTP/1.1 `Content-Length` / `Transfer-Encoding` conflict test "fails", and a
report may still be written up as "smuggling not exploitable".

**Why it is a false positive.** Because HTTP/2 frames carry explicit lengths,
there is no framing ambiguity for a classic desync to exploit inside H2 at all.
Any H2 smuggling attempt has to originate at the **downgrade boundary** rather
than in the H2 layer itself
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr]. A negative
result for H1 payloads on an H2 connection is a statement about the wrong layer.

**Disproof test.** It is a real finding if the downgrade path *tolerates* what
RFC 9113 makes malformed — an HTTP/2 message carrying connection-specific
headers such as `transfer-encoding` or `upgrade`, or a `Content-Length` that
does not equal the sum of DATA frame payloads. That non-conforming tolerance is
the condition being tested for; a first hop that rejects the message exactly as
the spec prescribes refutes it
[smuggling.test.ht_rfc_9113_is_stricter_than_many_dow]. Confirm at the
translating hop that it *regenerates* `Content-Length` and `Transfer-Encoding`
rather than copying attacker values; attacker-chosen values surviving verbatim
into the downgraded request is the finding
[smuggling.technique.ht_strip_and_regenerate_body_length_m].

---

## FP4 — HTML smuggling mistaken for request desync

**The misleading case.** A roughly 1KB HTML file that downloads an image
polyglot and reconstructs an XOR-obfuscated payload in the browser is filed
under "smuggling" because the word matches and the payload is hidden.

**Why it is a false positive.** This is HTML smuggling, not HTTP request
smuggling. Smuggling requires two HTTP parsers to disagree on message
boundaries; a client-side reconstruction involves no second parser at all
[smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync].

**Disproof test.** Replay a pair of requests with conflicting
`Content-Length` and `Transfer-Encoding` framing and show the back end serving
the second request under the first request's connection — that is two HTTP
parsers disagreeing rather than a single client-side reconstruction
[smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync]. If you
cannot produce that, it is HTML smuggling; reclassify it.

---

## FP5 — "The edge ignored it, the origin honoured it" (header-name variant)

**The misleading case.** One tier accepts a header and another drops it, which
reads exactly like a desync.

**Why it is a false positive.** Concluding that front end and back end disagree
because one accepts and one drops a malformed header is a false positive
*unless the request was actually forwarded* — a header dropped at the edge never
reaches the tier whose behaviour you are comparing.

**Disproof test.** It IS a real disagreement if the header demonstrably reaches
the back end — present in the origin's received headers, or honoured as a
distinct parameter there — and is simultaneously ignored, dropped, or treated as
a duplicate by the front end. Capture both hops or read both logs; if the
header exists in only one, the layers never disagreed and the header-name
variant of this finding should be discarded rather than reported
[smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync].

---

## FP6 — The second response caused by your own pipelining

**The misleading case.** Two responses arrive on one connection after a
conflicting-framing probe, and it looks like a desync.

**Why it is a false positive.** Your client sent both requests. The second
response is yours.

**Disproof test.** Re-run with exactly ONE request per connection. The marker
must appear without you having sent the corresponding request; if it appears
because a retrying client resent the original, or because you genuinely sent a
second request, the log evidence is not attributable to the framing conflict and
the claim collapses
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

---

## FP7 — Status-code and timing evidence

**The misleading case.** A 500, an unusual status, a slow response, or a
connection reset after an ambiguous probe, offered as evidence of smuggling.

**Why it is a false positive.** A timing change, an unusual status, or a
connection reset is equally consistent with ordinary proxy behaviour; none of
them is evidence that the connection desynchronised.

**Disproof test.** The absence of a second request in the back-end log is
dispositive. If the log contains exactly one request for that connection, the
connection was not desynchronised and no smuggling occurred regardless of the
response the attacker received
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

---

## FP8 — The classic bypass assumed to still work

**The misleading case.** A textbook payload (obfuscated `Transfer-Encoding`,
duplicate headers) is reported on the strength of the technique being famous.

**Why it is a false positive.** Many modern servers normalise or hard-code the
strict behaviour; the classic bypass may simply not apply to the deployed
version
[smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked].

**Disproof test.** It is blocked when the front end and back end both reject the
variant, or when the front end's parser correctly identifies the coding list and
either honours the transfer encoding or rejects the message — a 400 at the edge
with no forwarded request. Verify the actual version rather than assuming, and
confirm the discrepancy with the log-based proof before reporting
[smuggling.bypass.transfer_encoding_with_a_non_chunked_final_coding_defeats_front_ends_that_only_check_for_chunked].

---

## Rejection discipline

Record every rejection with its disproof test and its result. A rejection you
cannot reproduce is indistinguishable from a miss, and the audit trail is what
tells the next person which hypotheses are already dead.
