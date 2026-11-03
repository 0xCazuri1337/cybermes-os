# interpret — result → meaning → next action

The ambiguous and negative rows are the ones that matter; hunts die here.

## Strong results

| Result | Meaning | Next action |
|---|---|---|
| Second request appears in the back-end log for a connection where you sent one | Desync confirmed; the framing conflict is the cause | Capture the full raw pair and the two log lines; this is the reportable finding [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code] |
| Response arrives on your connection for a request you did not send | Response-direction desync; the shared connection is now misaligned | Record which client the response was computed for; response control is both the proof and the theft [smuggling.impact.ht_response_desynchronisation_up_to] |
| Front end accepts a conflicting TE+CL request AND forwards it | Both CL.TE and TE.CL remain live; the precondition holds [smuggling.technique.ht_http_request_smuggling_attacks_are] | Go to Step 3 and read what the origin actually received |
| Origin received a `Content-Length` that does not match the forwarded body length | The translation hop copied rather than regenerated body-length metadata | Downgrade-hop candidate; confirm attacker values survive verbatim [smuggling.technique.ht_strip_and_regenerate_body_length_m] |

## Ambiguous results — read these carefully

| Result | Meaning | Next action |
|---|---|---|
| **Timeout / hang on the connection** | Weak evidence only. A timing change, an unusual status, or a connection reset is equally consistent with ordinary proxy behaviour, so a hang never proves this class [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code] | Do NOT report. Go read the back-end log. If it shows exactly one request for that connection, the connection was not desynchronised and you have a true negative regardless of what the client saw |
| **400 on the conflicting TE+CL probe** | Ambiguous between "edge correctly refused" and "edge refused after forwarding". A 400 is the spec-mandated outcome of a request carrying both headers, and the useful question is which layer decided, not what the status was [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack] | Treat as a negative control UNLESS the request genuinely reached the back end. Check the back-end log: a 400 is only clean when no second request appears there [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code] |
| **A second request shows up in the response stream** | Ambiguous between a real smuggled prefix and your own pipelining. If your client sent both requests, the second response is yours and proves nothing | Re-run with ONE request per connection. The marker's presence is only evidence if the marker appears without you sending the corresponding request [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code] |
| **A retrying client resent the original request** | The duplicate log line is the retry, not a smuggle | Re-run with retries disabled and one connection. A marker explained by client retry is not attributable to the framing conflict |
| **400 on a duplicated Content-Length with a CONSISTENT comma list** | Not invalid framing at all — a list whose elements are all valid and identical is processed as that single value, so the 400 means something unrelated [smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive] | Retry with a genuinely conflicting list before drawing any conclusion about CL.CL |
| **The malformed header appears accepted at the edge but absent from the origin** | No disagreement occurred — a header dropped at the edge never reaches the tier you were comparing [smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync] | Discard the header-name variant of the finding. Capture both hops or read both logs before re-reporting |

## Negative results — how to read a genuine zero

| Result | Meaning | Next action |
|---|---|---|
| Every ambiguous probe returns a clean 400 at the edge with no forwarded request | Both hops resolve the conflict identically; the class is closed at that hop [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack] | Record it as a negative control with the raw pairs. Do NOT escalate |
| No desync from any connection-reuse or client-side manipulation | The reuse-dependent sub-forms are absent, not merely untested by you [smuggling.variant.ht_legitimate_reuse_required_cases_st] | Only now may the hunt close |
| A single reverse proxy in front of the app, one parser throughout | No disagreeing pair exists, so no smuggling is possible | Close the class on topology. Say so explicitly rather than reporting a non-finding |
| HTTP/2 front end, HTTP/1.1 smuggling attempted on the same connection | HTTP/1.1 framing ambiguity is not expressible on an H2 connection; frames carry explicit lengths [smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr] | Redirect the effort to the downgrade hop, or close. A negative here says nothing about the H2→H1 boundary |
| A tiny HTML attachment rebuilds an obfuscated payload in the browser | HTML smuggling, not request desync — no two HTTP parsers are involved [smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync] | Reclassify out of this class entirely |
| Repeated requests to appliance administrative asset paths, no desync evidence | Reconnaissance fingerprint only; ordinary client behaviour is the alternative reading [smuggling.signal.admin-path-probe-as-recon-signal] | Raise test priority for this class; do not report anything |

## The escalation rule

A status code is never a verdict. Escalate on exactly one observation: a
request the attacker never sent, appearing in the back-end log for a connection
where you sent one request
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
Everything else — 400s, 500s, hangs, resets, odd headers — routes to a log read,
not to a finding.
