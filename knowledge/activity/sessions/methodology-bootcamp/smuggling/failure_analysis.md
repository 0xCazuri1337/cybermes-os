# failure_analysis — a real failure mode of this class, diagnosed

The canonical way this class kills a hunt: **you see something anomalous, you
build the smuggle narrative, and the anomaly turns out to have nothing to do
with framing.** Here is the failure, decomposed.

---

## The failure: "the timeout that was a Content-Length mismatch"

**Expected.** A conflicting `Content-Length` / `Transfer-Encoding` request is
accepted by the front end and forwarded; the back end reads a shorter body, so
the connection hangs waiting for bytes that never arrive; then the smuggled
prefix appears in the back-end log. I expected a desync within one or two
probes.

**Actual.** Every probe returned a hang or a read timeout, and no second request
ever appeared in the back-end log. On the fourth attempt I gave up, wrote the
finding up as "smuggling suspected, front end hangs on ambiguous framing", and
would have shipped a false positive.

**The wrong assumption.** I assumed a hang was a desync signal. It is not. A
timing change, an unusual status, or a connection reset is equally consistent
with ordinary proxy behaviour — the hang was the connection idling because
*both* hops agreed on a longer body than I actually sent. That is the opposite
of a desync: it is agreement. I had inverted the meaning of the observation.
The status code and the timing told me nothing either way, which is precisely
why a timing change can never be evidence
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

The second wrong assumption was structural: I treated the anomaly as proof of
the class rather than as a prompt to read the back-end log. The log already
contained the answer — exactly one request per connection — and I never looked,
because I was reading the client-visible symptom instead.

**The next test.** Read the back-end access log for the affected connection.
If it contains exactly one request for that connection, the connection was not
desynchronised and no smuggling occurred *regardless of the response the
attacker received*
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
That single log read converts an unresolvable ambiguity into a clean negative.

---

## A second, subtler variant of the same failure

**Expected.** I sent a conflicting-framing request and got a 400. I read the
400 as "the front end refused, so no smuggling" and moved on.

**Actual.** The 400 was correct behaviour at the front end, but I had skipped
the step that distinguishes *refused and never forwarded* from *refused after
forwarding* — and the second case would have been a finding.

**The wrong assumption.** That a 400 is a verdict. A front end returning 400 for
a request carrying both `Transfer-Encoding` and `Content-Length` is behaving
exactly as HTTP/1.1 message parsing requires; it is a **negative control**, and
the useful next question is which layer decided, not what the status code was
[smuggling.evidence.a_front_end_returning_400_for_a_request_carr]. A 400 is only
a clean negative when the request genuinely never reached the back end,
verifiable by the fact that no second request appears in back-end logs
[smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].

**The next test.** Pair every 400 with a back-end log read for the same
connection. Status code decides nothing on its own.

---

## A third failure: the duplicate Content-Length that was not invalid

**Expected.** I probed a duplicated `Content-Length` and got a 400, which I
recorded as "framing validation confirmed, CL.CL closed".

**Actual.** The 400 was real but my probe was malformed as an *attack*: I used a
comma-separated list whose elements were all valid and all identical. Such a
list is processed as that single value — so my probe was not invalid framing at
all, and the 400 meant something unrelated to the variant I was testing.

**The wrong assumption.** That any duplicated `Content-Length` is invalid
framing. An invalid or duplicated `Content-Length` with no `Transfer-Encoding`
is an unrecoverable framing error that must yield 400
[smuggling.test.an_invalid_content_length_on_a_bare_request_is_a_framing_control_not_a_smuggling_primitive]
— but the spec's exception for a consistent list means my probe never reached
that rule.

**The next test.** Re-probe with a genuinely conflicting list. A negative from a
consistent-list probe tells you nothing about CL.CL.

---

## The structural lesson

Three failures, one shape: **I substituted a client-visible symptom for the one
observation that carries meaning.** The hang, the 400, and the malformed probe
were all *read* as verdicts. The back-end log was the only oracle, and every
one of these outcomes is settled by a single log read
[smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

Three discipline rules that follow, each with the check that catches it:

1. **No finding without a log line for a request you did not send.** Check: does
   the back-end access log contain exactly one request for that connection? If
   yes, close it as a negative and record the raw pairs.
2. **No 400 interpreted without establishing which layer decided it.** Check:
   is the error page edge-generated or the application's own? Is there any
   back-end log entry for the request?
3. **Every probe validated as an *attack* before its result is read.** Check:
   does this probe actually exercise the rule I think it does? A probe that
   never reaches the rule yields a 400 that means nothing.

## The gap this analysis leaves open

Even a fully correct negative on CL.TE and TE.CL does not close the hunt. A
chain that shows no header ambiguity still has sub-forms relying on connection
reuse, connection state, or the client
[smuggling.variant.ht_legitimate_reuse_required_cases_st]; the response
direction needs its own audit because modern stacks dechunk on one hop while
another trusts `Content-Length`
[smuggling.technique.ht_when_auditing_modern_stacks_also]; and a downgrade hop
is a separate surface, since H2's explicit frame lengths push the defect to the
translating hop
[smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr]. My "next test"
above fixes the framing result, not the hunt. That is the standing gap, and it
is the next test after the next test.
