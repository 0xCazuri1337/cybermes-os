# validate — the request/response pair shape that proves impact

## The proof that counts

Request smuggling is proven only when **a request the attacker never sent
appears in the back-end access log**, because a timing change, an unusual
status, or a connection reset is equally consistent with ordinary proxy
behaviour [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

The minimum reportable shape:

```
A) POST /api/profile HTTP/1.1
   Host: target
   Content-Length: 6
   Transfer-Encoding: chunked

   0

   (baseline: one clean aligned request, one back-end log line, captured BEFORE)
   -> HTTP/1.1 200 (or whatever the honest baseline was)

B) Same request, with the length metadata made self-contradictory and a unique
   marker placed in the residue the back end would read as the next request:

   POST /api/profile HTTP/1.1
   Host: target
   Content-Length: <covers the prefix only>
   Transfer-Encoding: chunked

   0

   GET /smuggle-check?id=<MARKER> HTTP/1.1      <- prefixed, never separately sent
   ...

   -> HTTP/1.1 200, back-end access log for THAT CONNECTION shows TWO lines:
      the POST, and a GET to /smuggle-check carrying <MARKER>
```

`<MARKER>` is a unique, attacker-chosen token that appears nowhere else. The
attributability rule is that the log line must exist **because of the framing
conflict**, not because the attacker sent it.

## The maximum-safe-proof rule (hard constraint)

**A desync proof must never touch another user's traffic.**

A successful smuggle pre-executes as the *next* message on a shared connection
[smuggling.technique.http_request_smuggling_arises_where_a_front_end_and_back_e].
The residue you inject is therefore not merely a test — it is a request that will
be executed as whatever legitimate client the proxy hands that connection next.
On a busy front end that client is a stranger. Poisoning another user's request
is **collateral damage to a third party**, and that is forbidden regardless of
authorization scope: the user authorized *you* to test, not the next anonymous
requester to absorb your payload.

### The safe proof, in preference order

1. **Self-inflicted desync on your own connection.** Open a dedicated
   connection, send the ambiguous request on it, and keep it. Read the
   back-end log for that connection. The only party to the desync is you; no
   unowned traffic is ever queued behind your residue because you never hand the
   connection on. This proves the mechanism.
2. **Detection via response-queue desync observed on your own connection.**
   Send the ambiguous request followed by a second request you *do* send, on
   the same connection, and observe that the two responses arrive swapped,
   truncated, or matched to the wrong request. The misalignment is visible
   entirely within traffic you generated.
3. **Passive confirmation.** Where log access exists, no live desync is needed:
   a second request line appearing in the origin's log for a connection where
   the client sent one is the proof
   [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

### Proofs that are forbidden

- Prepending a malformed request to a shared or pooled connection and hoping
  the next legitimate requester receives the residue.
- Any residue crafted to execute a *harmful* action — writing data, deleting,
  creating an account — even where the target is in scope. Harm to an
  unaccounted-for third party is out of scope by definition.
- Any "poison the queue and observe the victim" technique, including
  cache-poisoning or redirect variants delivered to another user's connection.

The ceiling of what this class can honestly be proven to, under that rule, is
**desynchronisation of the researcher's own connection**, plus whatever
passive evidence the logs already hold. Response desynchronisation *to a
different client* is the theoretical payoff
[smuggling.impact.ht_response_desynchronisation_up_to] — state it as the
mechanism's consequence, and demonstrate it only in the self-inflicted form.

## What does NOT count as proof

- **A 400.** It is the spec-mandated outcome for a request carrying both
  `Transfer-Encoding` and `Content-Length`
  [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].
  It is only a clean negative when the request genuinely never reached the back
  end — verifiable by the absence of any second request in back-end logs.
- **A 500, an unusual status, a timing change, or a connection reset.** All are
  equally consistent with ordinary proxy behaviour
  [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
- **A second response on the connection, when your own client pipelined both
  requests.** The second response is yours. Attributeability requires that the
  marker correspond to a request you never sent.
- **A duplicate log line caused by a client retry.** A retrying client resends
  the original; that is not attributable to the framing conflict and the claim
  collapses [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
- **One back-end log line for the connection.** The connection was not
  desynchronised regardless of what response you received.
- **An edge that dropped a header the origin never saw.** A rejected header
  never reaches the tier whose behaviour you were comparing, so the layers never
  disagreed [smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync].
- **Client-side payload reconstruction.** An HTML polyglot rebuilt in the
  browser involves no two HTTP parsers at all
  [smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync].
- **A single proxy in front of the app.** No disagreeing pair exists, so there is
  no smuggling to prove — the request is simply rejected or handled
  consistently.
- **An HTTP/1.1 payload sent on an HTTP/2 connection.** H2's explicit frame
  lengths leave no framing ambiguity to exploit in the H2 layer itself
  [smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr].

## Escalating the ceiling honestly

Once self-inflicted desync is proven, the honest statement of impact is
bounded by that proof: the attacker can cause the shared connection to carry a
request they never sent, which means request-side effects invisible to the
edge's inspection, and — where the response direction is also affected —
response control, since a response computed for the smuggled request can be
delivered to a different client [smuggling.impact.ht_response_desynchronisation_up_to].
State that second half as the mechanism's consequence, demonstrated only in the
self-inflicted form, rather than claiming a cross-client theft you did not and
should not perform.
