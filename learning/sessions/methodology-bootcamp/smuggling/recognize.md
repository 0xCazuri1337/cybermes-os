# recognize — the observations that justify investigating this class

Not the class description. What you actually SEE on the wire, in the logs, or
in the topology, that makes this class worth spending requests on.

## Topology observations (free, no probing)

1. **More than one HTTP/1.1 parser between you and the origin.** A reverse
   proxy, CDN, WAF, load balancer or API gateway in front of an application
   server is the precondition and nothing more
   [smuggling.technique.ht_http_request_smuggling_attacks_are]. One parser
   alone cannot disagree with itself; the interesting case is a *pair* whose
   implementations differ.
2. **A downgrade boundary.** HTTP/2 at the edge, HTTP/1.1 at the origin, or
   any translating hop in between, because H2's explicit frame lengths remove
   the ambiguity from the H2 layer itself and push the defect onto the hop that
   rewrites body-length metadata
   [smuggling.prerequisite.ht_request_smuggling_in_http_2_downgr],
   [smuggling.technique.ht_strip_and_regenerate_body_length_m].
3. **The edge normalises or strips framing headers.** If the proxy rewrites
   `Transfer-Encoding` or `Content-Length` rather than passing them through, the
   translation layer is where the two parsers can diverge — and the response
   direction has to be audited too, since modern stacks desynchronise on
   responses as well as requests
   [smuggling.technique.ht_when_auditing_modern_stacks_also].

## On-the-wire observations

4. **A 400 whose body does not match the application.** An edge-generated error
   page, not your application's error handler, is the signal that the *framing*
   was rejected before routing. The useful next question is which layer decided,
   not what the status code was
   [smuggling.evidence.a_front_end_returning_400_for_a_request_carr].
5. **A response that arrives for a request you did not send, or a response
   whose body does not match anything you asked for on that connection.** That
   is the response-queue desync signature — the payoff being response control,
   where a response computed for your smuggled request is delivered to a
   different client [smuggling.impact.ht_response_desynchronisation_up_to].
6. **A hang, a reset, or a truncated body on a connection you reused.** Weak on
   its own — these are equally consistent with ordinary proxy behaviour, which
   is exactly why a status code or a timing change never proves this class
   [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].
   Treat it as a prompt to go and read the origin log, not as a finding.
7. **Two back-end log lines for one front-end connection where you sent one
   request.** This is the observation that actually justifies the class, and
   the only one that carries proof
   [smuggling.validation.confirm_desync_with_a_visible_second_request_not_with_a_status_code].

## Log and neighbouring-traffic observations

8. **A request in the origin's access log with a path or method you never
   sent**, especially one that rides immediately behind an ordinary-looking
   request from the same front-end address
   [smuggling.technique.http_request_smuggling_arises_where_a_front_end_and_back_e].
9. **Repetition of an otherwise mundane static-path request from changing
   infrastructure, and requests to appliance administrative asset paths.**
   Both act as early reconnaissance fingerprints for exploitation
   [smuggling.signal.admin-path-probe-as-recon-signal]. These are recon
   signals: they tell you someone is working this class here, which raises the
   value of testing, and they are not themselves evidence of a desync.

## Signals that look like this class and are not

- A front end that drops or ignores a malformed header while the origin is
  merely *absent* from the comparison. A header rejected at the edge never
  reaches the tier whose behaviour you were comparing, so the two layers never
  disagreed [smuggling.fp_rule.a_header_rejected_by_the_front_end_is_absent_from_the_back_end_and_proves_nothing_about_desync].
- A 400 on a request carrying both `Transfer-Encoding` and `Content-Length`.
  That is the spec-mandated outcome, not a failed attack
  [smuggling.fp_rule.a_400_on_a_conflicting_te_cl_request_is_the_spec_mandated_outcome_not_a_failed_attack].
- A ~1KB HTML attachment that downloads an image polyglot and rebuilds an
  obfuscated payload in the browser. That is HTML smuggling — one client-side
  reconstruction, not two HTTP parsers disagreeing
  [smuggling.fp_rule.html_smuggling_polyglot_is_not_request_desync].
