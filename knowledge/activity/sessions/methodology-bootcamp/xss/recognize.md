# recognize — the observations that justify opening this class

Not "the app has user input". These are the things I actually *see* that make XSS
the right class to test next.

## Signal 1 — a unique alphanumeric marker comes back verbatim

Short, random, alphanumeric, sent **one per request** to each surface. Marker found
byte-for-byte in the response is the working precondition signal for reflected XSS
[xss.signal.unique_alnum_marker_reflected_in_response]. The sweep itself enumerates
query parameters, body fields, path segments and browser-set headers — and the file
path is a distinct sink surface from the query string
[xss.test.entrypoints.unique_alnum_marker_sweep]. Seeing the marker means *continue*,
not *found*: reflection is only the first third of the claim.

## Signal 2 — the reflection sits somewhere a browser actually parses

This is the observation that kills most of the reflection flood. A marker in the
body of a **302** is never rendered — the browser follows the redirect without
parsing that body [xss.signal.ht_this_is_not_trivial_as_modern_brow]. A marker in a
`text/html` response, in an inline `<script>`, inside a quoted attribute, or in a
`href` is in a live parser. Capture the full response header block before believing
anything: `Content-Type` and CSP decide whether there is a parser at all.

## Signal 3 — client-side code reads a URL or message source

`location.search`, `location.hash`, `document.referrer`, `postMessage` data,
`document.cookie`. The observation is not "the app uses the URL" — it is a *read of
an attacker-controllable source* [xss.signal.dom.executable_source_to_sink_path].
The URL is the most common DOM source and the fragment survives server-side
filtering untouched, so a page can be vulnerable while every server-side test passes
clean [xss.technique.dom.url_fragment_and_query_as_source].

## Signal 4 — a message listener that never reads `event.origin`

`addEventListener('message', …)` where the handler acts on `e.data` without an
allow-list check is a live cross-origin XSS vector
[xss.prerequisite.hth_however_if_the_receiving_applicat]. The reach is wider than it
looks: any window in the iframe hierarchy can post top-down, so an attacker who can
get a frame onto the page reaches the handler
[xss.evidence.postmessage.origin_check_must_be_allowlist_on_receiver]. The mirror
image — trusting a message because the sender frame looks same-origin — is the same
bug.

## Signal 5 — a bundle grep hits a real sink token

`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write/writeln`, `eval`,
`new Function`, string-argument `setTimeout`, the jQuery `html/append` family — a
concrete line offset is what turns "this SPA uses innerHTML somewhere" into a
testable candidate [xss.test.dom.enumerate_dangerous_sinks_in_bundle]. The
extension analogue is the concatenate-into-HTML-then-append pattern, which stays open
even where the extension CSP blocks inline script
[xss.signal.ht_the_problematic_javascript_part_o].

## Signal 6 — a free-text field that is stored and re-rendered to other users

Profile name, comment, ticket text, bio. The observation that matters is that a
*second* surface renders it [xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view].

## Signal 7 — the policy header says something

A nonce/hash/`strict-dynamic` `script-src`, an `unsafe-inline`, or
`require-trusted-types-for` tells me which payload family can possibly execute
[xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload]. Nonce versus
`unsafe-eval` is decisive for inline handler payloads
[xss.prerequisite.ht_script_src_self_unsafe_eval].

## Context before class: where the injection lands changes the class

The same injection in an extension is triaged by its *execution context*, not by
whether it "works": a Manifest V3 service worker has no DOM to modify and is a
code-injection review, while a sandboxed page is the documented exception to the MV3
CSP rule [xss.technique.ht_classify_the_final_execution_conte].