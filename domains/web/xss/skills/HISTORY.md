# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 70 (supported 70), FP rules 25, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 70 (supported 70), FP rules 25, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -304,4 +304,4 @@
   - Rule: Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
 
 ---
-Full class document: `domains/web/xss/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
+Full class document: `domains/web/xss/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
```

## 2026-10-02 19:37 — 111 diff lines
- items: 78 (supported 70), FP rules 24, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 70 items, 70 supported, 25 FP rules, 1 chains
+> evidence: 78 items, 70 supported, 24 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -38,16 +38,16 @@
 
 ## Techniques (what to change)
 
-- XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.
+- XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "XSS can cause a variety of problems for the end user that range in severity from an annoya".
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
-- Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.
+- Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent XSS, especially if you are required to support fr".
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
-- Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.
+- Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Even if you make a mistake in your validation (such as forgetting one out of 100 input fie".
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
-- Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.
+- Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds. _(unverified)_
   - **Disproof:** This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
 - An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.
@@ -95,6 +95,9 @@
 
 ## Tests
 
+- To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink. Observation B (reportability): the same payload is delivered to a page another user will load, or you demonstrate the same-origin action it enables. A write-up resting on observation A
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.validation.self_fired_marker_is_not_a_reportable_finding) states the full boundary.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - When a filter blocks your quote or tag characters, probe the decoder gap in a fixed order - HTML-entity-encode the blocked character first, then prepend a backslash to neutralise the app's own escaping - and a hit proves the filter normalises but does not neutralise.
   - **Disproof:** The procedure is wrong if the entity probe is fired at the wrong layer: &#39; only helps where the browser HTML-decodes before parsing, so sending it into a JS string inside a <script> block, into a URL, or into a CSS value does nothing, and a hunter who treats a non-firing entity probe as proof of safety has only tested one decoder. It is also wrong to stop at the first working bypass - the same filter may have a second gap, and reporting only the first understates the defect.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html>
@@ -104,7 +107,7 @@
 - Reading the characters immediately before and after each reflection point tells you which of the six XSS contexts you are in, and the context selects the payload family, so no payload should be tried before the context is named.
   - **Disproof:** The procedure is wrong if a single reflection is genuinely multi-context - the same marker echoed into a hidden input AND an inline script AND a data attribute - because naming one context hides the others; you must enumerate every offset, not the first one found. It is also wrong where the payload family is chosen but the surrounding markup makes it inert: a marker inside a <title>, inside an HTML comment, inside a <textarea>, or inside an already-escaped attribute with no decode step later. Those require a different escape, not a context-specific payload.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://portswigger.net/web-security/cross-site-scripting/reflected> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
-- Before writing an impact claim, read the live response headers for the CSP nonce/hash/strict-dynamic directives, the HttpOnly flag on the session cookie, and any require-trusted-types-for directive, because each one caps what your confirmed execution can actually do.
+- Before writing an impact claim, read the live response headers for the CSP nonce/hash/strict-dynamic directives, the HttpOnly flag on the session cookie, and any require-trusted-types-for directive, because each one caps what your confirmed execution can actually do. _(unverified)_
   - **Disproof:** The procedure is wrong if you treat a nonce you observed on one page load as a permanent value and paste it into a payload - a nonce is regenerated per response, so a captured nonce will not match and the test fails for the wrong reason. It is also wrong to conclude a control blocks impact from the header alone: nonce/hash/strict-dynamic govern script execution, not already-confirmed event-handler execution through a parsed HTML node in every policy, and HttpOnly says nothing about tokens held in localStorage.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
 - Grepping a downloaded JS bundle for the concrete sink token set - innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln, eval, new Function, setTimeout/setInterval with a string first argument, and the jQuery html/append family - is what converts 'this page uses innerHTML somewhere' into a list of lines you can actually test.
@@ -122,6 +125,32 @@
 - A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.
   - **Disproof:** The procedure is wrong if a payload executes with no visible trace you chose to look for - e.g. the proof writes to a network beacon instead of the DOM, so 'no alert' reads as failure when execution actually happened. It is also wrong to require a visible popup as the sole gate: CSP report-only mode, Trusted Types default policies, and headless profiles can all suppress alert() while script still runs. Confirm with a second, independent observable (network egress, DOM mutation, console log) before calling it a failure.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+- To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter. The browser HTML-decodes tag attribute values after parsing the tags but before the JavaScript is interpreted, so &#39; b
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.bypass.filter.html_entity_decoding_of_attribute_values) states the full boundary.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- To decide this case, observe: acker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done. The usual next step is to assume the value is dangerous because it is attacker-supplied, without ever classifying the sink it lands in.
+The
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sink_reachability.source_never_reaches_execution_sink) states the full boundary.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks. Reporting 'I injected a script tag and it did not fire' as a working XSS overstates it.
+The mechanism: a nonce-based CSP names a spe
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload) states the full boundary.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
+- To decide this case, observe: oks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload. Report writers then label the endpoint XSS because the words 'attacker-controlled' and 'unencoded' are both present.
+The mechanism that kills it: whether injected markup executes is decid
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.json_api.content_type_json_is_not_html_execution) states the full boundary.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- To decide this case, observe: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself. Reflection is only the first third of the claim; the second third is whether the reflected bytes can terminate the context they sit in.
+The
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context) states the full boundary.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- To decide this case, observe: e sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload. Two specific failure modes produce false bypass claims: (a) the payload was neutralised becau
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sanitizer.output_observed_inert_in_page) states the full boundary.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Document/write>
+- To decide this case, observe: T a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen. The missing half is the victim.
+The mechanism: stored (second-order) XSS arises when an application receives data from an untrusted sour
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view) states the full boundary.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
 - Stored XSS is proven only by storing a payload as one identity and loading the exit point as a second identity, because your own session re-rendering your own input proves storage and reflection, never cross-user execution.
   - **Disproof:** The procedure is wrong if you only ever test with one account and the app renders stored values differently per role - the marker may be HTML-encoded for the author and injected raw into an admin moderation queue, so your own view can look safe while the privileged view is exploitable. It is also wrong where stored data is overwritten before any second read (recent-searches lists, ephemeral carts); a marker found once is not proof of durable storage - re-read the exit point after an unrelated action to confirm it survives.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
@@ -137,7 +166,7 @@
 - An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.
   - **Disproof:** This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
-- An HttpOnly session cookie removes the cookie-exfiltration chain, so impact must be restated as in-origin actions rather than session theft.
+- An HttpOnly session cookie removes the cookie-exfiltration chain, so impact must be restated as in-origin actions rather than session theft. _(unverified)_
   - **Disproof:** The session cookie lacks HttpOnly and document.cookie returns it inside the injected script, so full session replay is achievable.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
 - A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.
@@ -146,7 +175,7 @@
 
 ## False-positive rules (when to reject it)
 
-- Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.
+- Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead. _(unverified)_
   - **Disproof:** The rule is wrong if the session cookie lacks HttpOnly and document.cookie returns it to injected script, in which case full session replay IS achievable and the original impact claim stands. It is also wrong when the sensitive credential is not the cookie at all - a JWT or API token in localStorage or sessionStorage, or a CSRF token readable from the DOM, is unaffected by HttpOnly. Read the Session Management cheat sheet's own warning before assuming HttpOnly helps: it only protects the confidentiality of that one cookie.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
 - Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.
@@ -191,7 +220,7 @@
 - When a site reflects attacker input into its own Content-Security-Policy - typically the trailing report-uri directive - a semicolon lets the attacker append directives, and the script-src-elem directive lets an appended script-src overwrite the existing nonce or hash based script-src entirely.
   - **Disproof:** The claim is wrong if the site does not reflect any input into the policy, since there is then nothing to inject and the nonce stands. It is also wrong if the reflected value is filtered so a semicolon or a comma cannot appear, because then no new directive can be opened. It is wrong for browsers that do not implement script-src-elem, where an appended script-src would simply be dropped as a duplicate and the original policy would still apply. And it is wrong for servers that deliver the policy as a meta tag rather than a header in a context where the attacker controls only part of the value, since the injected text is then inert element content rather than a directive.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
-- Client-side template injection in an AngularJS page executes when the framework's expression evaluator parses the attacker's text, so an injected expression that overwrites String.prototype.charAt defeats the sandbox's own identifier check and hands $eval straight to the attacker.
+- Client-side template injection in an AngularJS page executes when the framework's expression evaluator parses the attacker's text, so an injected expression that overwrites String.prototype.charAt defeats the sandbox's own identifier check and hands $eval straight to the attacker. _(unverified)_
   - **Disproof:** The claim is wrong on AngularJS 1.6 and later, where the sandbox was removed entirely because it was never a real security boundary, so the charAt overwrite is unnecessary but the payload still works - which does not make the claim false, it makes it outdated as a description of necessity. It is genuinely wrong if the application never passes untrusted data into an AngularJS template expression or filter, because then no evaluation happens at all and the payload is inert text. It is also wrong if a CSP is enforced in a mode that blocks inline script and the expression cannot reach a DOM event AngularJS itself defines, since the CSP path then refuses the execution.
   - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
 - Injecting an unterminated img src attribute captures the rest of the victim's response into an outbound request URL without executing any script, because the HTML tokenizer stays in the double-quoted attribute value state until it finds the next quotation mark anywhere in the document.
```

## 2026-10-03 01:46 — 243 diff lines
- items: 108 (supported 96), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 78 items, 70 supported, 24 FP rules, 1 chains
+> evidence: 108 items, 96 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -26,12 +26,33 @@
 - Stored XSS requires the payload to persist in a server-side store and later render in another user's response, so proof needs two distinct steps.
   - **Disproof:** The payload executes only in the submitting user's own session and never renders for any other user or role.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/stored>
+- Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.
+  - **Disproof:** Registering and controlling a worker script on the origin with neither arbitrary-JS hosting nor a JSONP endpoint that can be made to emit arbitrary JS refutes these as the required prerequisites.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
+- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler. _(unverified)_
+  - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
+- An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.
+  - **Disproof:** An inline event handler payload firing on a page whose script-src carries only 'unsafe-eval', with no 'unsafe-inline', no matching hash or nonce, and no other executable gadget, refutes this gating.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
+- The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.
+  - **Disproof:** A fetch-listener worker registered and intercepting traffic from a script hosted off the vulnerable origin, or a JSONP response whose callback cannot be broken out of, refutes the origin-delivery requirement.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
+- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.
+  - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
 
 ## Recon signals (where to look)
 
 - DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.
   - **Disproof:** The source is read but the value always flows into a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.
+  - **Disproof:** A concatenating handler whose value is escaped or inserted as text before the append, so the same input renders as literal characters with no new element or handler, refutes this sink pattern.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
+- Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.
+  - **Disproof:** Script executing from a payload delivered only in the body of a 302 response, in a browser that follows the redirect before parsing, refutes this claim.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md>
 - A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal for reflected XSS.
   - **Disproof:** The marker is absent from the response, appears only encoded in a form that cannot be decoded back into a live context, or is reflected only after a separate later request.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
@@ -47,6 +68,9 @@
 - Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Even if you make a mistake in your validation (such as forgetting one out of 100 input fie".
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
+- A reflected or stored cross-site scripting entry point is confirmed when a chosen script payload executes in the page context rather than being escaped into inert text.
+  - **Disproof:** Refuted when the payload is returned HTML-encoded with no executable sink, which shows the output is contextually escaped rather than vulnerable.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/27.%20Cross-Site%20Scripting%20%28XSS%29/Cross-Site%20Scripting%20%28XSS%29.md>
 - Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds. _(unverified)_
   - **Disproof:** This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
@@ -68,6 +92,18 @@
 - Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.
   - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
+- The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.
+  - **Disproof:** A payload that reaches a DOM sink and executes as page JavaScript from a Manifest V3 service worker, or a sandboxed page that inherits the host extension's CSP and APIs, refutes this context-based split.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
+- When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.
+  - **Disproof:** A reflected value containing a closing script tag sequence that neither terminates the block nor produces any new element or handler in the rendered page refutes the escapability.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md>
+- The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin. _(unverified)_
+  - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
+- The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.
+  - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
@@ -95,7 +131,7 @@
 
 ## Tests
 
-- To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink. Observation B (reportability): the same payload is delivered to a page another user will load, or you demonstrate the same-origin action it enables. A write-up resting on observation A
+- To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.validation.self_fired_marker_is_not_a_reportable_finding) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - When a filter blocks your quote or tag characters, probe the decoder gap in a fixed order - HTML-entity-encode the blocked character first, then prepend a backslash to neutralise the app's own escaping - and a hit proves the filter normalises but does not neutralise.
@@ -125,30 +161,25 @@
 - A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.
   - **Disproof:** The procedure is wrong if a payload executes with no visible trace you chose to look for - e.g. the proof writes to a network beacon instead of the DOM, so 'no alert' reads as failure when execution actually happened. It is also wrong to require a visible popup as the sole gate: CSP report-only mode, Trusted Types default policies, and headless profiles can all suppress alert() while script still runs. Confirm with a second, independent observable (network egress, DOM mutation, console log) before calling it a failure.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
-- To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter. The browser HTML-decodes tag attribute values after parsing the tags but before the JavaScript is interpreted, so &#39; b
+- To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.bypass.filter.html_entity_decoding_of_attribute_values) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
-- To decide this case, observe: acker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done. The usual next step is to assume the value is dangerous because it is attacker-supplied, without ever classifying the sink it lands in.
-The
+- To decide this case, observe: Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sink_reachability.source_never_reaches_execution_sink) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
-- To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks. Reporting 'I injected a script tag and it did not fire' as a working XSS overstates it.
-The mechanism: a nonce-based CSP names a spe
+- To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
-- To decide this case, observe: oks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload. Report writers then label the endpoint XSS because the words 'attacker-controlled' and 'unencoded' are both present.
-The mechanism that kills it: whether injected markup executes is decid
+- To decide this case, observe: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.json_api.content_type_json_is_not_html_execution) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
-- To decide this case, observe: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself. Reflection is only the first third of the claim; the second third is whether the reflected bytes can terminate the context they sit in.
-The
+- To decide this case, observe: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.html_encoding.entity_encoded_reflection_cannot_break_context) states the full boundary.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
-- To decide this case, observe: e sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload. Two specific failure modes produce false bypass claims: (a) the payload was neutralised becau
+- To decide this case, observe: If the sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sanitizer.output_observed_inert_in_page) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Document/write>
-- To decide this case, observe: T a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen. The missing half is the victim.
-The mechanism: stored (second-order) XSS arises when an application receives data from an untrusted sour
+- To decide this case, observe: Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view) states the full boundary.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
... (truncated)
```

## 2026-10-03 02:41 — 21 diff lines
- items: 109 (supported 97), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 108 items, 96 supported, 27 FP rules, 1 chains
+> evidence: 109 items, 97 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -26,6 +26,9 @@
 - Stored XSS requires the payload to persist in a server-side store and later render in another user's response, so proof needs two distinct steps.
   - **Disproof:** The payload executes only in the submitting user's own session and never renders for any other user or role.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/stored>
+- An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.
+  - **Disproof:** If the same input is provably neutralised by encoding or escaping before it reaches any browser-executed script context, event handler or DOM write, the cross-site scripting claim fails.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md>
 - Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.
   - **Disproof:** Registering and controlling a worker script on the origin with neither arbitrary-JS hosting nor a JSONP endpoint that can be made to emit arbitrary JS refutes these as the required prerequisites.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
```
