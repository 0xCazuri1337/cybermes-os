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

## 2026-10-04 00:43 — 654 diff lines
- items: 109 (supported 97), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -20,363 +20,351 @@
 
 ## Prerequisites (do not start without these)
 
-- Reflected XSS requires attacker data from the current HTTP request to be embedded unneutralized in that same immediate response.
+- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
+- An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the same input is provably neutralised by encoding or escaping before it reaches any browser-executed script context, event handler or DOM write, the cross-site scripting claim fails.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md>
+- An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.  _(merged 1 duplicate row(s))_
+  - **Disproof:** An inline event handler payload firing on a page whose script-src carries only 'unsafe-eval', with no 'unsafe-inline', no matching hash or nonce, and no other executable gadget, refutes this gating.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
+- Reflected XSS requires attacker data from the current HTTP request to be embedded unneutralized in that same immediate response.  _(merged 1 duplicate row(s))_
   - **Disproof:** The unique probe value is absent from the immediate HTTP response for that surface, or appears only after a separate later request, making it stored rather than reflected.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
-- Stored XSS requires the payload to persist in a server-side store and later render in another user's response, so proof needs two distinct steps.
+- Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Registering and controlling a worker script on the origin with neither arbitrary-JS hosting nor a JSONP endpoint that can be made to emit arbitrary JS refutes these as the required prerequisites.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
+- Stored XSS requires the payload to persist in a server-side store and later render in another user's response, so proof needs two distinct steps.  _(merged 1 duplicate row(s))_
   - **Disproof:** The payload executes only in the submitting user's own session and never renders for any other user or role.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/stored>
-- An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.
-  - **Disproof:** If the same input is provably neutralised by encoding or escaping before it reaches any browser-executed script context, event handler or DOM write, the cross-site scripting claim fails.
-  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md>
-- Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.
-  - **Disproof:** Registering and controlling a worker script on the origin with neither arbitrary-JS hosting nor a JSONP endpoint that can be made to emit arbitrary JS refutes these as the required prerequisites.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
-- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler. _(unverified)_
-  - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
-- An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.
-  - **Disproof:** An inline event handler payload firing on a page whose script-src carries only 'unsafe-eval', with no 'unsafe-inline', no matching hash or nonce, and no other executable gadget, refutes this gating.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
-- The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.
+- The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.  _(merged 1 duplicate row(s))_
   - **Disproof:** A fetch-listener worker registered and intercepting traffic from a script hosted off the vulnerable origin, or a JSONP response whose callback cannot be broken out of, refutes the origin-delivery requirement.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
-- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.
-  - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
-  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
 
 ## Recon signals (where to look)
 
-- DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.
+- A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal for reflected XSS.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The marker is absent from the response, appears only encoded in a form that cannot be decoded back into a live context, or is reflected only after a separate later request.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+- DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.  _(merged 1 duplicate row(s))_
   - **Disproof:** The source is read but the value always flows into a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
-- The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.
+- Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Script executing from a payload delivered only in the body of a 302 response, in a browser that follows the redirect before parsing, refutes this claim.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md>
+- The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** A concatenating handler whose value is escaped or inserted as text before the append, so the same input renders as literal characters with no new element or handler, refutes this sink pattern.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md>
-- Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.
-  - **Disproof:** Script executing from a payload delivered only in the body of a 302 response, in a browser that follows the redirect before parsing, refutes this claim.
+
+## Techniques (what to change)
+
+- A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- A reflected or stored cross-site scripting entry point is confirmed when a chosen script payload executes in the page context rather than being escaped into inert text.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when the payload is returned HTML-encoded with no executable sink, which shows the output is contextually escaped rather than vulnerable.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/27.%20Cross-Site%20Scripting%20%28XSS%29/Cross-Site%20Scripting%20%28XSS%29.md>
+- An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
+- An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the sink is document.write rather than innerHTML, if the browser is one that still runs script elements assigned via innerHTML, or if a separate code path appends the node and executes it.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+- Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
+- Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+- Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Even if you make a mistake in your validation (such as forgetting one out of 100 input fie".
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
+- In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.  _(merged 2 duplicate row(s))_
+  - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
+- Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent XSS, especially if you are required to support fr".
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
+- Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 2 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
+- The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This is wrong if the application reads the location and immediately decodes or strips it before any use, or if the page never passes the value into a sink that renders or executes it.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+- The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.  _(merged 1 duplicate row(s))_
+  - **Disproof:** A payload that reaches a DOM sink and executes as page JavaScript from a Manifest V3 service worker, or a sandboxed page that inherits the host extension's CSP and APIs, refutes this context-based split.
... (truncated)
```

## 2026-10-04 00:50 — 17 diff lines
- items: 109 (supported 97), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -411,10 +411,10 @@
 
 ## Hunt procedure
 
-1. Enumerate the surface before probing: collect every endpoint, parameter and object id the class could plausibly sit on.
-2. Establish a CONTROLLED BASELINE first — one unauthenticated and one authenticated low-privilege request per candidate — and diff against the probe. A difference with no baseline proves nothing.
-3. Change exactly ONE variable per probe. Two changes produce a difference you cannot attribute.
-4. Record raw request and response pairs verbatim, including headers, before you interpret anything.
+1. Intercept with Burp (Proxy > Intercept) and re-issue the request with a unique alphanumeric marker; confirm it is echoed before choosing a payload.
+2. Settle the CONTEXT first: read the bytes either side of the reflection to pick one of the six XSS contexts, then fire only that context's payload.
+3. Prove execution in a real browser (alert() or a DNS-beacon callback such as interactsh) -- a payload visible in a response pane is unexecuted text.
+4. For DOM XSS, seed location.search / location.hash and search the live DOM; grep the JS bundle for innerHTML, document.write and eval to find the sink.
 
 ### What counts as proof
 
```

## 2026-10-04 13:16 — 199 diff lines
- items: 111 (supported 99), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 109 items, 97 supported, 27 FP rules, 1 chains
+> evidence: 111 items, 99 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -61,16 +61,16 @@
 
 - A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.  _(merged 1 duplicate row(s))_
   - **Disproof:** The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
 - A reflected or stored cross-site scripting entry point is confirmed when a chosen script payload executes in the page context rather than being escaped into inert text.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when the payload is returned HTML-encoded with no executable sink, which shows the output is contextually escaped rather than vulnerable.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting> · <https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/27.%20Cross-Site%20Scripting%20%28XSS%29/Cross-Site%20Scripting%20%28XSS%29.md>
 - An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
@@ -82,7 +82,7 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
 - Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
@@ -91,10 +91,10 @@
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.  _(merged 2 duplicate row(s))_
   - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
@@ -103,7 +103,13 @@
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- Public writeup evidence for xss: Blob-URL sandbox escape to XSS.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://jorianwoltjer.com/blog/p/stories/finding-xss-on-shazzer>
+- Public writeup evidence for xss: self-XSS to account takeover.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://zere.es/posts/self-xss-account-takeover/>
 - The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 2 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
@@ -127,7 +133,7 @@
 
 - A DOM XSS claim is only proven when the debugger shows an actual value flowing from a source read into an execution sink, because grepping source and sink names separately proves nothing about the path between them.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if the path is data-dependent and your single marker run takes a different branch than the attacker's input would (a length check, an if/else on the first character, a try/catch). A clean debugger trace on one marker does not prove the branch an attacker's payload would take is also safe. It is also wrong to stop at the first sink: a value often flows into a safe sink AND an unsafe sink, so the trace must continue to every use of the tainted variable.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if a payload executes with no visible trace you chose to look for - e.g. the proof writes to a network beacon instead of the DOM, so 'no alert' reads as failure when execution actually happened. It is also wrong to require a visible popup as the sole gate: CSP report-only mode, Trusted Types default policies, and headless profiles can all suppress alert() while script still runs. Confirm with a second, independent observable (network egress, DOM mutation, console log) before calling it a failure.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
@@ -136,16 +142,16 @@
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
 - Before writing an impact claim, read the live response headers for the CSP nonce/hash/strict-dynamic directives, the HttpOnly flag on the session cookie, and any require-trusted-types-for directive, because each one caps what your confirmed execution can actually do.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The procedure is wrong if you treat a nonce you observed on one page load as a permanent value and paste it into a payload - a nonce is regenerated per response, so a captured nonce will not match and the test fails for the wrong reason. It is also wrong to conclude a control blocks impact from the header alone: nonce/hash/strict-dynamic govern script execution, not already-confirmed event-handler execution through a parsed HTML node in every policy, and HttpOnly says nothing about tokens held in localStorage.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
 - For DOM XSS you must seed the marker into a client-side source such as location.search and locate it in the live DOM with devtools Control+F, because the browser's View Source never shows JavaScript-injected nodes.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if the app renders the marker only after an interaction or a timer - a click, a scroll, a setTimeout, a route change - because a single load-time Control+F finds nothing and the source IS reachable. It is also wrong where the value is passed to an execution sink such as eval or setTimeout-with-string, where the marker legitimately never appears in the DOM, so 'absent from the DOM' is not evidence of safety and must not be recorded as a clean result.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html>
 - Grepping a downloaded JS bundle for the concrete sink token set - innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln, eval, new Function, setTimeout/setInterval with a string first argument, and the jQuery html/append family - is what converts 'this page uses innerHTML somewhere' into a list of lines you can actually test.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if the sink token appears in dead code, a comment, a minifier artifact, or an error-handling branch that never runs - a raw grep hit is a candidate list, not a vulnerability, and a hit list with no reachability analysis will generate false positives. It is also wrong as a completeness claim: many apps reach sinks through a framework abstraction (a template engine's {{{ }}} escape, a v-html directive, React's dangerouslySetInnerHTML) where the literal token never appears in any bundle.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - Reading the characters immediately before and after each reflection point tells you which of the six XSS contexts you are in, and the context selects the payload family, so no payload should be tried before the context is named.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if a single reflection is genuinely multi-context - the same marker echoed into a hidden input AND an inline script AND a data attribute - because naming one context hides the others; you must enumerate every offset, not the first one found. It is also wrong where the payload family is chosen but the surrounding markup makes it inert: a marker inside a <title>, inside an HTML comment, inside a <textarea>, or inside an already-escaped attribute with no decode step later. Those require a different escape, not a context-specific payload.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://portswigger.net/web-security/cross-site-scripting/reflected> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
 - Stored XSS is proven only by storing a payload as one identity and loading the exit point as a second identity, because your own session re-rendering your own input proves storage and reflection, never cross-user execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if you only ever test with one account and the app renders stored values differently per role - the marker may be HTML-encoded for the author and injected raw into an admin moderation queue, so your own view can look safe while the privileged view is exploitable. It is also wrong where stored data is overwritten before any second read (recent-searches lists, ephemeral carts); a marker found once is not proof of durable storage - re-read the exit point after an unrelated action to confirm it survives.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
@@ -154,13 +160,13 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Document/write>
 - To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.validation.self_fired_marker_is_not_a_reportable_finding) states the full boundary.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
 - To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.bypass.filter.html_entity_decoding_of_attribute_values) states the full boundary.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - To decide this case, observe: Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sink_reachability.source_never_reaches_execution_sink) states the full boundary.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
@@ -169,7 +175,7 @@
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
 - To decide this case, observe: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.json_api.content_type_json_is_not_html_execution) states the full boundary.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
... (truncated)
```

## 2026-10-04 19:46 — 9 diff lines
- items: 111 (supported 99), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -431,6 +431,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/xss/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-04 21:29 — 44 diff lines
- items: 111 (supported 102), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 111 items, 99 supported, 27 FP rules, 1 chains
+> evidence: 111 items, 102 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -86,8 +86,8 @@
 - DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
-- Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Even if you make a mistake in your validation (such as forgetting one out of 100 input fie".
+- Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Even if you make a mistake in your validation (such as forgetting one out of 100”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.  _(merged 2 duplicate row(s))_
   - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
@@ -98,8 +98,8 @@
 - Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
-- Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent XSS, especially if you are required to support fr".
+- Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent XSS, especially if you are required to ”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
@@ -122,8 +122,8 @@
 - When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.  _(merged 1 duplicate row(s))_
   - **Disproof:** A reflected value containing a closing script tag sequence that neither terminates the block nor produces any new element or handler in the rendered page refutes the escapability.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md>
-- XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "XSS can cause a variety of problems for the end user that range in severity from an annoya".
+- XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“XSS can cause a variety of problems for the end user that range in severity from”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
 - document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the value reaching the sink is sanitised by a vetted library configured for that sink, or is only ever assigned as a property value that the browser does not parse as markup.
```

## 2026-10-07 00:50 — 2 DoD-session rules (pre-gate, no skillgen run)
- items: unchanged; 2 FP-kill rules filed in `research/pending/fp/fp-dod-session-2026-10-03.json` (source: `/mnt/e/bugbounty/DOD/sessions/2026-10-03-kh/findings/XSS-VERDICTS.md`, `TRUST-BOUNDARY-REHUNT.md`)

```diff
--- xss@current
+++ xss@pending
+- xss.fprule.browser_encodes_location_hash: the browser percent-encodes <, > and spaces when storing the fragment, so location.hash never hands raw angle brackets to JS — a static location.hash→innerHTML chain must be settled in a real browser, not by reasoning. Mirror rule: attribute-reflected values arrive as %3c (encoded) → not XSS.
+- xss.fprule.spa_bundle_runtime_capture: capture SPA bundles with Network.enable before navigation, bodies inside the event pump, and sessionId on Network.getResponseBody — otherwise you get a healthy script count with 0 bodies and a false negative.
```

## 2026-10-28 14:45 — 44 diff lines
- items: 106 (supported 100), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 111 items, 102 supported, 27 FP rules, 1 chains
+> evidence: 106 items, 100 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -20,7 +20,7 @@
 
 ## Prerequisites (do not start without these)
 
-- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.  _(merged 2 duplicate row(s))_ _(unverified)_
+- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.  _(merged 1 duplicate row(s))_
   - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
 - An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.  _(merged 1 duplicate row(s))_
@@ -104,13 +104,7 @@
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
-- Public writeup evidence for xss: Blob-URL sandbox escape to XSS.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://jorianwoltjer.com/blog/p/stories/finding-xss-on-shazzer>
-- Public writeup evidence for xss: self-XSS to account takeover.  _(merged 1 duplicate row(s))_
-  - **Disproof:** Refuted if the fetched page no longer contains this exact span, or if the described behaviour is corrected or withdrawn by the publisher.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://zere.es/posts/self-xss-account-takeover/>
-- The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 2 duplicate row(s))_ _(unverified)_
+- The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
 - The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.  _(merged 1 duplicate row(s))_
@@ -317,7 +311,7 @@
 - An XSS-installed service worker outlives the 24-hour window that makes the browser bypass its cache on update checks, so a remediation claim of 'fixed within a day' is not supported until a changed script has actually been fetched, installed and activated.  _(merged 1 duplicate row(s))_
   - **Disproof:** A malicious worker that stops intercepting requests within 24 hours of the site serving a changed script refutes the persistence claim.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md>
-- HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.  _(merged 2 duplicate row(s))_ _(unverified)_
+- HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the injected markup is escaped or sanitized so neither a link element nor a redirect renders, the escalation path never materialises and the finding stays at HTML injection severity.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://kathan19.gitbook.io/howtohunt/html-injection/html_injection_on_password_reset_page.md>
 - Serving the vulnerable page over HTTPS changes nothing about the attack, because same-origin script execution is scoped by origin, and https is part of the origin definition rather than a barrier to it.  _(merged 1 duplicate row(s))_
```

## 2026-10-28 17:55 — 22 diff lines
- items: 105 (supported 99), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 106 items, 100 supported, 27 FP rules, 1 chains
+> evidence: 105 items, 99 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -89,8 +89,8 @@
 - Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Even if you make a mistake in your validation (such as forgetting one out of 100”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
-- In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.  _(merged 2 duplicate row(s))_
-  - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
+- In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
```

## 2026-10-28 21:00 — 56 diff lines
- items: 111 (supported 99), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 105 items, 99 supported, 27 FP rules, 1 chains
+> evidence: 111 items, 99 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -83,6 +83,9 @@
 - Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- DOM XSS reads attacker-controlled data in JavaScript (location.hash, location.search, location.href, document.referrer, document.write, innerHTML, eval, setTimeout or a string argument) and executes it against the serving origin.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted if the sink is percent-encoded before reaching the DOM, the source is not attacker-controlled, or a real-browser probe does not execute the payload.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
 - DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
@@ -104,6 +107,12 @@
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- Self-XSS that harms only the attacker's own session becomes effective stored XSS and account takeover when combined with a CSRF-vulnerable field mutation endpoint.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted if the mutation endpoint enforces a CSRF token, SameSite=Lax/Strict cookies are required, or the field is not stored and rendered.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/csrf>
+- Stored XSS in collaborative content (wiki, issue tracker, customer ticket, comment, label color, tag) is delivered to every viewer, and when a privileged user views it the payload runs in the privileged session.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted if the field sanitizes style/svg/math and the diagram renderer is sandboxed, or if privileged users are exempt from the render path.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/stored> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
 - The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
@@ -341,12 +350,21 @@
 - A nonce-based CSP only blocks injected inline script, so DOM sinks and dangling markup remain exploitable under the same policy.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the policy is nonce- or hash-based with an unguessable per-load nonce and the payload yields no element carrying a matching nonce or hash AND no other reachable sink exists.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
+- A sanitizer can be bypassed with mutation XSS: markup that is safe under the sanitizer's parser is re-parsed by the browser into an executable form.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted if the sanitizer re-parses its own output before delivery, or if no re-serialization pipeline exists between input and render.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
+- Content Security Policy can be defeated when the vulnerable sink is an svg+xml response that ignores the script-src policy, a JSONP endpoint on a whitelisted domain, or a base tag that re-points script sources.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted if the CSP applies to the svg+xml response, the JSONP endpoint is not proxied through the domain, or the base-tag target is not reachable by the browser.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
 - HTML-encoding characters the filter blocks defeats it inside an event-handler attribute, because the browser HTML-decodes attribute values before JavaScript runs.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the browser decodes the attribute only once and the application re-encodes after decoding, or if the sink is textContent or a DOM property that receives the still-encoded value without HTML decoding.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 
 ## Chaining opportunities
 
+- A reflected XSS fused with an unkeyed cache input becomes persistent stored-equivalent XSS at CDN scale: the payload is injected through an unkeyed parameter and served to every visitor until the cache TTL.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** Refuted if the response is not cacheable, the injected parameter is keyed, or the reflection is sanitized or encoded before caching.
+  - Sources: <https://portswigger.net/research/practical-web-cache-poisoning> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws> · <https://portswigger.net/web-security/web-cache-poisoning/exploiting-implementation-flaws/lab-web-cache-poisoning-unkeyed-query>
 - A stored payload submitted through a low-privilege account that later renders inside an administrator's session escalates a self-XSS into administrator compromise, and proving it requires two distinct identities.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the payload fires only in the submitting account's own session and never renders in a second, higher-privileged user's view, then it is self-XSS and the escalation step is unproven.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/stored>
```

## 2026-10-28 21:11 — 41 diff lines
- items: 114 (supported 102), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 111 items, 99 supported, 27 FP rules, 1 chains
+> evidence: 114 items, 102 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -107,6 +107,9 @@
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- React and Next.js SSR shift the XSS surface rather than remove it: JSX escapes string values, but server-side rendering of unescaped data plus dangerouslySetInnerHTML / url / style sinks produce XSS that client-side sanitizers cannot reach.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Never use dangerouslySetInnerHTML without sanitizing; scheme-allow-list URLs in href; sanitize style/CSS; use React's built-in escaping and CSP with script-src nonces.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html> · <https://deepstrike.io/blog/nextjs-security-testing-bug-bounty-guide> · <https://mahsamohajer.com/security>
 - Self-XSS that harms only the attacker's own session becomes effective stored XSS and account takeover when combined with a CSRF-vulnerable field mutation endpoint.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted if the mutation endpoint enforces a CSRF token, SameSite=Lax/Strict cookies are required, or the field is not stored and rendered.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/csrf>
@@ -338,6 +341,9 @@
 - In a JavaScript template literal the payload does not need to escape the backtick, because the ${...} expression syntax executes during literal processing.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes $ or the brace characters, or if the value is interpolated by a templating engine that does not evaluate expressions at all.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- SVG onload and mutation XSS (mXSS) are bypass classes that survive html-sanitizer allow-lists: SVG fires onload automatically even where <script> is filtered, and mXSS exploits the parser/serialiser round-trip so a sanitizer sees a benign tree while the browser re-parses it into a dangerous one.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Sanitize with DOMPurify (pin >= 3.2.7 / 2.5.9), never mutate already-sanitized output, and avoid post-sanitisation DOM transforms.
+  - Sources: <https://swisskyrepo.github.io/PayloadsAllTheThings/XSS%20Injection/> · <https://www.vulnsy.com/cheat-sheets/xss>
 
 ## Defence bypasses
 
@@ -356,6 +362,9 @@
 - Content Security Policy can be defeated when the vulnerable sink is an svg+xml response that ignores the script-src policy, a JSONP endpoint on a whitelisted domain, or a base tag that re-points script sources.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted if the CSP applies to the svg+xml response, the JSONP endpoint is not proxied through the domain, or the base-tag target is not reachable by the browser.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
+- DOM clobbering turns benign injected HTML into XSS: an attacker injects markup whose id/name collides with a security-sensitive JS variable, and the browser's named-property behavior makes window.[name] resolve to an HTML element instead of the intended data. This is the XSS side-channel for sanitizers that block script tags but leave HTML in.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Freeze sensitive DOM objects (Object.freeze), type-check window properties before use (instanceof), sanitize id/name attributes before insertion, or declare globals with let/const so they are not window-properties.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html> · <https://www.codereviewlab.com/learning/advanced-xss>
 - HTML-encoding characters the filter blocks defeats it inside an event-handler attribute, because the browser HTML-decodes attribute values before JavaScript runs.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the browser decodes the attribute only once and the application re-encodes after decoding, or if the sink is textContent or a DOM property that receives the still-encoded value without HTML decoding.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
```

## 2026-10-28 21:43 — 28 diff lines
- items: 114 (supported 104), FP rules 27, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 114 items, 102 supported, 27 FP rules, 1 chains
+> evidence: 114 items, 104 supported, 27 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -110,12 +110,12 @@
 - React and Next.js SSR shift the XSS surface rather than remove it: JSX escapes string values, but server-side rendering of unescaped data plus dangerouslySetInnerHTML / url / style sinks produce XSS that client-side sanitizers cannot reach.  _(merged 1 duplicate row(s))_
   - **Disproof:** Never use dangerouslySetInnerHTML without sanitizing; scheme-allow-list URLs in href; sanitize style/CSS; use React's built-in escaping and CSP with script-src nonces.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html> · <https://deepstrike.io/blog/nextjs-security-testing-bug-bounty-guide> · <https://mahsamohajer.com/security>
-- Self-XSS that harms only the attacker's own session becomes effective stored XSS and account takeover when combined with a CSRF-vulnerable field mutation endpoint.  _(merged 1 duplicate row(s))_ _(unverified)_
+- Self-XSS that harms only the attacker's own session becomes effective stored XSS and account takeover when combined with a CSRF-vulnerable field mutation endpoint.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the mutation endpoint enforces a CSRF token, SameSite=Lax/Strict cookies are required, or the field is not stored and rendered.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/csrf>
-- Stored XSS in collaborative content (wiki, issue tracker, customer ticket, comment, label color, tag) is delivered to every viewer, and when a privileged user views it the payload runs in the privileged session.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/csrf>
+- Stored XSS in collaborative content (wiki, issue tracker, customer ticket, comment, label color, tag) is delivered to every viewer, and when a privileged user views it the payload runs in the privileged session.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted if the field sanitizes style/svg/math and the diagram renderer is sandboxed, or if privileged users are exempt from the render path.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/stored> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
 - The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
```

## 2026-10-31 06:41 — 224 diff lines
- items: 114 (supported 74), FP rules 22, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 114 items, 104 supported, 27 FP rules, 1 chains
+> evidence: 114 items, 74 supported, 22 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -20,7 +20,7 @@
 
 ## Prerequisites (do not start without these)
 
-- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.  _(merged 1 duplicate row(s))_
+- A message listener that never checks the origin of incoming messages turns cross-origin postMessage data into a cross-site scripting vector, because any hostile page can then drive the handler.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** A handler that rejects messages whose origin is not the expected one, and never writes the received data into a scriptable sink, is not reachable cross-origin.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
 - An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.  _(merged 1 duplicate row(s))_
@@ -44,7 +44,7 @@
 
 ## Recon signals (where to look)
 
-- A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal for reflected XSS.  _(merged 1 duplicate row(s))_
+- A short unique alphanumeric marker submitted to an entry point and found verbatim in the response is the working precondition signal for reflected XSS.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The marker is absent from the response, appears only encoded in a form that cannot be decoded back into a live context, or is reflected only after a separate later request.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
 - DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.  _(merged 1 duplicate row(s))_
@@ -74,7 +74,7 @@
 - An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
-- An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.  _(merged 1 duplicate row(s))_
+- An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is wrong if the sink is document.write rather than innerHTML, if the browser is one that still runs script elements assigned via innerHTML, or if a separate code path appends the node and executes it.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.  _(merged 1 duplicate row(s))_ _(unverified)_
@@ -86,7 +86,7 @@
 - DOM XSS reads attacker-controlled data in JavaScript (location.hash, location.search, location.href, document.referrer, document.write, innerHTML, eval, setTimeout or a string argument) and executes it against the serving origin.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Refuted if the sink is percent-encoded before reaching the DOM, the source is not attacker-controlled, or a real-browser probe does not execute the payload.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://portswigger.net/web-security/cross-site-scripting/cheat-sheet>
-- DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.  _(merged 1 duplicate row(s))_
+- DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.  _(merged 1 duplicate row(s))_
@@ -98,13 +98,13 @@
 - In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.  _(merged 1 duplicate row(s))_
   - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
-- Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.  _(merged 1 duplicate row(s))_
+- Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
 - Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent XSS, especially if you are required to ”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
-- Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_
+- Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - React and Next.js SSR shift the XSS surface rather than remove it: JSX escapes string values, but server-side rendering of unescaped data plus dangerouslySetInnerHTML / url / style sinks produce XSS that client-side sanitizers cannot reach.  _(merged 1 duplicate row(s))_
@@ -119,7 +119,7 @@
 - The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md>
-- The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.  _(merged 1 duplicate row(s))_
+- The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is wrong if the application reads the location and immediately decodes or strips it before any use, or if the page never passes the value into a sink that renders or executes it.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.  _(merged 1 duplicate row(s))_
@@ -131,7 +131,7 @@
 - XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.  _(merged 1 duplicate row(s))_
   - **Disproof:** Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“XSS can cause a variety of problems for the end user that range in severity from”) does not occur under a test that isolates that control.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
-- document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.  _(merged 1 duplicate row(s))_
+- document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is wrong if the value reaching the sink is sanitised by a vetted library configured for that sink, or is only ever assigned as a property value that the browser does not parse as markup.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 
@@ -161,25 +161,25 @@
 - Stored XSS is proven only by storing a payload as one identity and loading the exit point as a second identity, because your own session re-rendering your own input proves storage and reflection, never cross-user execution.  _(merged 1 duplicate row(s))_
   - **Disproof:** The procedure is wrong if you only ever test with one account and the app renders stored values differently per role - the marker may be HTML-encoded for the author and injected raw into an admin moderation queue, so your own view can look safe while the privileged view is exploitable. It is also wrong where stored data is overwritten before any second read (recent-searches lists, ephemeral carts); a marker found once is not proof of durable storage - re-read the exit point after an unrelated action to confirm it survives.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
-- To decide this case, observe: If the sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: If the sanitizer stripped the element, event handler or javascript: URL, the surviving characters are inserted as TEXT - the marker is visible in the rendered output as literal characters, no element with a live handler exists, no beacon fires and no console error appears from your payload.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sanitizer.output_observed_inert_in_page) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Document/write>
-- To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.validation.self_fired_marker_is_not_a_reportable_finding) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
-- To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: When a value is reflected into a scriptable attribute such as onclick and the filter blocks the quote character, HTML-encoding it works around the filter.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.bypass.filter.html_entity_decoding_of_attribute_values) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
-- To decide this case, observe: Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.sink_reachability.source_never_reaches_execution_sink) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
-- To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Why it looks vulnerable: the markup injection is real - your marker sits unencoded in an HTML-executing context - so the defect is genuine even when nothing happens when the victim clicks.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.csp.live_nonce_or_hash_policy_blocks_payload) states the full boundary.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
 - To decide this case, observe: Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.stored_xss.entry_point_never_reaches_second_user_view) states the full boundary.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
-- To decide this case, observe: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.  _(merged 1 duplicate row(s))_
+- To decide this case, observe: Why it looks vulnerable: you POST {"name":"<script>alert(1)</script>"} to /api/profile and the string comes back verbatim in the response body - a clean taint-to-reflection path with a classic payload.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (xss.fp_rule.json_api.content_type_json_is_not_html_execution) states the full boundary.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
 - To decide this case, observe: Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself.  _(merged 1 duplicate row(s))_
@@ -200,7 +200,7 @@
 - A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the payload demonstrably renders and executes in a second, independently authenticated session or in a view reached by another user, then the marker is not self-only and the finding does clear the bar.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
-- A reflected XSS on a page whose CSP is nonce-based is only exploitable if the injected markup executes on that same page and inherits its policy; a payload delivered on a page with no CSP header, or a different policy, is not covered by the nonce argument.  _(merged 1 duplicate row(s))_
+- A reflected XSS on a page whose CSP is nonce-based is only exploitable if the injected markup executes on that same page and inherits its policy; a payload delivered on a page with no CSP header, or a different policy, is not covered by the nonce argument.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is false if the policy uses 'strict-dynamic' together with a host allow-list, because a single executed script then loads arbitrary further script without needing the nonce again. It is also false if the nonce value is itself attacker-influenced - reflected in the page, derived from a predictable or reused value, or set on a script the attacker controls - since the whole policy then collapses to allowing that script. And a policy that omits default-src or leaves script-src unset inherits the permissive default, so no nonce is being enforced in the first place. Finally the argument is void if the vulnerable response carries no Content-Security-Policy header at all.
... (truncated)
```

## 2026-11-02 23:13 — 11 diff lines
- items: 114 (supported 74), FP rules 22, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -451,7 +451,7 @@
 
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
-Full class document: `domains/web/xss/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
+Full class document: `skills/web/xss/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
 
 ---
 Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-11-02 23:31 — 12 diff lines
- items: 114 (supported 74), FP rules 22, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -5,7 +5,8 @@
 
 # Cross-Site Scripting — hunting skill
 
-<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
+<!-- GENERATED from db/wks.db — do not edit -->
+<!-- Generated by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
      python -m wks.skillgen -->
 
```
