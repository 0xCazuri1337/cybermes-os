# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 00:09 — 1 diff lines
- items: 12 (supported 12), FP rules 0, chains 0, state researching
- still missing: fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 00:49 — 149 diff lines
- items: 39 (supported 39), FP rules 1, chains 1, state researching
- still missing: fp_rules

```diff
--- xss@current
+++ xss@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 12 items, 12 supported, 0 FP rules, 0 chains
-> maturity: **researching** — missing: fp_rules, chain
+> evidence: 39 items, 39 supported, 1 FP rules, 1 chains
+> maturity: **researching** — missing: fp_rules
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
 
@@ -40,7 +40,25 @@
 
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.
+  - **Disproof:** This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
+  - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.
+  - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.
+  - **Disproof:** This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.
+  - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.
+  - **Disproof:** This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.
   - **Disproof:** The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
@@ -49,34 +67,106 @@
 
 - If a DOM source value is URL-encoded before reaching the sink the markup payload cannot survive, making the candidate a false positive.
   - **Disproof:** A non-encoded payload with no percent sequences in the traced value reaches the sink and executes script in the victim's browser.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+- An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.
+  - **Disproof:** This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - An HttpOnly session cookie removes the cookie-exfiltration chain, so impact must be restated as in-origin actions rather than session theft.
   - **Disproof:** The session cookie lacks HttpOnly and document.cookie returns it inside the injected script, so full session replay is achievable.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
+- A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.
+  - **Disproof:** If the payload demonstrably renders and executes in a second, independently authenticated session or in a view reached by another user, then the marker is not self-only and the finding does clear the bar.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
 
 ## False-positive rules (when to reject it)
 
+- Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.
+  - **Disproof:** The rule is wrong if the session cookie lacks HttpOnly and document.cookie returns it to injected script, in which case full session replay IS achievable and the original impact claim stands. It is also wrong when the sensitive credential is not the cookie at all - a JWT or API token in localStorage or sessionStorage, or a CSRF token readable from the DOM, is unaffected by HttpOnly. Read the Session Management cheat sheet's own warning before assuming HttpOnly helps: it only protects the confidentiality of that one cookie.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
+- Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.
+  - **Disproof:** The rule is wrong when the policy contains 'unsafe-inline' (or 'unsafe-eval' for eval-style payloads), or when strict-dynamic is present and the injection point runs on a page that already loaded a nonced/hash-trusted script - in both cases a nonce-less injected script is executed anyway and the finding is a full XSS. It is also wrong if the CSP is only a report-only header (Content-Security-Policy-Report-Only), which logs violations without blocking anything.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
+- Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.
+  - **Disproof:** The rule is wrong if the clobbered or polluted property is later assigned into an HTML-executing sink - a clobbered script src/iframe src whose value navigates to attacker markup, or a polluted property consumed by a template that renders it as HTML - because that is script execution with an injection-only primitive, and it is a real XSS. OWASP's own note that CSP mitigates clobbering of script sources but not already-present code that can be abused for execution is the same distinction seen from the mitigation side.
+  - Sources: <https://portswigger.net/web-security/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
+- Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.
+  - **Disproof:** The rule is wrong if the encoding is applied for the wrong context - for example only HTML-entity-encoded output dropped inside a JavaScript string, a URL, a CSS value or an unquoted attribute, where &quot; and &#39; do not neutralise a quote delimiter and a ';alert(1)// payload still breaks the string. It is also wrong if the entity is decoded and re-serialised anywhere before rendering (a client-side read of .innerHTML followed by a re-write, or a client-side template that re-interprets the text as HTML), because then the inert text becomes live markup.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.
+  - **Disproof:** The rule is wrong if the same reflected value reaches an HTML-executing context through any code path: the API is called by a front end that assigns the response into innerHTML or a framework's raw-HTML binding, the endpoint is reachable at the same path with a text/html or JSONP callback content type, or the server renders the stored value into an HTML page for other users. Then the JSON body is only the delivery mechanism, and the finding is a genuine XSS located at the sink.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
+- Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.
+  - **Disproof:** The rule is wrong if the polluted property is consumed by a templating engine or a client-side render that inserts it as markup - a server-side template interpolating the inherited property, or front-end code writing it to innerHTML or a raw-HTML framework binding - because then the pollution is the injection primitive and the result is stored XSS reachable by every user of the app. Equally, if the pollution reaches a code-execution gadget (a template engine option object, a child-process invocation), that is RCE, which is a stronger finding than the XSS report claimed.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html>
 - A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.
   - **Disproof:** The page's origin exposes no authenticated state, no same-origin privileged endpoints and no tokens reachable from injected script, leaving only a bare popup.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
+- Reject a sanitizer-bypass XSS claim when the rendered page shows the payload as inert text with the dangerous markup stripped, because a payload that does not become live DOM in the browser is not a bypass.
+  - **Disproof:** The rule is wrong if a real element with a live event handler or a navigable javascript:/data: URL is present in the rendered DOM and your callback endpoint receives the request - that is a genuine sanitizer bypass and a real XSS, even if the sanitizer appeared to strip <script>. The rule also does not apply where the string is sanitized and then mutated or re-serialised before insertion, since the protection can be voided downstream; check the sink, not the sanitizer call.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Document/write>
+- Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.
+  - **Disproof:** The candidate stops being self-XSS the moment a working delivery exists: a crafted URL (or a CSRF-style auto-submitting form) that fires the payload automatically in any other user's browser, on a page an authenticated victim visits. Then it is ordinary reflected XSS and this rejection rule is wrong. Equally, if the 'pasting' step is not required because the value is stored and later rendered to other users, the finding is stored XSS, not self-XSS.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+- Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.
+  - **Disproof:** The candidate is a real DOM XSS if the identical tainted value, in the identical code path, is also passed to an execution-capable sink - innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/string setTimeout - anywhere the same value can reach on another page load, in a fallback branch, or for a different input shape. This rule is also wrong if setAttribute's attribute NAME is derived from the same tainted input (setAttribute(t, v) where t is user-influenced), because OWASP limits setAttribute's safety to hardcoded, innocuous attribute names; an injected name such as onmouseover re-creates an injection sink.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+- Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
+  - **Disproof:** The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
 
 ## Impact framing
 
 - The same reflected XSS has materially higher impact on a page behind login than on an unauthenticated page, because the victim's session grants privileged in-origin actions.
   - **Disproof:** The vulnerable endpoint is reachable and exploitable only while unauthenticated, and no authenticated page on the same origin reflects the same parameter.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
+- Serving the vulnerable page over HTTPS changes nothing about the attack, because same-origin script execution is scoped by origin, and https is part of the origin definition rather than a barrier to it.
+  - **Disproof:** If the payload only executes on a plaintext HTTP origin and the browser blocks it or the application serves different content over HTTPS, then the scheme does affect the finding and this claim does not hold for it.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
+
+## Variants
+
+- In a JavaScript template literal the payload does not need to escape the backtick, because the ${...} expression syntax executes during literal processing.
+  - **Disproof:** This is wrong if the application escapes $ or the brace characters, or if the value is interpolated by a templating engine that does not evaluate expressions at all.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 
 ## Defence bypasses
 
 - A CSP only blocks inline or foreign script execution; nonces, hashes and strict-dynamic decide whether an injected payload can still run.
   - **Disproof:** The policy is nonce- or hash-based with an unguessable per-load nonce and no unsafe-inline, and the payload yields no element carrying a matching nonce or hash.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
+- HTML-encoding characters the filter blocks defeats it inside an event-handler attribute, because the browser HTML-decodes attribute values before JavaScript runs.
+  - **Disproof:** This is wrong if the browser decodes the attribute only once and the application re-encodes after decoding, or if the sink is textContent or a DOM property that receives the still-encoded value without HTML decoding.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+- A filter blocking parentheses is bypassed by invoking the function without them, for example with a throw statement and a global exception handler.
+  - **Disproof:** This is wrong if the filter also blocks the throw keyword, the semicolon, or the equals sign, or if the application CSP forbids inline handlers so no assignment is ever reached.
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 
... (truncated)
```

## 2026-10-02 00:49 — 23 diff lines
- items: 39 (supported 39), FP rules 2, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,8 +10,8 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 39 items, 39 supported, 1 FP rules, 1 chains
-> maturity: **researching** — missing: fp_rules
+> evidence: 39 items, 39 supported, 2 FP rules, 1 chains
+> maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
 
@@ -167,6 +167,9 @@
 - **GET /search returns the q parameter unencoded in the HTML body**
   - Killed by: The response was served as application/json and the page inserted it via textContent, so the injected markup was parsed as text and never became nodes
   - Rule: Reflection is not execution: confirm the response is parsed as HTML and that the value reaches an execution-capable sink before calling it XSS
+- **Cookie theft via reflected XSS on an authenticated settings page**
+  - Killed by: The session cookie carried HttpOnly, so document.cookie returned nothing — but the script could still read the page's CSRF token and submit the password change with it, which is the real impact
+  - Rule: Never price XSS as cookie theft until you read the cookie flags; with HttpOnly the finding is in-origin privileged action, which is usually higher impact anyway
 
 ---
 Full class document: `classes/xss.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
```

## 2026-10-02 00:55 — 98 diff lines
- items: 48 (supported 48), FP rules 2, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 39 items, 39 supported, 2 FP rules, 1 chains
+> evidence: 48 items, 48 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -38,6 +38,27 @@
 
 ## Techniques (what to change)
 
+- Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.
+  - **Disproof:** This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
+- An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.
+  - **Disproof:** This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
+- An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.
+  - **Disproof:** This is wrong if the sink is document.write rather than innerHTML, if the browser is one that still runs script elements assigned via innerHTML, or if a separate code path appends the node and executes it.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.
+  - **Disproof:** This is wrong if the value reaching the sink is sanitised by a vetted library configured for that sink, or is only ever assigned as a property value that the browser does not parse as markup.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.
+  - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.
+  - **Disproof:** This is wrong if the application reads the location and immediately decodes or strips it before any use, or if the page never passes the value into a sink that renders or executes it.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.
+  - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
@@ -65,9 +86,12 @@
 
 ## Validation bar (how to prove it)
 
+- A page that handles postMessage without validating event.origin accepts attacker-controlled input from any origin.
+  - **Disproof:** This is wrong if the handler verifies event.origin against an exact expected origin before acting, or if the data is only used in a context that cannot reach a sink or a privileged action.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage>
 - If a DOM source value is URL-encoded before reaching the sink the markup payload cannot survive, making the candidate a false positive.
   - **Disproof:** A non-encoded payload with no percent sequences in the traced value reaches the sink and executes script in the victim's browser.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.
   - **Disproof:** This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
@@ -85,7 +109,7 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
 - Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.
   - **Disproof:** The rule is wrong when the policy contains 'unsafe-inline' (or 'unsafe-eval' for eval-style payloads), or when strict-dynamic is present and the injection point runs on a page that already loaded a nonced/hash-trusted script - in both cases a nonce-less injected script is executed anyway and the finding is a full XSS. It is also wrong if the CSP is only a report-only header (Content-Security-Policy-Report-Only), which logs violations without blocking anything.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
 - Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.
   - **Disproof:** The rule is wrong if the clobbered or polluted property is later assigned into an HTML-executing sink - a clobbered script src/iframe src whose value navigates to attacker markup, or a polluted property consumed by a template that renders it as HTML - because that is script execution with an injection-only primitive, and it is a real XSS. OWASP's own note that CSP mitigates clobbering of script sources but not already-present code that can be abused for execution is the same distinction seen from the mitigation side.
   - Sources: <https://portswigger.net/web-security/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
@@ -97,7 +121,7 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
 - Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.
   - **Disproof:** The rule is wrong if the polluted property is consumed by a templating engine or a client-side render that inserts it as markup - a server-side template interpolating the inherited property, or front-end code writing it to innerHTML or a raw-HTML framework binding - because then the pollution is the injection primitive and the result is stored XSS reachable by every user of the app. Equally, if the pollution reaches a code-execution gadget (a template engine option object, a child-process invocation), that is RCE, which is a stronger finding than the XSS report claimed.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.
   - **Disproof:** The page's origin exposes no authenticated state, no same-origin privileged endpoints and no tokens reachable from injected script, leaving only a bare popup.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting>
@@ -109,7 +133,7 @@
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
 - Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.
   - **Disproof:** The candidate is a real DOM XSS if the identical tainted value, in the identical code path, is also passed to an execution-capable sink - innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/string setTimeout - anywhere the same value can reach on another page load, in a fallback branch, or for a different input shape. This rule is also wrong if setAttribute's attribute NAME is derived from the same tainted input (setAttribute(t, v) where t is user-influenced), because OWASP limits setAttribute's safety to hardcoded, innocuous attribute names; an injected name such as onmouseover re-creates an injection sink.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
   - **Disproof:** The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
@@ -133,13 +157,16 @@
 
 - A CSP only blocks inline or foreign script execution; nonces, hashes and strict-dynamic decide whether an injected payload can still run.
   - **Disproof:** The policy is nonce- or hash-based with an unguessable per-load nonce and no unsafe-inline, and the payload yields no element carrying a matching nonce or hash.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
 - HTML-encoding characters the filter blocks defeats it inside an event-handler attribute, because the browser HTML-decodes attribute values before JavaScript runs.
   - **Disproof:** This is wrong if the browser decodes the attribute only once and the application re-encodes after decoding, or if the sink is textContent or a DOM property that receives the still-encoded value without HTML decoding.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - A filter blocking parentheses is bypassed by invoking the function without them, for example with a throw statement and a global exception handler.
   - **Disproof:** This is wrong if the filter also blocks the throw keyword, the semicolon, or the equals sign, or if the application CSP forbids inline handlers so no assignment is ever reached.
   - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
+- A nonce-based CSP only blocks injected inline script, so DOM sinks and dangling markup remain exploitable under the same policy.
+  - **Disproof:** This is wrong if the policy is nonce- or hash-based with an unguessable per-load nonce and the payload yields no element carrying a matching nonce or hash AND no other reachable sink exists.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
 
 ## Chaining opportunities
 
```

## 2026-10-02 01:36 — 11 diff lines
- items: 48 (supported 48), FP rules 2, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -7,7 +7,7 @@
 
 <!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
      Edit the rows (or ingest better research) and re-run:
-     python -m wks.skillgen -->
+     python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
 > evidence: 48 items, 48 supported, 2 FP rules, 1 chains
```

## 2026-10-02 02:06 — 145 diff lines
- items: 66 (supported 66), FP rules 2, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 48 items, 48 supported, 2 FP rules, 1 chains
+> evidence: 66 items, 66 supported, 2 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -61,28 +61,61 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.
   - **Disproof:** This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.
   - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.
   - **Disproof:** This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.
   - **Disproof:** This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.
   - **Disproof:** The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
+
+## Tests
+
+- When a filter blocks your quote or tag characters, probe the decoder gap in a fixed order - HTML-entity-encode the blocked character first, then prepend a backslash to neutralise the app's own escaping - and a hit proves the filter normalises but does not neutralise.
+  - **Disproof:** The procedure is wrong if the entity probe is fired at the wrong layer: &#39; only helps where the browser HTML-decodes before parsing, so sending it into a JS string inside a <script> block, into a URL, or into a CSS value does nothing, and a hunter who treats a non-firing entity probe as proof of safety has only tested one decoder. It is also wrong to stop at the first working bypass - the same filter may have a second gap, and reporting only the first understates the defect.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- When a filter blocks parentheses you switch to a parentheses-free invocation, and when the reflection lands inside backticks you use ${...} with no terminator at all - both are determined by what step 1 showed you in the response.
+  - **Disproof:** The procedure is wrong if the marker lands in a template literal that is never actually evaluated as a tagged/interpolated expression at runtime (a string built for display, or a literal inside a JSON blob parsed as data) - ${...} then stays literal text and you will have burned the window on the wrong technique. It is also wrong to assume parentheses-free invocation survives everywhere: onerror=alert;throw 1 needs an element that fires error, so on a non-error context the payload is inert and the miss is a context error, not proof the filter holds.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- Reading the characters immediately before and after each reflection point tells you which of the six XSS contexts you are in, and the context selects the payload family, so no payload should be tried before the context is named.
+  - **Disproof:** The procedure is wrong if a single reflection is genuinely multi-context - the same marker echoed into a hidden input AND an inline script AND a data attribute - because naming one context hides the others; you must enumerate every offset, not the first one found. It is also wrong where the payload family is chosen but the surrounding markup makes it inert: a marker inside a <title>, inside an HTML comment, inside a <textarea>, or inside an already-escaped attribute with no decode step later. Those require a different escape, not a context-specific payload.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+- Before writing an impact claim, read the live response headers for the CSP nonce/hash/strict-dynamic directives, the HttpOnly flag on the session cookie, and any require-trusted-types-for directive, because each one caps what your confirmed execution can actually do.
+  - **Disproof:** The procedure is wrong if you treat a nonce you observed on one page load as a permanent value and paste it into a payload - a nonce is regenerated per response, so a captured nonce will not match and the test fails for the wrong reason. It is also wrong to conclude a control blocks impact from the header alone: nonce/hash/strict-dynamic govern script execution, not already-confirmed event-handler execution through a parsed HTML node in every policy, and HttpOnly says nothing about tokens held in localStorage.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
+- Grepping a downloaded JS bundle for the concrete sink token set - innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln, eval, new Function, setTimeout/setInterval with a string first argument, and the jQuery html/append family - is what converts 'this page uses innerHTML somewhere' into a list of lines you can actually test.
+  - **Disproof:** The procedure is wrong if the sink token appears in dead code, a comment, a minifier artifact, or an error-handling branch that never runs - a raw grep hit is a candidate list, not a vulnerability, and a hit list with no reachability analysis will generate false positives. It is also wrong as a completeness claim: many apps reach sinks through a framework abstraction (a template engine's {{{ }}} escape, a v-html directive, React's dangerouslySetInnerHTML) where the literal token never appears in any bundle.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- For DOM XSS you must seed the marker into a client-side source such as location.search and locate it in the live DOM with devtools Control+F, because the browser's View Source never shows JavaScript-injected nodes.
+  - **Disproof:** The procedure is wrong if the app renders the marker only after an interaction or a timer - a click, a scroll, a setTimeout, a route change - because a single load-time Control+F finds nothing and the source IS reachable. It is also wrong where the value is passed to an execution sink such as eval or setTimeout-with-string, where the marker legitimately never appears in the DOM, so 'absent from the DOM' is not evidence of safety and must not be recorded as a clean result.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- A DOM XSS claim is only proven when the debugger shows an actual value flowing from a source read into an execution sink, because grepping source and sink names separately proves nothing about the path between them.
+  - **Disproof:** The procedure is wrong if the path is data-dependent and your single marker run takes a different branch than the attacker's input would (a length check, an if/else on the first character, a try/catch). A clean debugger trace on one marker does not prove the branch an attacker's payload would take is also safe. It is also wrong to stop at the first sink: a value often flows into a safe sink AND an unsafe sink, so the trace must continue to every use of the tainted variable.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- A short unique alphanumeric marker echoed verbatim in the response, from every request-controlled entry point tested one at a time, is the pass condition that proves reflection exists before any payload is chosen.
+  - **Disproof:** The procedure is wrong if the marker reflects yet no XSS is reachable - that is a real possibility the method cannot detect: the reflection may sit inside a comment, inside an HTML entity-encoded attribute the app later re-decodes and re-renders on another page, or inside a JSON field that a second script writes into innerHTML on a different route. It is also wrong if the 'static string' control is insufficient, because an app that echoes a per-session value (a CSRF token built from your marker, a request-id cache) will pass step 4 and still tell you nothing about general reflection.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+- A payload only counts as XSS once a real browser parses the delivered page and the injected JavaScript actually runs; a payload visible in Repeater's response pane is unexecuted source text, not a finding.
+  - **Disproof:** The procedure is wrong if a payload executes with no visible trace you chose to look for - e.g. the proof writes to a network beacon instead of the DOM, so 'no alert' reads as failure when execution actually happened. It is also wrong to require a visible popup as the sole gate: CSP report-only mode, Trusted Types default policies, and headless profiles can all suppress alert() while script still runs. Confirm with a second, independent observable (network egress, DOM mutation, console log) before calling it a failure.
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+- Stored XSS is proven only by storing a payload as one identity and loading the exit point as a second identity, because your own session re-rendering your own input proves storage and reflection, never cross-user execution.
+  - **Disproof:** The procedure is wrong if you only ever test with one account and the app renders stored values differently per role - the marker may be HTML-encoded for the author and injected raw into an admin moderation queue, so your own view can look safe while the privileged view is exploitable. It is also wrong where stored data is overwritten before any second read (recent-searches lists, ephemeral carts); a marker found once is not proof of durable storage - re-read the exit point after an unrelated action to confirm it survives.
+  - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
 
 ## Validation bar (how to prove it)
 
@@ -94,7 +127,7 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
 - An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.
   - **Disproof:** This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.
-  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
 - An HttpOnly session cookie removes the cookie-exfiltration chain, so impact must be restated as in-origin actions rather than session theft.
   - **Disproof:** The session cookie lacks HttpOnly and document.cookie returns it inside the injected script, so full session replay is achievable.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
@@ -138,6 +171,33 @@
   - **Disproof:** The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.
   - Sources: <https://owasp.org/www-community/attacks/xss/> · <https://portswigger.net/web-security/cross-site-scripting/stored>
 
+## Evidence requirements
+
+- An attacker-controlled value reflected inside a quoted HTML attribute can execute script without ever emitting an angle bracket, by terminating the attribute value, adding an onfocus handler plus autofocus, and repairing the trailing markup with a bare x=" so the parser stays in sync.
+  - **Disproof:** This claim is wrong if the reflected value is HTML-entity-encoded before it lands in the attribute, because &quot; is decoded as text rather than as a quote delimiter and the attribute value never terminates. It is also wrong for an unquoted attribute whose landing context forbids the characters entirely, or if the page sets a CSP without 'unsafe-inline' in script-src, since an inline event handler is then refused by the browser and the handler never runs. Finally it is wrong if autofocus is stripped from allowed attributes AND no user interaction is possible (for example the element is display:none or inside a hidden tab), because then onfocus never fires.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+- When a site reflects attacker input into its own Content-Security-Policy - typically the trailing report-uri directive - a semicolon lets the attacker append directives, and the script-src-elem directive lets an appended script-src overwrite the existing nonce or hash based script-src entirely.
+  - **Disproof:** The claim is wrong if the site does not reflect any input into the policy, since there is then nothing to inject and the nonce stands. It is also wrong if the reflected value is filtered so a semicolon or a comma cannot appear, because then no new directive can be opened. It is wrong for browsers that do not implement script-src-elem, where an appended script-src would simply be dropped as a duplicate and the original policy would still apply. And it is wrong for servers that deliver the policy as a meta tag rather than a header in a context where the attacker controls only part of the value, since the injected text is then inert element content rather than a directive.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/content-security-policy>
+- Client-side template injection in an AngularJS page executes when the framework's expression evaluator parses the attacker's text, so an injected expression that overwrites String.prototype.charAt defeats the sandbox's own identifier check and hands $eval straight to the attacker.
+  - **Disproof:** The claim is wrong on AngularJS 1.6 and later, where the sandbox was removed entirely because it was never a real security boundary, so the charAt overwrite is unnecessary but the payload still works - which does not make the claim false, it makes it outdated as a description of necessity. It is genuinely wrong if the application never passes untrusted data into an AngularJS template expression or filter, because then no evaluation happens at all and the payload is inert text. It is also wrong if a CSP is enforced in a mode that blocks inline script and the expression cannot reach a DOM event AngularJS itself defines, since the CSP path then refuses the execution.
+  - Sources: <https://cwe.mitre.org/data/definitions/1336.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
+- Injecting an unterminated img src attribute captures the rest of the victim's response into an outbound request URL without executing any script, because the HTML tokenizer stays in the double-quoted attribute value state until it finds the next quotation mark anywhere in the document.
+  - **Disproof:** The claim is wrong if the surrounding markup contains no double quotation mark at all after the injection point, because the attribute value then consumes to end of file and the browser issues a request with an empty or truncated value. It is also wrong on Chrome, which blocks img URLs containing raw angle brackets and newlines, since the captured content would have to contain one of those to be interesting. It is wrong if the site filters '>' or the quotation mark in the landing context, since the attacker cannot open the new tag at all. And it is wrong under a CSP with img-src 'self', which blocks the external request entirely, leaving no capture.
+  - Sources: <https://html.spec.whatwg.org/multipage/parsing.html> · <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
+- Assigning to element.innerHTML does not run an injected <script> element on any modern browser, so a DOM XSS payload aimed at that sink must instead use an element whose event fires on parse failure, such as an <img> with an invalid src and an onerror handler.
+  - **Disproof:** The claim is wrong if the target browser is one that still executes script elements inserted via innerHTML, since that pre-existing behaviour was never removed from the HTML fragment parsing algorithm in every engine. It is also wrong if the sink is document.write or document.writeln rather than innerHTML, because those go through the full parser and do run a script element. It is additionally wrong for a sink that later re-reads the .innerHTML property and passes it to document.write or eval, where the script element executes after the second step. And it is wrong where Trusted Types enforcement is on and the assignment throws before any parsing happens.
+  - Sources: <https://developer.mozilla.org/en-US/docs/Web/API/Element/innerHTML> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+- A postMessage listener that never reads event.origin accepts a message from any site, and because any window in the iframe hierarchy can reach the handler top-down, the receiver must check the origin against an allow-list before acting on event.data.
+  - **Disproof:** The claim is wrong if the receiver does validate e.origin against an allow-list before touching e.data, since then a forged-origin message is rejected and nothing executes - the listener existing is not the finding. It is also wrong if the sink inside the handler is not reachable with attacker-chosen data, for example the handler reads only a fixed key and never assigns a value into innerHTML, eval, or a script src. And it is wrong if the handler validates both origin and the syntax of the received message and re-validates before use, because MDN notes that an unvalidated message body from an otherwise trusted sender can itself be the XSS hole.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage>
+- A client-side prototype pollution source plus a config object that falls back to a default option becomes script execution when the library writes that inherited option into a script element's src and appends it to the document.
+  - **Disproof:** The claim is wrong if the config object defines its own transport_url property, because an object's own property takes precedence over anything inherited from the prototype and the gadget cannot fire. It is also wrong if the object is created with a null prototype or if Object.prototype is frozen or sealed, since then nothing is inherited and nothing to pollute. It is wrong if the sink is not reached - for example the library only builds a URL string for display and never assigns it to a fetching property. And it is wrong if a CSP restricts script-src to the origin's own domain, in which case the appended script is blocked and the chain stops at the network request rather than executing.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/prototype-pollution>
+- With require-trusted-types-for enforced, a DOM sink that receives a plain string does not silently sanitise it - the browser attempts to obtain a TrustedScript from a default policy and, if none is defined or none returns one, the operation throws an exception instead of executing.
+  - **Disproof:** The claim is wrong if a default policy is defined and its transformation function returns the input unchanged, for example a policy built with DOMPurify replaced by an identity function - the sink then receives a TrustedScript and the exception never fires. It is also wrong for an indirect sink that bypasses the check, such as assigning to innerText on a script element or building a script element from a text node, where in some engine versions the check is not applied at the point of assignment. It is wrong where require-trusted-types-for is not actually in the delivered policy header, including the case where the header is present but a report-only variant is used. And it is wrong on browsers that do not implement Trusted Types at all, where the payload runs unchanged.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API>
+
... (truncated)
```

## 2026-10-02 10:30 — 264 diff lines
- items: 67 (supported 67), FP rules 25, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 66 items, 66 supported, 2 FP rules, 1 chains
+> evidence: 67 items, 67 supported, 25 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -46,67 +46,67 @@
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/dangling-markup>
 - An innerHTML sink will not execute an injected script element, so execution requires an event-handler element such as img or iframe.
   - **Disproof:** This is wrong if the sink is document.write rather than innerHTML, if the browser is one that still runs script elements assigned via innerHTML, or if a separate code path appends the node and executes it.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - document.write, innerHTML, outerHTML, insertAdjacentHTML and jQuery html() are execution-capable sinks, while textContent is not.
   - **Disproof:** This is wrong if the value reaching the sink is sanitised by a vetted library configured for that sink, or is only ever assigned as a property value that the browser does not parse as markup.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - DOM-based XSS exists only where an attacker-controllable source reaches a sink that supports dynamic code execution.
   - **Disproof:** This is wrong if the source is read but its value only ever reaches a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - The URL is the most common DOM XSS source, and the payload can ride in the query string, the fragment, or the path.
   - **Disproof:** This is wrong if the application reads the location and immediately decodes or strips it before any use, or if the page never passes the value into a sink that renders or executes it.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - Injected markup with an id or name attribute creates a window/document property that shadows built-in APIs, turning attacker markup into a live configuration object.
   - **Disproof:** This is wrong if the page never reads the clobbered property, if the injected markup cannot set an id or name attribute in that position, or if the code uses getElementById or a scoped lookup that bypasses named property access.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.
   - **Disproof:** This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.
   - **Disproof:** A finding here is wrong if the application escapes or re-quotes the value so no new attribute can be injected, or if a strict CSP blocks inline event handlers outright.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.
   - **Disproof:** This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.
   - **Disproof:** This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - Inside a quoted JavaScript string literal the payload must both escape the string delimiter and repair the trailing script, because any syntax error prevents execution.
   - **Disproof:** This is wrong if the application escapes the delimiter so the string cannot be terminated, or if the value is placed in a context that is not a string literal at all.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.
   - **Disproof:** This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.
   - **Disproof:** The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 
 ## Tests
 
 - When a filter blocks your quote or tag characters, probe the decoder gap in a fixed order - HTML-entity-encode the blocked character first, then prepend a backslash to neutralise the app's own escaping - and a hit proves the filter normalises but does not neutralise.
   - **Disproof:** The procedure is wrong if the entity probe is fired at the wrong layer: &#39; only helps where the browser HTML-decodes before parsing, so sending it into a JS string inside a <script> block, into a URL, or into a CSS value does nothing, and a hunter who treats a non-firing entity probe as proof of safety has only tested one decoder. It is also wrong to stop at the first working bypass - the same filter may have a second gap, and reporting only the first understates the defect.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html>
 - When a filter blocks parentheses you switch to a parentheses-free invocation, and when the reflection lands inside backticks you use ${...} with no terminator at all - both are determined by what step 1 showed you in the response.
   - **Disproof:** The procedure is wrong if the marker lands in a template literal that is never actually evaluated as a tagged/interpolated expression at runtime (a string built for display, or a literal inside a JSON blob parsed as data) - ${...} then stays literal text and you will have burned the window on the wrong technique. It is also wrong to assume parentheses-free invocation survives everywhere: onerror=alert;throw 1 needs an element that fires error, so on a non-error context the payload is inert and the miss is a context error, not proof the filter holds.
-  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html>
 - Reading the characters immediately before and after each reflection point tells you which of the six XSS contexts you are in, and the context selects the payload family, so no payload should be tried before the context is named.
   - **Disproof:** The procedure is wrong if a single reflection is genuinely multi-context - the same marker echoed into a hidden input AND an inline script AND a data attribute - because naming one context hides the others; you must enumerate every offset, not the first one found. It is also wrong where the payload family is chosen but the surrounding markup makes it inert: a marker inside a <title>, inside an HTML comment, inside a <textarea>, or inside an already-escaped attribute with no decode step later. Those require a different escape, not a context-specific payload.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://portswigger.net/web-security/cross-site-scripting/reflected> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - Before writing an impact claim, read the live response headers for the CSP nonce/hash/strict-dynamic directives, the HttpOnly flag on the session cookie, and any require-trusted-types-for directive, because each one caps what your confirmed execution can actually do.
   - **Disproof:** The procedure is wrong if you treat a nonce you observed on one page load as a permanent value and paste it into a payload - a nonce is regenerated per response, so a captured nonce will not match and the test fails for the wrong reason. It is also wrong to conclude a control blocks impact from the header alone: nonce/hash/strict-dynamic govern script execution, not already-confirmed event-handler execution through a parsed HTML node in every policy, and HttpOnly says nothing about tokens held in localStorage.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/content-security-policy> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html>
 - Grepping a downloaded JS bundle for the concrete sink token set - innerHTML, outerHTML, insertAdjacentHTML, document.write/writeln, eval, new Function, setTimeout/setInterval with a string first argument, and the jQuery html/append family - is what converts 'this page uses innerHTML somewhere' into a list of lines you can actually test.
   - **Disproof:** The procedure is wrong if the sink token appears in dead code, a comment, a minifier artifact, or an error-handling branch that never runs - a raw grep hit is a candidate list, not a vulnerability, and a hit list with no reachability analysis will generate false positives. It is also wrong as a completeness claim: many apps reach sinks through a framework abstraction (a template engine's {{{ }}} escape, a v-html directive, React's dangerouslySetInnerHTML) where the literal token never appears in any bundle.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - For DOM XSS you must seed the marker into a client-side source such as location.search and locate it in the live DOM with devtools Control+F, because the browser's View Source never shows JavaScript-injected nodes.
   - **Disproof:** The procedure is wrong if the app renders the marker only after an interaction or a timer - a click, a scroll, a setTimeout, a route change - because a single load-time Control+F finds nothing and the source IS reachable. It is also wrong where the value is passed to an execution sink such as eval or setTimeout-with-string, where the marker legitimately never appears in the DOM, so 'absent from the DOM' is not evidence of safety and must not be recorded as a clean result.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html>
 - A DOM XSS claim is only proven when the debugger shows an actual value flowing from a source read into an execution sink, because grepping source and sink names separately proves nothing about the path between them.
   - **Disproof:** The procedure is wrong if the path is data-dependent and your single marker run takes a different branch than the attacker's input would (a length check, an if/else on the first character, a try/catch). A clean debugger trace on one marker does not prove the branch an attacker's payload would take is also safe. It is also wrong to stop at the first sink: a value often flows into a safe sink AND an unsafe sink, so the trace must continue to every use of the tainted variable.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - A short unique alphanumeric marker echoed verbatim in the response, from every request-controlled entry point tested one at a time, is the pass condition that proves reflection exists before any payload is chosen.
   - **Disproof:** The procedure is wrong if the marker reflects yet no XSS is reachable - that is a real possibility the method cannot detect: the reflection may sit inside a comment, inside an HTML entity-encoded attribute the app later re-decodes and re-renders on another page, or inside a JSON field that a second script writes into innerHTML on a different route. It is also wrong if the 'static string' control is insufficient, because an app that echoes a per-session value (a CSRF token built from your marker, a request-id cache) will pass step 4 and still tell you nothing about general reflection.
   - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://portswigger.net/web-security/cross-site-scripting/reflected>
@@ -124,25 +124,25 @@
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html> · <https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage>
 - If a DOM source value is URL-encoded before reaching the sink the markup payload cannot survive, making the candidate a false positive.
   - **Disproof:** A non-encoded payload with no percent sequences in the traced value reaches the sink and executes script in the victim's browser.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/dom-based>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/dom-based> · <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html>
 - An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.
   - **Disproof:** This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/contexts> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 - An HttpOnly session cookie removes the cookie-exfiltration chain, so impact must be restated as in-origin actions rather than session theft.
   - **Disproof:** The session cookie lacks HttpOnly and document.cookie returns it inside the injected script, so full session replay is achievable.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
 - A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.
   - **Disproof:** If the payload demonstrably renders and executes in a second, independently authenticated session or in a view reached by another user, then the marker is not self-only and the finding does clear the bar.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/exploiting>
+  - Sources: <https://portswigger.net/web-security/cross-site-scripting> · <https://portswigger.net/web-security/cross-site-scripting/exploiting> · <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
 
 ## False-positive rules (when to reject it)
 
... (truncated)
```

## 2026-10-02 13:38 — 33 diff lines
- items: 70 (supported 70), FP rules 25, chains 1, state mature

```diff
--- xss@current
+++ xss@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE CWE-79 · OWASP A03:2021
-> evidence: 67 items, 67 supported, 25 FP rules, 1 chains
+> evidence: 70 items, 70 supported, 25 FP rules, 1 chains
 > maturity: **mature**
 
 Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.
@@ -38,6 +38,15 @@
 
 ## Techniques (what to change)
 
+- XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "XSS can cause a variety of problems for the end user that range in severity from an annoya".
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/>
+- Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Input validation will not always prevent XSS, especially if you are required to support fr".
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/>
+- Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.
+  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Even if you make a mistake in your validation (such as forgetting one out of 100 input fie".
+  - Sources: <https://cwe.mitre.org/data/definitions/79.html> · <https://owasp.org/www-community/attacks/xss/>
 - Client-side template injection executes when the framework scans rendered content for template expressions and evaluates any it finds.
   - **Disproof:** This is wrong if user input never reaches a template render path, if the framework escapes the value before interpolation, or if the value is inserted as a plain data attribute the engine never evaluates.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html> · <https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection>
@@ -295,4 +304,4 @@
   - Rule: Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
 
 ---
-Full class document: `classes/xss.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
+Full class document: `skills/Web/xss/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id xss`
```
