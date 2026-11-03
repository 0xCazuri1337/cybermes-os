<!-- GENERATED from db/wks.db — do not edit -->
# Cross-Site Scripting

> surface: `client` · CWE: CWE-79 · OWASP: A03:2021
> maturity: **mature** — 114 items, 74 supported, 22 FP rules, 1 chains

Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.

**Aliases:** xss, cross site scripting, stored xss, reflected xss, dom xss

## False-positive rules

- **Hypothesis:** GET /search returns the q parameter unencoded in the HTML body
  - **Invalidated by:** The response was served as application/json and the page inserted it via textContent, so the injected markup was parsed as text and never became nodes
  - **Rule:** Reflection is not execution: confirm the response is parsed as HTML and that the value reaches an execution-capable sink before calling it XSS

- **Hypothesis:** Cookie theft via reflected XSS on an authenticated settings page
  - **Invalidated by:** The session cookie carried HttpOnly, so document.cookie returned nothing — but the script could still read the page's CSRF token and submit the password change with it, which is the real impact
  - **Rule:** Never price XSS as cookie theft until you read the cookie flags; with HttpOnly the finding is in-origin privileged action, which is usually higher impact anyway

- **Hypothesis:** Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.
  - **Invalidated by:** The rule is wrong if the session cookie lacks HttpOnly and document.cookie returns it to injected script, in which case full session replay IS achievable and the original impact claim stands. It is also wrong when the sensitive credential is not the cookie at all - a JWT or API token in localStorage or sessionStorage, or a CSRF token readable from the DOM, is unaffected by HttpOnly. Read the Session Management cheat sheet's own warning before assuming HttpOnly helps: it only protects the confidentiality of that one cookie.
  - **Rule:** Reject a report's 'steals session cookies' impact claim when the session cookie carries the HttpOnly attribute, and restate the impact as in-origin action on behalf of the victim instead.

- **Hypothesis:** Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.
  - **Invalidated by:** The rule is wrong when the policy contains 'unsafe-inline' (or 'unsafe-eval' for eval-style payloads), or when strict-dynamic is present and the injection point runs on a page that already loaded a nonced/hash-trusted script - in both cases a nonce-less injected script is executed anyway and the finding is a full XSS. It is also wrong if the CSP is only a report-only header (Content-Security-Policy-Report-Only), which logs violations without blocking anything.
  - **Rule:** Reject a DOM or reflected XSS candidate when the live page ships a CSP whose script-src carries a nonce or hash source without unsafe-inline and without strict-dynamic, because your injected inline script and inline event handlers cannot execute.

- **Hypothesis:** Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.
  - **Invalidated by:** The rule is wrong if the clobbered or polluted property is later assigned into an HTML-executing sink - a clobbered script src/iframe src whose value navigates to attacker markup, or a polluted property consumed by a template that renders it as HTML - because that is script execution with an injection-only primitive, and it is a real XSS. OWASP's own note that CSP mitigates clobbering of script sources but not already-present code that can be abused for execution is the same distinction seen from the mitigation side.
  - **Rule:** Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.

- **Hypothesis:** Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.
  - **Invalidated by:** The rule is wrong if the encoding is applied for the wrong context - for example only HTML-entity-encoded output dropped inside a JavaScript string, a URL, a CSS value or an unquoted attribute, where &quot; and &#39; do not neutralise a quote delimiter and a ';alert(1)// payload still breaks the string. It is also wrong if the entity is decoded and re-serialised anywhere before rendering (a client-side read of .innerHTML followed by a re-write, or a client-side template that re-interprets the text as HTML), because then the inert text becomes live markup.
  - **Rule:** Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.

- **Hypothesis:** Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.
  - **Invalidated by:** The rule is wrong if the same reflected value reaches an HTML-executing context through any code path: the API is called by a front end that assigns the response into innerHTML or a framework's raw-HTML binding, the endpoint is reachable at the same path with a text/html or JSONP callback content type, or the server renders the stored value into an HTML page for other users. Then the JSON body is only the delivery mechanism, and the finding is a genuine XSS located at the sink.
  - **Rule:** Reject a JSON API endpoint reported as XSS when the response Content-Type is application/json and no client-side code path inserts the reflected value into an HTML document.

- **Hypothesis:** Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.
  - **Invalidated by:** The rule is wrong if the polluted property is consumed by a templating engine or a client-side render that inserts it as markup - a server-side template interpolating the inherited property, or front-end code writing it to innerHTML or a raw-HTML framework binding - because then the pollution is the injection primitive and the result is stored XSS reachable by every user of the app. Equally, if the pollution reaches a code-execution gadget (a template engine option object, a child-process invocation), that is RCE, which is a stronger finding than the XSS report claimed.
  - **Rule:** Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.

- **Hypothesis:** A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.
  - **Invalidated by:** The page's origin exposes no authenticated state, no same-origin privileged endpoints and no tokens reachable from injected script, leaving only a bare popup.
  - **Rule:** A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.

- **Hypothesis:** Reject a sanitizer-bypass XSS claim when the rendered page shows the payload as inert text with the dangerous markup stripped, because a payload that does not become live DOM in the browser is not a bypass.
  - **Invalidated by:** The rule is wrong if a real element with a live event handler or a navigable javascript:/data: URL is present in the rendered DOM and your callback endpoint receives the request - that is a genuine sanitizer bypass and a real XSS, even if the sanitizer appeared to strip <script>. The rule also does not apply where the string is sanitized and then mutated or re-serialised before insertion, since the protection can be voided downstream; check the sink, not the sanitizer call.
  - **Rule:** Reject a sanitizer-bypass XSS claim when the rendered page shows the payload as inert text with the dangerous markup stripped, because a payload that does not become live DOM in the browser is not a bypass.

- **Hypothesis:** Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.
  - **Invalidated by:** The candidate stops being self-XSS the moment a working delivery exists: a crafted URL (or a CSRF-style auto-submitting form) that fires the payload automatically in any other user's browser, on a page an authenticated victim visits. Then it is ordinary reflected XSS and this rejection rule is wrong. Equally, if the 'pasting' step is not required because the value is stored and later rendered to other users, the finding is stored XSS, not self-XSS.
  - **Rule:** Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.

- **Hypothesis:** Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.
  - **Invalidated by:** The candidate is a real DOM XSS if the identical tainted value, in the identical code path, is also passed to an execution-capable sink - innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/string setTimeout - anywhere the same value can reach on another page load, in a fallback branch, or for a different input shape. This rule is also wrong if setAttribute's attribute NAME is derived from the same tainted input (setAttribute(t, v) where t is user-influenced), because OWASP limits setAttribute's safety to hardcoded, innocuous attribute names; an injected name such as onmouseover re-creates an injection sink.
  - **Rule:** Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.

- **Hypothesis:** Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
  - **Invalidated by:** The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.
  - **Rule:** Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.
