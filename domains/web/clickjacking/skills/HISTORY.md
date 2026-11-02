# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 15:57 — 1 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 16:07 — 8 diff lines
- items: 13 (supported 13), FP rules 2, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -76,4 +76,4 @@
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
 
 ---
-Full class document: `domains/web/clickjacking/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
+Full class document: `domains/web/clickjacking/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
```

## 2026-10-02 19:37 — 97 diff lines
- items: 23 (supported 15), FP rules 5, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 13 items, 13 supported, 2 FP rules, 1 chains
+> evidence: 23 items, 15 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -32,16 +32,16 @@
 
 ## Techniques (what to change)
 
-- Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely.
+- Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Based on the Tools, Techniques, and Procedures employed and some background information we".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
-- If this check passes, the rootkit then copies the injection information into a global variable.
+- If this check passes, the rootkit then copies the injection information into a global variable. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If this check passes, the rootkit then copies the injection information into a global vari".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
-- This ensures that only on every n -th send buffer an injection is attempted.
+- This ensures that only on every n -th send buffer an injection is attempted. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This ensures that only on every n -th send buffer an injection is attempted.".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
-- Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.
+- Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes. _(unverified)_
   - **Disproof:** If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
   - Sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
 - A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.
@@ -51,6 +51,24 @@
   - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
 
+## Tests
+
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_strict_default_src_is_not_a_framing_defence) states the full boundary.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_frame_ancestors_policy_delivered_in_a_meta_element_is_not_a_control) states the full boundary.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
+- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.framability_of_a_static_read_only_page_is_low_severity_not_a_finding) states the full boundary.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
+- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.validation.prove_framing_with_a_real_iframe_and_a_forced_click) states the full boundary.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
+- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedd _(unverified)_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.bypass.sameorigin_only_matches_the_top_level_document) states the full boundary.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
+
 ## Validation bar (how to prove it)
 
 - A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.
@@ -59,15 +77,27 @@
 - A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.
   - **Disproof:** Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
+- The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent.
+  - **Disproof:** If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
 
 ## False-positive rules (when to reject it)
 
 - This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.
   - **Disproof:** Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/kovter-killer-how-to-remediate-the-apt-of-clickjacking/>
+- A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced.
+  - **Disproof:** It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
+- A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection.
+  - **Disproof:** It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
 - Reject a clickjacking finding until it is distinguished from the adjacent behaviour this class also covers. "Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the..." and "A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A clickjacking finding is validated only by a differential browser ren" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
+- An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.
+  - **Disproof:** It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
 
 ## Impact framing
 
@@ -75,5 +105,11 @@
   - **Disproof:** Disproof is a state-change requirement: the framed route takes no state-changing action on a single click, or requires a second factor the click alone cannot satisfy, or the token on the page is not reachable from the framed context. Also disproof: the framed response sets `SameSite` on its session cookie such that the cross-site POST carries no session at all, so there is no authenticated victim to act as. Any of these collapses the impact to nuisance.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
 
+## Defence bypasses
+
+- X-Frame-Options SAMEORIGIN is defeated by an intermediate same-origin frame nested inside an attacker page, because it matches only the top-level document's location, whereas a per-ancestor check inspects every ancestor in the chain.
+  - **Disproof:** It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
+
 ---
 Full class document: `domains/web/clickjacking/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
```

## 2026-10-03 01:46 — 76 diff lines
- items: 24 (supported 19), FP rules 5, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 23 items, 15 supported, 5 FP rules, 1 chains
+> evidence: 24 items, 19 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -34,38 +34,38 @@
 
 - Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Based on the Tools, Techniques, and Procedures employed and some background information we".
-  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
+  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 - If this check passes, the rootkit then copies the injection information into a global variable. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If this check passes, the rootkit then copies the injection information into a global vari".
-  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
+  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 - This ensures that only on every n -th send buffer an injection is attempted. _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This ensures that only on every n -th send buffer an injection is attempted.".
-  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
+  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 - Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes. _(unverified)_
   - **Disproof:** If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
   - Sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
 - A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.
   - **Disproof:** If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
-  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
+  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 - Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.
   - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
 
 ## Tests
 
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_strict_default_src_is_not_a_framing_defence) states the full boundary.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_frame_ancestors_policy_delivered_in_a_meta_element_is_not_a_control) states the full boundary.
   - Sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.framability_of_a_static_read_only_page_is_low_severity_not_a_finding) states the full boundary.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: eat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.validation.prove_framing_with_a_real_iframe_and_a_forced_click) states the full boundary.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: : treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable. Boundary of the rule: It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedd _(unverified)_
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.bypass.sameorigin_only_matches_the_top_level_document) states the full boundary.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
 
@@ -99,9 +99,15 @@
   - **Disproof:** It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
 
+## Evidence requirements
+
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.
+  - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (clickjacking.fp_rule.auto.derived) states the full boundary.
+  - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
+
 ## Impact framing
 
-- The impact of a frameable state-changing page is that a foreign origin can force an authenticated user's action and capture a per-page token, turning one redressed click into privilege escalation.
+- The impact of a frameable state-changing page is that a foreign origin can force an authenticated user's action and capture a per-page token, turning one redressed click into privilege escalation. _(unverified)_
   - **Disproof:** Disproof is a state-change requirement: the framed route takes no state-changing action on a single click, or requires a second factor the click alone cannot satisfy, or the token on the page is not reachable from the framed context. Also disproof: the framed response sets `SameSite` on its session cookie such that the cross-site POST carries no session at all, so there is no authenticated victim to act as. Any of these collapses the impact to nuisance.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
 
```

## 2026-10-03 05:00 — 23 diff lines
- items: 24 (supported 19), FP rules 6, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 24 items, 19 supported, 5 FP rules, 1 chains
+> evidence: 24 items, 19 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -117,5 +117,11 @@
   - **Disproof:** It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
 
+## Rejected before you report
+
+- **The response sets X-Frame-Options but no CSP frame-ancestors, therefore framing protection is incomplete**
+  - Killed by: The legacy header cannot express a per-path allowlist and is the intended control where frame-ancestors is absent; the frame was refused. The pairing of both headers is the normal defensive configuration, not a missing one
+  - Rule: X-Frame-Options without frame-ancestors is the COMMON hardened configuration - frame-ancestors has patchy support, so operators set both. Treat it as a finding only when the framed document actually renders cross-origin
+
 ---
 Full class document: `domains/web/clickjacking/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
```

## 2026-10-04 00:43 — 165 diff lines
- items: 24 (supported 19), FP rules 6, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -20,100 +20,94 @@
 
 ## Prerequisites (do not start without these)
 
-- A web endpoint is clickjacking-exposed only when its responses carry neither an X-Frame-Options header nor a CSP frame-ancestors directive on every state-changing route.
+- A web endpoint is clickjacking-exposed only when its responses carry neither an X-Frame-Options header nor a CSP frame-ancestors directive on every state-changing route.  _(merged 1 duplicate row(s))_
   - **Disproof:** If ANY response on the state-changing route returns a valid `X-Frame-Options: DENY`/`SAMEORIGIN` or a `Content-Security-Policy` containing `frame-ancestors`, the endpoint is not frameable and this claim is false for it. A 200 with either header present, observed on a raw request with no browser involved, disproves it.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 
 ## Recon signals (where to look)
 
-- A response carrying X-Frame-Options but no CSP frame-ancestors is a weak-mitigation signal, not a finding: legacy X-Frame-Options cannot express per-path allowlists and is ignored when frame-ancestors is present.
+- A response carrying X-Frame-Options but no CSP frame-ancestors is a weak-mitigation signal, not a finding: legacy X-Frame-Options cannot express per-path allowlists and is ignored when frame-ancestors is present.  _(merged 1 duplicate row(s))_
   - **Disproof:** If a raw request to the endpoint returns a `Content-Security-Policy` header whose directives include `frame-ancestors` (any value), the response is already in bucket C and the 'legacy-only' signal does not apply. Equally, if a cross-origin iframe load of the endpoint is refused by a current browser, the practical exposure is nil regardless of which headers are present, and the signal is a false lead.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 
 ## Techniques (what to change)
 
-- Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely. _(unverified)_
+- A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.  _(merged 1 duplicate row(s))_
+  - **Disproof:** If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
+  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
+- Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Based on the Tools, Techniques, and Procedures employed and some background information we".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- If this check passes, the rootkit then copies the injection information into a global variable. _(unverified)_
+- Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.  _(merged 1 duplicate row(s))_ _(unverified)_
+  - **Disproof:** If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
+  - Sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
+- Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.  _(merged 1 duplicate row(s))_
+  - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
+- If this check passes, the rootkit then copies the injection information into a global variable.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If this check passes, the rootkit then copies the injection information into a global vari".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- This ensures that only on every n -th send buffer an injection is attempted. _(unverified)_
+- This ensures that only on every n -th send buffer an injection is attempted.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This ensures that only on every n -th send buffer an injection is attempted.".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes. _(unverified)_
-  - **Disproof:** If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
-  - Sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
-- A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.
-  - **Disproof:** If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
-  - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.
-  - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
-  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
 
 ## Tests
 
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_strict_default_src_is_not_a_framing_defence) states the full boundary.
-  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
+- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.bypass.sameorigin_only_matches_the_top_level_document) states the full boundary.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
+- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_frame_ancestors_policy_delivered_in_a_meta_element_is_not_a_control) states the full boundary.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.framability_of_a_static_read_only_page_is_low_severity_not_a_finding) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/> · <https://httpd.apache.org/docs/2.4/mod/mod_headers.html>
+- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
   - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.validation.prove_framing_with_a_real_iframe_and_a_forced_click) states the full boundary.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.bypass.sameorigin_only_matches_the_top_level_document) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
 
 ## Validation bar (how to prove it)
 
-- A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.
+- A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.  _(merged 1 duplicate row(s))_
+  - **Disproof:** Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
+  - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
+- A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.  _(merged 1 duplicate row(s))_
   - **Disproof:** The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://portswigger.net/web-security/clickjacking/>
-- A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.
-  - **Disproof:** Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
-  - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent.
+- The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.
   - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
 
 ## False-positive rules (when to reject it)
 
-- This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.
+- A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.
+  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
+- A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.
+  - Sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
+- An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.  _(merged 1 duplicate row(s))_
+  - **Disproof:** It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
+  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
+- Reject a clickjacking finding until it is distinguished from the adjacent behaviour this class also covers. "Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the..." and "A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A clickjacking finding is validated only by a differential browser ren" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
+  - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
+- This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.  _(merged 1 duplicate row(s))_
   - **Disproof:** Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/kovter-killer-how-to-remediate-the-apt-of-clickjacking/>
-- A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced.
-  - **Disproof:** It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.
-  - Sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
-- A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection.
-  - **Disproof:** It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.
-  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
-- Reject a clickjacking finding until it is distinguished from the adjacent behaviour this class also covers. "Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the..." and "A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.
-  - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A clickjacking finding is validated only by a differential browser ren" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
-  - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
-- An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.
... (truncated)
```

## 2026-10-04 19:46 — 9 diff lines
- items: 24 (supported 19), FP rules 6, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -134,6 +134,3 @@
 > Ordered prerequisites, the validation bar and the false-positive rules below are the authority: this block is the mechanics, those are the standard.
 ---
 Full class document: `domains/web/clickjacking/knowledge/DIGEST.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
-
----
-Runbook: [`HUNT.md`](HUNT.md) — every promoted technique mapped to an executable procedure with the observables to record.
```

## 2026-10-28 14:45 — 30 diff lines
- items: 19 (supported 14), FP rules 6, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 24 items, 19 supported, 6 FP rules, 1 chains
+> evidence: 19 items, 14 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -50,18 +50,6 @@
 - This ensures that only on every n -th send buffer an injection is attempted.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This ensures that only on every n -th send buffer an injection is attempted.".
   - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-
-## Tests
-
-- To decide this case, observe: How to apply it in the field: treat this as the bypass it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.bypass.sameorigin_only_matches_the_top_level_document) states the full boundary.
-  - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
-- To decide this case, observe: How to apply it in the field: treat this as the fp_rule it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 3 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.fp_rule.a_frame_ancestors_policy_delivered_in_a_meta_element_is_not_a_control) states the full boundary.
-  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/> · <https://httpd.apache.org/docs/2.4/mod/mod_headers.html>
-- To decide this case, observe: How to apply it in the field: treat this as the validation it is — a hunter must be able to state the concrete observation that demonstrates it, with a request and response in hand, before the finding is reportable.  _(merged 1 duplicate row(s))_
-  - **Disproof:** This test does not apply where the surrounding behaviour is unobservable -- for example when the response is identical in every case, or when the only evidence is server-side and not reflected to the requester. The originating rule (clickjacking.validation.prove_framing_with_a_real_iframe_and_a_forced_click) states the full boundary.
-  - Sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-28 17:55 — 33 diff lines
- items: 16 (supported 14), FP rules 6, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 19 items, 14 supported, 6 FP rules, 1 chains
+> evidence: 16 items, 14 supported, 6 FP rules, 1 chains
 > maturity: **mature**
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -35,21 +35,12 @@
 - A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.  _(merged 1 duplicate row(s))_
   - **Disproof:** If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
   - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- Based on the Tools, Techniques, and Procedures employed and some background information we cannot publicly disclose, a Russia-based attacker is likely.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "Based on the Tools, Techniques, and Procedures employed and some background information we".
-  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 - Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
   - Sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
 - Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.  _(merged 1 duplicate row(s))_
   - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
-- If this check passes, the rootkit then copies the injection information into a global variable.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "If this check passes, the rootkit then copies the injection information into a global vari".
-  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
-- This ensures that only on every n -th send buffer an injection is attempted.  _(merged 1 duplicate row(s))_ _(unverified)_
-  - **Disproof:** This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "This ensures that only on every n -th send buffer an injection is attempted.".
-  - Sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/>
 
 ## Validation bar (how to prove it)
 
```

## 2026-10-31 06:41 — 38 diff lines
- items: 16 (supported 11), FP rules 5, chains 1, state mature

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 16 items, 14 supported, 6 FP rules, 1 chains
+> evidence: 16 items, 11 supported, 5 FP rules, 1 chains
 > maturity: **mature**
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -38,7 +38,7 @@
 - Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
   - Sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
-- Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.  _(merged 1 duplicate row(s))_
+- Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
   - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
 
@@ -65,7 +65,7 @@
 - An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.  _(merged 1 duplicate row(s))_
   - **Disproof:** It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
   - Sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
-- Reject a clickjacking finding until it is distinguished from the adjacent behaviour this class also covers. "Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the..." and "A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_
+- Reject a clickjacking finding until it is distinguished from the adjacent behaviour this class also covers. "Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the..." and "A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "A clickjacking finding is validated only by a differential browser ren" is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
 - This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.  _(merged 1 duplicate row(s))_
@@ -74,7 +74,7 @@
 
 ## Evidence requirements
 
-- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.  _(merged 1 duplicate row(s))_
+- A convincing observation for this class is: Adjacent behaviour that produces the same observable result: A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.  _(merged 1 duplicate row(s))_ _(unverified)_
   - **Disproof:** Not evidence when the observable cannot be produced at all -- blind, server-side-only, or identical-in-every-case behaviour leaves nothing to show. The originating rule (clickjacking.fp_rule.auto.derived) states the full boundary.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html>
 
```
