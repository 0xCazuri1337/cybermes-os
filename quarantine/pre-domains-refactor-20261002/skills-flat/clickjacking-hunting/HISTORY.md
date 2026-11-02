# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: methodology, items, fp_rules, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 7 (supported 7), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -11,7 +11,7 @@
 
 > surface `client` · CWE 1021 · OWASP A05:2021
 > evidence: 7 items, 7 supported, 1 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, fp_rules, chain
+> maturity: **researching** — missing: items, fp_rules, chain
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
 
```

## 2026-10-02 12:21 — 27 diff lines
- items: 9 (supported 9), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `client` · CWE 1021 · OWASP A05:2021
-> evidence: 7 items, 7 supported, 1 FP rules, 0 chains
+> evidence: 9 items, 9 supported, 1 FP rules, 0 chains
 > maturity: **researching** — missing: items, fp_rules, chain
 
 A foreign page can frame and overlay the target so the user's click means something they did not intend.
@@ -38,9 +38,15 @@
 - A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.
   - **Disproof:** If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
   - Sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
+- Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.
+  - **Disproof:** The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>
 
 ## Validation bar (how to prove it)
 
+- A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.
+  - **Disproof:** The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
+  - Sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://portswigger.net/web-security/clickjacking/>
 - A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.
   - **Disproof:** Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>
```

## 2026-10-02 13:38 — 8 diff lines
- items: 9 (supported 9), FP rules 1, chains 0, state researching
- still missing: items, fp_rules, chain

```diff
--- clickjacking@current
+++ clickjacking@new
@@ -64,4 +64,4 @@
   - Sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
 
 ---
-Full class document: `classes/clickjacking.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
+Full class document: `skills/Web/clickjacking/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id clickjacking`
```
