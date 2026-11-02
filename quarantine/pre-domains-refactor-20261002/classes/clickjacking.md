# Clickjacking / UI Redressing

> surface: `client` · CWE: 1021 · OWASP: A05:2021
> maturity: **researching** — 9 items, 9 supported, 1 FP rules, 0 chains

A foreign page can frame and overlay the target so the user's click means something they did not intend.

**Aliases:** clickjacking, ui redress, frame embedding

## Prerequisite

- **A web endpoint is clickjacking-exposed only when its responses carry neither an X-Frame-Options header nor a CSP frame-ancestors directive on every state-changing route.**  
  `high_confidence` · score 0.954 · disproved by: If ANY response on the state-changing route returns a valid `X-Frame-Options: DENY`/`SAMEORIGIN` or a `Content-Security-Policy` containing `frame-ancestors`, the endpoint is not frameable and this claim is false for it. A 200 with either header present, observed on a raw request with no browser involved, disproves it.
  sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>

## Signal

- **A response carrying X-Frame-Options but no CSP frame-ancestors is a weak-mitigation signal, not a finding: legacy X-Frame-Options cannot express per-path allowlists and is ignored when frame-ancestors is present.**  
  `high_confidence` · score 0.863 · disproved by: If a raw request to the endpoint returns a `Content-Security-Policy` header whose directives include `frame-ancestors` (any value), the response is already in bucket C and the 'legacy-only' signal does not apply. Equally, if a cross-origin iframe load of the endpoint is refused by a current browser, the practical exposure is nil regardless of which headers are present, and the signal is a false lead.
  sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>

## Technique

- **A click-redress that does not need a full overlay works by leaving an HTML tag unclosed, so the victim's click on the visible control is parsed as a submit of an attacker-controlled form.**  
  `high_confidence` · score 0.9265 · disproved by: If the returned HTML has the injected attribute and tag balanced by the application's own sanitiser, so that no injected element becomes an ancestor of the page's real form, the technique does not work. Concretely: replay the payload and confirm the attacker `action` is not an ancestor-form target and that clicking the visible control submits to the application's own endpoint, with no request to the attacker's host.
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>
- **Click-redress at scale is delivered by injecting a framed or scripted payload into HTTP responses in transit, so the framing decision is made by the victim's browser against attacker-chosen bytes.**  
  `high_confidence` · score 0.863 · disproved by: If the responses served to the victim contain no attacker-controlled iframe or script reference - verified by diffing the served HTML against the application's own template output across repeated fetches, with no variance - then nothing was injected in transit and this technique is not in play. A 200 whose body hash is stable and contains only same-origin subresources disproves it.
  sources: <https://security.googleblog.com/2008/02/all-your-iframe-are-point-to-us.html> · <https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/>
- **Framing a login, password-reset or payment-confirmation page is the clickjacking case that causes loss, because the frame-buster, frame-ancestors and SameSite defences are built for embedded-page redress and the real impact comes from the user's action completing inside the active session.**  
  `high_confidence` · score 0.8355 · disproved by: The claim is wrong, and the framing is not a clickjacking finding, if the framed page performs no state change on click (a pure read or search page); the sensitive action requires re-authentication or a second factor that cannot be satisfied by the single overlaid click; the response denies framing outright through X-Frame-Options or a frame-ancestors directive that excludes the testing origin, which makes the overlay impossible; or the frame is same-origin with the attacker page, which is a scripting bug, not UI redress. Name the state change in the report or the item is a hardening note.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://securelist.com/vulnerabilities-and-exploits-in-q2-2026/121091/>

## Validation

- **A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.**  
  `high_confidence` · score 0.9025 · disproved by: The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://portswigger.net/web-security/clickjacking/>
- **A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.**  
  `high_confidence` · score 0.8715 · disproved by: Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
  sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>

## Fp Rule

- **This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.**  
  `high_confidence` · score 0.874 · disproved by: Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.
  sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/kovter-killer-how-to-remediate-the-apt-of-clickjacking/>

## Impact

- **The impact of a frameable state-changing page is that a foreign origin can force an authenticated user's action and capture a per-page token, turning one redressed click into privilege escalation.**  
  `high_confidence` · score 0.899 · disproved by: Disproof is a state-change requirement: the framed route takes no state-changing action on a single click, or requires a second factor the click alone cannot satisfy, or the token on the page is not reachable from the framed context. Also disproof: the framed response sets `SameSite` on its session cookie such that the cross-site POST carries no session at all, so there is no authenticated victim to act as. Any of these collapses the impact to nuisance.
  sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-post-csp-journey/>

## Known gaps

Not yet satisfied: `items`, `fp_rules`, `chain`
