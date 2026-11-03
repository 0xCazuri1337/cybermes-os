<!-- GENERATED from db/wks.db — do not edit -->
# Clickjacking / UI Redressing

> surface: `client` · CWE: 1021 · OWASP: A05:2021
> maturity: **mature** — 16 items, 11 supported, 5 FP rules, 1 chains

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
  sources: <https://security.googleblog.com/2011/05/website-security-for-webmasters.html> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>

## Validation

- **A clickjacking finding is validated only by a differential browser render showing a cross-origin frame actually loaded and a decoy click landing on a framed state-changing control, not by the absence of a frame-protective header.**  
  `high_confidence` · score 0.9025 · disproved by: The validation fails, and there is no clickjacking finding, if the framed document never paints in the cross-origin parent; the parent receives a frame-busting navigation and the framed content is replaced; the click at the decoy coordinates is dispatched to the parent page rather than the frame (an overlay that is not actually over the control); the state change requires a second factor or a re-authentication step the attacker cannot supply; or replaying the framed request without a real click produces the same state change, which means the outcome was a CSRF, not UI redress. Record the click dispatch target, not just the missing header.
  sources: <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> · <https://portswigger.net/web-security/clickjacking/>
- **The convincing clickjacking evidence is a PoC page that frames the target in an attacker-controlled document and demonstrates that a user interaction intended for the attacker's content lands on the framed target, which proves the UI is being redressed rather than merely that a header is absent.**  
  `high_confidence` · score 0.893 · disproved by: If the framed resource refuses to load in the nested context because the ancestor check aborts the load, or the target requires a fresh interaction the attacker cannot borrow, the redressing claim collapses and only a missing-header hardening note remains; a bare 200 response to a HEAD or OPTIONS probe proves nothing about framing.
  sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>
- **A clickjacking finding is only validated when two independent observations agree: the raw header block lacks both frame protections, and a real cross-origin iframe load of the page is refused rather than rendered.**  
  `high_confidence` · score 0.8715 · disproved by: Disproof is any one of: a raw response on the target route that carries `X-Frame-Options` or a `Content-Security-Policy` containing `frame-ancestors`; or a cross-origin iframe load that is refused by a current browser; or a frame that renders but exposes no state-changing control, in which case there is nothing to redress and the finding does not stand.
  sources: <https://blog.cloudflare.com/custom-headers-for-pages/> · <https://github.blog/engineering/platform-security/githubs-csp-journey/>

## Fp Rule

- **This LOOKS like clickjacking (an iframe embeds an authenticated page) but is actually a benign same-origin embed, separated by the frame's document being same-origin with the embedding page.**  
  `high_confidence` · score 0.874 · disproved by: Disproof of the FP verdict: the framed document's origin differs from the embedder's (different host, or different scheme/port), or the framed document can reach into the parent document. Either observation makes the embed cross-origin and the finding real, so this is not a same-origin benign embed. Conversely, a strictly same-origin frame with no parent-DOM reach is confirmed benign.
  sources: <https://github.blog/engineering/platform-security/githubs-csp-journey/> · <https://www.crowdstrike.com/blog/kovter-killer-how-to-remediate-the-apt-of-clickjacking/>
- **A frame-ancestors directive that appears in a meta element rather than a response header is not a defence, because the directive must be ignored in a policy defined via meta, so a scanner that parses the HTML and finds it has found nothing enforced.**  
  `high_confidence` · score 0.8655 · disproved by: It IS enforced when the same directive is also present in a real Content-Security-Policy response header, which takes precedence; it is NOT enforced when the meta-tag form is the only place it appears, in which case the page remains framable from any origin and the finding stands. The related server-side gap is that a protection header added only on success responses is missing from error and redirect responses.
  sources: <https://httpd.apache.org/docs/2.4/mod/mod_headers.html> · <https://www.w3.org/TR/CSP2/>
- **An embeddable page is only a reportable clickjacking finding when the framed page exposes a state-changing or authenticating interaction an attacker would want to borrow; a framed page with no actionable controls is at most a low-severity hardening note.**  
  `high_confidence` · score 0.8655 · disproved by: It IS reportable when the framed page renders a delete, transfer, approval, or settings control reachable by the forced click; it is NOT when the framed resource is a public read-only view with no interactive elements, since nothing of value can be redressed and the missing control header carries no exploitation path.
  sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>
- **A Content-Security-Policy that defines default-src 'none' but omits frame-ancestors does not prevent framing, because frame-ancestors does not fall back to the default sources, so a hunter cannot treat a strict-looking policy as clickjacking protection.**  
  `high_confidence` · score 0.838 · disproved by: It IS protection when frame-ancestors or an equivalent X-Frame-Options value is actually present and non-permissive; it is NOT when the policy relies on default-src or frame-src alone, since the spec states explicitly that an absent frame-ancestors leaves the resource framable from anywhere.
  sources: <https://tomcat.apache.org/tomcat-9.0-doc/config/filter.html> · <https://www.w3.org/TR/CSP2/>

## Bypass

- **X-Frame-Options SAMEORIGIN is defeated by an intermediate same-origin frame nested inside an attacker page, because it matches only the top-level document's location, whereas a per-ancestor check inspects every ancestor in the chain.**  
  `high_confidence` · score 0.838 · disproved by: It is not defeated when the top-level document itself is the attacker origin, because the match then fails at the first ancestor; it IS defeated when the target can be embedded by one of its own pages that in turn can be framed cross-origin, since every-ancestor checking is what closes that gap.
  sources: <https://nginx.org/en/docs/http/ngx_http_headers_module.html> · <https://www.w3.org/TR/CSP2/>

## False-positive rules

- **Hypothesis:** The response sets X-Frame-Options but no CSP frame-ancestors, therefore framing protection is incomplete
  - **Invalidated by:** The legacy header cannot express a per-path allowlist and is the intended control where frame-ancestors is absent; the frame was refused. The pairing of both headers is the normal defensive configuration, not a missing one
  - **Rule:** X-Frame-Options without frame-ancestors is the COMMON hardened configuration - frame-ancestors has patchy support, so operators set both. Treat it as a finding only when the framed document actually renders cross-origin
