# History

Append-only. Each entry records WHY the skill changed, not just that it did. Improvement means better hunting behaviour, not more text.

## 2026-10-02 10:30 — 1 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: methodology, items, chain

```diff
(initial generation, 2026-10-02)
```

## 2026-10-02 10:32 — 11 diff lines
- items: 5 (supported 5), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- cors@current
+++ cors@new
@@ -11,7 +11,7 @@
 
 > surface `web` · CWE 942 · OWASP A05:2021
 > evidence: 5 items, 5 supported, 2 FP rules, 0 chains
-> maturity: **researching** — missing: methodology, items, chain
+> maturity: **researching** — missing: items, chain
 
 The cross-origin policy grants a foreign origin more access than intended.
 
```

## 2026-10-02 12:21 — 21 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- cors@current
+++ cors@new
@@ -10,7 +10,7 @@
      python -m wks.skillgen -->
 
 > surface `web` · CWE 942 · OWASP A05:2021
-> evidence: 5 items, 5 supported, 2 FP rules, 0 chains
+> evidence: 6 items, 6 supported, 2 FP rules, 0 chains
 > maturity: **researching** — missing: items, chain
 
 The cross-origin policy grants a foreign origin more access than intended.
@@ -32,6 +32,9 @@
 
 ## Techniques (what to change)
 
+- An Access-Control-Allow-Origin: null allowlist entry is exploitable when any attacker-reachable document can legitimately run in a null origin, because sandboxed iframes and local files send Origin: null and the reflection becomes indistinguishable from a trusted origin.
+  - **Disproof:** The claim is wrong, and the null allowlist is not reachable, if the response never carries Access-Control-Allow-Credentials: true, so a credentialed cross-origin read returns nothing a logged-out caller lacks; no attacker-controlled document can be made to issue requests in a null origin against the target (no upload-and-render path, no PDF or HTML preview, no sandboxed viewer); the server varies its response on something other than Origin so the null response is a generic error page; or the endpoint returns identical bodies for authenticated and anonymous callers. A reflected header with no credentialed read from a null-origin document is a hardening note, not a finding.
+  - Sources: <https://portswigger.net/web-security/cors/> · <https://www.w3.org/TR/cors/>
 - Cross-origin data theft is demonstrated by reading an authenticated response body from a controlled origin with credentials included, not by observing the ACAO header alone.
   - **Disproof:** If the controlled-origin page receives an opaque or empty body while the header is present, the browser enforced the CORS check and no data crossed origins.
   - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
```

## 2026-10-02 13:38 — 8 diff lines
- items: 6 (supported 6), FP rules 2, chains 0, state researching
- still missing: items, chain

```diff
--- cors@current
+++ cors@new
@@ -49,4 +49,4 @@
   - Sources: <https://www.w3.org/TR/cors/> · <https://bishopfox.com/blog/is-cors-obsolete>
 
 ---
-Full class document: `classes/cors.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
+Full class document: `skills/Web/cors/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id cors`
```
