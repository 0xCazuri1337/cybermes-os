# DOM Clobbering / postMessage / Service Worker / CSS Exfil — Reference

Source provenance: `hunt-dom`.

## DOM Clobbering
- HTML markup injection (no `<script>`) overwrites JS globals like `window.config` or shadows `document.getElementById`.
- App later treats that value as URL/code → sink fires under markup-only injection.

## postMessage hijacking
- A `message` handler that trusts `event.data` without validating `event.origin` lets an attacker iframe/opener drive privileged actions or feed a sink.
- No XSS needed for cross-origin token theft.

## Service worker abuse
- Register a same-origin SW script (via upload/open-redirect/path) using stored XSS → intercept all in-scope `fetch` → persistent credential capture.
- Prerequisites: arbitrary-JS hosting on origin + XSS to register worker.

## CSS exfiltration
- Attribute-value selectors (`input[value^="a"]`) leak CSRF token/API key/nonce char-by-char to OOB host with zero JS.
- d0nut research: sequential `@import` recursion drops per-char-position constraint.

## Named research provenance
- Gareth Heyes / PortSwigger DOM clobbering + DOM-Invader.
- Michał Bentkowski DOMPurify clobbering bypasses.
- jQuery `htmlPrefilter` XSS (CVE-2020-11022 / CVE-2020-11023, jQuery < 3.5.0).
- d0nut CSS exfiltration.

Cite only what you reproduce; research is for technique provenance, not severity inflation.
