# DOM XSS — Reference

Source provenance: `hunt-dom`, `domains/web/xss/topics/dom-xss.md`.

## Core rule
DOM XSS exists only where an attacker-controllable source reaches an execution-capable sink. Reading the source alone is not a finding.

## Dangerous sinks
`document.write`, `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `jQuery.html()`.

## Safe sink
`textContent` (and similar text-only sinks).

## innerHTML note
Assigning to `element.innerHTML` does not run an injected `<script>` on modern browsers; use an element whose event fires on parse failure (e.g., `<img src=x onerror=...>`).

## Sources
URL fragment, query string, postMessage data, window.name, document.referrer, localStorage.

## Validation
- Trace source → sink in code/bundle.
- Confirm execution in browser with a unique canary.
- Enumerate dangerous sinks in the JS bundle.

## Fragment trap: `location.hash` NEVER yields a raw `<` (measured)

A `location.hash` -> `innerHTML` sink looks like textbook DOM XSS in source review. It is almost always not exploitable from a link.

Measured in headless Chromium over CDP (2026-10-04):

```js
// (a) delivered as a link
location = 'https://host/app/#army/<img src=x onerror=alert(7413)>'
location.hash        // -> "#army/%3Cimg%20src=x%20onerror=alert(7413)%3E"

// (b) assigned from script, bypassing URL parsing entirely
location.hash = '#army/<img src=x onerror=alert(7413)>'
location.hash                       // -> ALSO percent-encoded
location.hash.split('/')[1].includes('<')        // -> false
document.querySelectorAll('#board img').length   // -> 0
```

The browser percent-encodes `<`, `>` and spaces when it stores the fragment, whether by navigation or assignment. So `innerHTML` receives literal `%3Cimg...` and renders characters, not an element.

Fragment-decoding checks (grep first):

```js
/decodeURIComponent\s*\(\s*location\.(hash|search)/
```

If that feeds an `innerHTML` sink it IS exploitable. Also check `atob(...)`. Note asymmetry: `URLSearchParams` decodes `location.search`, so a search-based sink is live where a hash-based one is inert.

HTML text injection into a hash sink is not XSS: content spoofing/text injection is ineligible on HackerOne. Do not dress it up as XSS.

## Proving a sink fires: headless Chromium over CDP

When the reporting tool's browser is unavailable (cloud 402, local profile locked), do not quit the user's browser. Drive headless Edge/Chrome directly over CDP with a disposable `--user-data-dir`:

```bash
msedge.exe --headless=new --disable-gpu --no-first-run \
  --remote-debugging-port=9222 --user-data-dir=$TEMP/throwaway about:blank
```

Node 22+ ships a global `WebSocket`, so no dependency is needed. Override `window.alert` after load and re-trigger the sink (e.g., reassign `location.hash`), because navigation replaces the JS context. Evidence is `Runtime.consoleAPICalled` / `Runtime.exceptionThrown` — a screenshot is not proof.
