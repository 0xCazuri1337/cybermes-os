# Proven recipes — egress-blocked + captcha-gated web hunt

Copied from the BMW Group / MINI authorized hunt (in-scope: *.bmw.de, *.mini.de, *.bmw-motorrad.de). Adapt host/paths per target.

## 1. Browser-as-proxy reach + SSO token injection (authenticated API calls)
Navigate browser to an in-scope page first, then run from console (same origin):
```js
// Inject cross-subdomain SSO token (BMW gcdmToken valid on *.mini.de)
document.cookie = "gcdmToken=<PASTED_TOKEN>; path=/; domain=.mini.de";
const r = await fetch('/de_DE/shop/ls/wishlist/api/v1/wishlists/items?info_level=minimal&limit=1',
  {credentials:'include', headers:{'accept':'application/json','x-caller-name':'wishlist'}});
console.log(r.status, await r.text());
```
- Re-inject after ANY cross-origin navigation (token context evicts).
- Verify with a known-good 200 before assuming auth.

## 2. WAF soft-404 control (disprove ".env 403" false positives)
```bash
curl -s -o /tmp/a -w "%{http_code} %{size_download}\n" https://host/.env
curl -s -o /tmp/b -w "%{http_code} %{size_download}\n" https://host/zzz-nonsense-$RANDOM
cmp -s /tmp/a /tmp/b && echo "SOFT-404 false positive (catch-all)" || echo "differs — investigate"
```
BMW result: `.env` and `.env.backup` → 403 "Access Denied" identical to junk path = WAF pattern block, NOT a real file.

## 3. OAuth redirect_uri validation test (authorize stage)
```js
// Unauthenticated (no session) → foreign redirect_uri
const noauth = await fetch('https://customer.bmwgroup.com/oneid/authorize/?client=miniwebcom&response_type=code&redirect_uri=https://example.com&scope=svds%20vehicle_data', {redirect:'manual', credentials:'omit'});
console.log('no-session status', noauth.status); // 200 (login page) — normal, not a bug
// Authenticated (valid gcdmToken) → foreign redirect_uri
const auth = await fetch('https://customer.bmwgroup.com/oneid/authorize/?client=miniwebcom&response_type=code&redirect_uri=https://example.com&scope=svds%20vehicle_data', {redirect:'manual', credentials:'include'});
console.log('with-session status', auth.status, auth.headers.get('location')); // 403, no Location → allowlist enforced
```

## 4. Wishlist IDOR attempts (all RULED OUT — server enforces session ownership)
```js
// Spoof gcid in body → discarded
POST /de_DE/shop/ls/wishlist/api/v1/wishlists/items
  body: {externalId:'X', externalType:'vehicle', type:'vehicle', origin:'configurator',
         legacyOcpRequestData: JSON.stringify({gcid:'11111111-1111-1111-1111-111111111111'})}
  → 201, stored under SESSION gcid (spoof ignored)
// Fetch by id → 405 (no arbitrary-id read)
// Spoof ?gcid= query → ignored, returns own items
```

## 5. CORS probe
```js
const r = await fetch('/de_DE/shop/ls/wishlist/api/v1/wishlists/items?info_level=minimal&limit=1',
  {credentials:'include', headers:{'accept':'application/json','x-caller-name':'wishlist','origin':'https://example.com'}});
console.log(r.headers.get('access-control-allow-origin'), r.headers.get('access-control-allow-credentials'));
// BMW: both null → no credentialed cross-origin read.
```

## Tooling available in this env
nuclei, dalfox, ffuf, subfinder, amass, httpx, curl, browser. Missing: sqlmap, jwt_tool, interactsh, gobuster, nikto, whatweb.
