# Bot-Wall Vendor Indicators

Cookie / header fingerprints that tell you which bot-mitigation vendor is in
front of a target. Seen in the terminal `curl -sI` response or
`browser_console` of `document.cookie`.

## Kasada
- Cookies: `KP_UIDz`, `KP_UIDz-ssn`, `x-kpsdk-ct`, `x-kpsdk-r`, `x-kpsdk-c`, `x-kpsdk-h`, `x-kpsdk-fc`
- Headers (response): `x-kpsdk-ct`, `x-kpsdk-r`, `x-kpsdk-c`
- Akamai alias often present: `akaalb_<site>_<ALB>` cookie, `prd-kasada` in alias
- Behavior: serves a JS proof-of-work; plain curl gets `429`/`503`. Browser
  solves it. Static `/_next/static/*` and other asset paths are ALSO gated.

## Akamai (Bot Manager)
- Cookies: `bm_so`, `bm_lso`, `ak_bm_*` (session tab id sometimes in sessionStorage as `ak_bm_tab_id`)
- Headers: `akamai-request-bc`, `akamai-grn`, `akamaighost`
- Behavior: `429`/`403` on curl; browser with valid `_abck`/sensor data passes.

## PerimeterX / HUMAN
- Cookies: `_px`, `pxsid`, `pxvid`, `pxhd`, `pxorc`
- Header: `x-px-authorization` (client)
- Behavior: inline script injects sensor; curl blocked.

## Cloudflare Bot Management
- Cookies: `cf_clearance`, `__cf_bm`, `cf_chl_` (challenge)
- Header: `cf-ray`, `cf-request-id`
- Behavior: `403`/challenge page to curl; browser solves JS challenge.

## General tell
- Terminal `curl` returns `429`/`503`/`403` but the SAME URL loads `200` with
  full DOM in the browser tool → bot wall, not a hard IP/host block.
- Slow/rate-limited responses to scripted traffic even after a successful load
  = throttling; space requests (200ms+) and prefer the browser context.

## What this means for recon
If the bot wall is **path-based** (gates `/_next/static/*`, `/static/spa/*`),
you CANNOT read the client bundles to find endpoints. Fall back to:
- SSR route maps in the rendered HTML / `__NEXT_DATA__`
- Gateway path brute (see enumeration-recipes.md) reading structured 401/403 bodies
- Internal hostnames leaked in loaders / source maps
