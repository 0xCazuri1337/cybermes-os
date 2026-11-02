# High-Payout XSS Patterns — Reference

Source provenance: `xss-hunter` (H1 reports $10k+).

## Patterns
1. Cache poisoning via HTTP request smuggling (PayPal $20k): desync between front-end proxy and back-end; poison shared JS; bypass CSP via non-CSP endpoint.
2. Attribute breakout in markdown reference filters (GitLab $16k): overly permissive regex allows quotes to break out of HTML attributes.
3. Language-specific attribute injection in diagram renderers (GitLab $13.95k): trust `lang` attribute of `<pre>` during diagram generation.
4. Stored XSS in feature autocomplete/popups.

## Notes
- These are advanced patterns; load only for high-value targets.
- Each requires target-specific adaptation.
- Preserve H1 report numbers as provenance, not severity inflation.

## SVG `data:` to `blob:` URL origin inheritance

Architectural cause: a rich text editor automatically converts `data:` URLs into `blob:` URLs, which inherit the origin of the hosting page rather than having a unique/restricted origin.

H1 Report #1276742 (Shopify) - $5,300.

Payload:

```html
<img src="data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIG9ubG9hZD0iYWxlcnQoZG9jdW1lbnQuZG9tYWluKSI+PC9zdmc+">
```

Bypass: use `blob:` URLs to bypass `data:` URL restrictions and inherit page origin.

## Chains & Compositions (Senior Hunting)

XSS as standalone finding pays Low-Medium on mature programs. Real payouts cluster around chains converting JS execution into ATO, mass-victim impact, CSP bypass, or token exfil.

1. Reflected XSS + cache poisoning -> persistent stored XSS at CDN scale.
2. Self-XSS + CSRF trigger -> effective stored XSS -> ATO.
3. DOM XSS on /signin or /oauth callback -> fragment token capture -> ATO.
4. SVG upload XSS + CSP bypass -> JS execution on trusted origin -> cookie/token theft.
5. postMessage XSS + origin check bypass -> cross-origin token exfil -> ATO.
6. Markdown/wiki XSS + privileged viewer -> cross-privilege stored XSS.

Operator pattern: when XSS confirmed, ask what state-changing endpoint or token store the JS can access. Chain payout is 5-20x standalone. Discipline gate: do not file XSS as Critical without demonstrating terminal impact.

Cross-references: hunt-cache-poison (Chain 1), hunt-csrf (Chain 2), hunt-oauth (Chains 3,5), hunt-file-upload/hunt-xxe (Chain 4), hunt-ato (terminal impact).
