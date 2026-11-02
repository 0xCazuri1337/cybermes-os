# Request Smuggling / HTTP Desync

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **researching** — 2 items, 2 supported, 1 FP rules, 0 chains

Front-end and back-end disagree about where one request ends, so one request becomes two.

**Aliases:** request smuggling, http desync, cl te, te cl

## Signal

- **Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.**  
  `high_confidence` · score 0.8105 · disproved by: If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Fp Rule

- **A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.**  
  `high_confidence` · score 0.9205 · disproved by: A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>

## Known gaps

Not yet satisfied: `items`, `supported_items`, `fp_rules`, `chain`
