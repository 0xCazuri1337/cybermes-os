---
name: smuggling-hunting
description: Use when hunting Request Smuggling / HTTP Desync in a web target. Ordered prerequisites, signals, techniques, validation bar and false-positive rules.
---

# Request Smuggling / HTTP Desync — hunting skill

<!-- GENERATED from db/wks.db by wks/skillgen.py. DO NOT HAND-EDIT.
     Edit the rows (or ingest better research) and re-run:
     python -m wks.skillgen -->

> surface `web` · CWE 444 · OWASP A04:2021
> evidence: 2 items, 2 supported, 1 FP rules, 0 chains
> maturity: **researching** — missing: items, supported_items, fp_rules, chain

Front-end and back-end disagree about where one request ends, so one request becomes two.

**Also called:** request smuggling, http desync, cl te, te cl


## Recon signals (where to look)

- Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.
  - **Disproof:** If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
  - Sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## False-positive rules (when to reject it)

- A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.
  - **Disproof:** A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.
  - Sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>

---
Full class document: `skills/Web/smuggling/EVIDENCE.md` · retrieve more with `python -m wks.cli search "<query>" --class-id smuggling`
