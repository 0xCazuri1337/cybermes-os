# Request Smuggling / HTTP Desync

## Definition

Front-end and back-end disagree about where one request ends, so one request becomes two.

- **CWE:** 444
- **OWASP:** A04:2021
- **Surface:** web
- **Aliases:** ["request smuggling", "http desync", "cl te", "te cl"]

Canonical home for `smuggling`. Rendered from `db/wks.db` by `methodology/scripts/build_taxonomy.py` — edit the rows, not this file.

## Root Cause

Not yet researched.

## Preconditions

Not yet researched.

## Attack Surface

Surface: **web**.

The entry points and enabling conditions for this surface are enumerated under **Preconditions**; the observable signals are under **Detection**.

## Detection

**Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.**

Exploitation of edge appliances commonly begins with a request for a static administrative asset path that a normal client would not fetch. Because the request is a plain GET for a file, filtering and rate limiting rarely treat it as hostile, which is precisely why it survives to the vulnerable handler. Two properties make it useful to a defender: the path is predictable enough to hunt for in logs, and an attacker probing from rotating infrastructure produces a scattered request pattern for one static path, which is anomalous even though each individual request is unremarkable.

*Disproof:* If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.

## Exploitation

Not yet researched.

## Variations

Not yet researched.

## Technology / Framework Considerations

Not yet researched.

## API Considerations

Not yet researched.

## Attack Chains

Not yet researched.

## Real-World Examples

Not yet researched.

## Common False Positives

**A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.**

The observation is a tiny HTML attachment that appears inert to mail and web filters, contains an encoded blob, and reconstructs a payload client-side, which is filed under smuggling because the payload crosses a boundary unseen by the filter. It is a different class. HTML smuggling operates entirely inside one browser and one origin: the sender hid the payload inside image polyglots, called the PNG or GIF files from remote so the HTML stays small, and added dynamic XOR encryption to the payloads hidden inside the image. No intermediary parses two conflicting request framings. HTTP request smuggling is a disagreement between a front-end and back-end HTTP parser over where one request ends and the next begins; a real instance looks like a server whose REST parser incorrectly handles pipelined HTTP requests, which allows successive requests to overwrite the previously parsed HTTP method, URL and body, and is filed as inconsistent interpretation of HTTP requests (CWE-444). The distinguishing test is where the payload boundary is drawn: for HTML smuggling, one request and one response, and the payload materializes in the DOM; for smuggling, two requests where the victim's request is prefixed to or swallowed by the attacker's. Classify on the parser disagreement, not on the payload being hidden.

*Disproof:* A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.

## Validation

Not yet researched.

## Impact

Not yet researched.

## Related Bug Classes

Not yet researched.

## References

- **blog.trailofbits.com** (writeup)
  - <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/>
- **helpnetsecurity.com** (writeup)
  - <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **talosintelligence.com** (vendor_advisory)
  - <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577>
- **unit42.paloaltonetworks.com** (writeup)
  - <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

Every item above is gated on >= 2 distinct publisher hosts (`wks/quality.py`, rule R1). Publisher diversity, not citation count, is what makes these corroborated.
