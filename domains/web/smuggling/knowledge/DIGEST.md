# Request Smuggling / HTTP Desync

> surface: `web` · CWE: 444 · OWASP: A04:2021
> maturity: **mature** — 17 items, 17 supported, 2 FP rules, 1 chains

Front-end and back-end disagree about where one request ends, so one request becomes two.

**Aliases:** request smuggling, http desync, cl te, te cl

## Signal

- **Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal.**  
  `high_confidence` · score 0.8105 · disproved by: If the appliance never served that asset path, or the same requests occur steadily from stable client infrastructure with no subsequent exploitation, the traffic is ordinary client behaviour.
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Technique

- **In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**  
  `high_confidence` · score 0.8295 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **The grep -q guard prevents duplicate injection if the persistence mechanism is run again.**  
  `high_confidence` · score 0.818 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**  
  `high_confidence` · score 0.802 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**  
  `high_confidence` · score 0.7905 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**  
  `high_confidence` · score 0.7905 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **It basically enables you to hide a payload in plain sight.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
  sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **It basically enables you to hide a payload in plain sight.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It basically enables you to hide a payload in plain sight.".
  sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler device, which processes the malicious packet.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "In this exploit chain, the attacker sends crafted DTLS traffic to a vulnerable NetScaler d".
  sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **The attacker sends an HTTP request to the NetScaler device with a dropper command encoded as Base64 text in the User-Agent string.**  
  `high_confidence` · score 0.7745 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The attacker sends an HTTP request to the NetScaler device with a dropper command encoded ".
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **It does not indicate successful exploitation on patched devices.**  
  `high_confidence` · score 0.763 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **It does not indicate successful exploitation on patched devices.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "It does not indicate successful exploitation on patched devices.".
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
- **The grep -q guard prevents duplicate injection if the persistence mechanism is run again.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "The grep -q guard prevents duplicate injection if the persistence mechanism is run again.".
  sources: <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **They should be seen as general hunting guidance until more is known about the exploitation activity identified by Citrix in their advisory.**  
  `high_confidence` · score 0.747 · disproved by: This is refuted if an authoritative source shows the described behaviour does not occur, does not grant access, or is already prevented by default framework configuration: "They should be seen as general hunting guidance until more is known about the exploitation".
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>

## Fp Rule

- **A roughly 1KB HTML file that downloads an image polyglot and reconstructs an XOR-obfuscated payload in the browser is HTML smuggling, not HTTP request smuggling; smuggling requires two HTTP parsers to disagree on message boundaries.**  
  `high_confidence` · score 0.9205 · disproved by: A replayed pair of requests with conflicting Content-Length and Transfer-Encoding framing makes the back-end serve the second request under the first request's connection, showing two HTTP parsers disagreeing rather than a single client-side reconstruction.
  sources: <https://www.talosintelligence.com/vulnerability_reports/TALOS-2018-0577> · <https://www.helpnetsecurity.com/2024/02/29/bobthesmuggler-open-source-tool-undetectable-payload-delivery/>
- **Reject a smuggling finding until it is distinguished from the adjacent behaviour this class also covers. "Requests to appliance administrative asset paths act as an early reconnaissance fingerprint for exploitation, and the repetition of an otherwise mundane static-path request from changing infrastructure is itself the signal." and "It basically enables you to hide a payload in plain sight." share a surface and a symptom, so a response that matches the first is not evidence for it while the second remains possible.**  
  `high_confidence` · score 0.8655 · disproved by: This rule is wrong if a controlled test shows the two behaviours can never co-occur on the same surface, or if the corpus entry for "It basically enables you to hide a payload in plain sight." is out of date. In that case this class needs its false-positive guidance rewritten rather than deleted.
  sources: <https://blog.trailofbits.com/2026/09/21/saml-a-fractal-of-bad-design/> · <https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/>
