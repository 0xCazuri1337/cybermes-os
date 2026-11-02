---
name: file-upload
description: "Canonical file-upload capability: RCE via webshell, XSS via SVG/HTML, SSRF via XXE in DOCX, path traversal via filename, ImageMagick/FFmpeg/headless-Chrome SSRF, archive extraction attacks, and webshell-activity threat hunting. Consolidates 2 sub-skills: hunt-file-upload, hunting-for-webshell-activity. Use when hunting or validating file-upload-related vulnerabilities."
sources: consolidated
report_count: 5
---

# FILE-UPLOAD — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for file-upload vulnerability testing and webshell-activity threat hunting. It consolidates 2 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Discover file upload endpoints (avatar, attachment, import/export, profile picture, document processors).
- Bypass extension/MIME/magic-byte validation to achieve RCE, stored XSS, SSRF, or path traversal.
- Validate actual code execution (whoami output), XSS firing, SSRF callback, or traversal impact.
- Hunt deployed web shells (T1505.003) via process/network/log telemetry on internet-facing servers.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- File upload features: `/upload`, `/avatar`, `/profile-picture`, `/attachment`, `/import`, `/export`, `/generate-pdf`, `/screenshot`, `/report`.
- Bypass techniques: double extension, null byte, case variants, MIME spoof, magic-byte prefix, polyglot, SVG/HTML XSS, XXE in DOCX, ZIP slip, filename injection, `.htaccess`/`web.config` handler re-enablement.
- Image/AV processors: ImageMagick, FFmpeg, libwebp, headless Chrome/PDF generators.
- Archive extraction: ZIP/TAR slip, symlink attacks.
- Webshell threat hunting: file creation in web dirs, suspicious child-process spawning, anomalous HTTP request patterns.

Out of scope (hand off):
- Pure XSS without upload vector -> `xss` capability.
- Pure SSRF without upload/processing vector -> `ssrf` capability.
- XXE outside upload/parsing context -> `xxe` capability.
- Command injection not via upload -> `command-injection` capability.
- RCE validation beyond upload -> `command-injection` capability.

## 3. Invocation and routing

Use this capability when:
- A target exposes any upload, avatar, attachment, import/export, or document-processing endpoint.
- You need to test whether an uploaded file can be served/executed/parsed with attacker control.
- You are assessing image/video/PDF processors for SSRF/file-read.
- You are hunting for deployed web shells after compromise or EDR/SIEM alerts.

Routing notes:
- Start with `references/hunt-file-upload.md` for hunting methodology, bypass tables, and payload suites.
- Use `references/hunting-for-webshell-activity.md` for threat-hunting workflow, scenarios, and output format.
- Use `references/hunting-for-webshell-activity-api-reference.md` for Splunk/KQL/Sigma detection queries and process-tree indicators.
- Webshell hunt report template: `references/hunting-for-webshell-activity-template.md` (source: `hunting-for-webshell-activity` assets/template.md).
- Webshell hunt standards (MITRE/data sources): `references/hunting-for-webshell-activity-standards.md` (source: `hunting-for-webshell-activity` standards.md).
- Webshell hunt detailed workflow (SPL/KQL phases): `references/hunting-for-webshell-activity-workflows.md` (source: `hunting-for-webshell-activity` workflows.md).
- Webshell detection tooling: `hunting-for-webshell-activity/scripts/agent.py` (process/access/file-event hunter) and `hunting-for-webshell-activity/scripts/process.py` (Sysmon process/file-event detector). Both are defensive detection scripts (read logs only; no payload generation).
- Chain to `command-injection`, `xxe`, `xss`, `ssrf` for deeper exploitation.

## 4. Inputs and outputs

Inputs:
- Target base URLs, upload endpoints, and request templates.
- Session cookies/authentication material for authenticated uploads.
- Optional: Burp Suite project, browser automation, attacker-controlled origin/host (COLLAB_HOST), wordlists, OOB endpoint.

Outputs:
- Confirmed or refuted file-upload findings with execution/proof.
- Bypass matrix (technique vs server response).
- Webshell hunt results: Hunt ID, technique, host, evidence, risk level, confidence, recommended action.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include upload endpoints and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Do not access other users' data beyond proof of control.
- Host PoC/payloads only on attacker infrastructure you control.
- Document any out-of-scope endpoint discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Enumerate upload surfaces: `/upload`, `/avatar`, `/profile-picture`, `/attachment`, `/import`, `/export`, `/generate-pdf`, `/screenshot`, `/report`, mobile/SPA endpoints.
2. Identify accepted content types, size limits, extension allowlists, and storage location (same origin vs CDN).
3. Determine whether uploaded files are served directly (URL returned) and with what Content-Type.
4. Identify processing pipelines: image resize, thumbnail, EXIF strip, video transcode, PDF generation, archive extraction.
5. Fingerprint framework/gateway and web server (PHP/JSP/ASPX/Tomcat/IIS/nginx).
6. For webshell hunting: identify internet-facing web servers, EDR/SIEM coverage, log sources.

See `references/hunt-file-upload.md` (Detection) and `references/hunting-for-webshell-activity.md` (Prerequisites).

## 7. Detection methodology

Core detection flow:
1. Probe upload endpoint with a benign file; record response, returned URL, stored filename, and served Content-Type.
2. Test extension bypasses: `shell.php.jpg`, `shell.pHp`, `shell.php5`, `shell.phtml`, `shell.php%00.jpg`, `shell.jpg.php`.
3. Test MIME spoof: `.php` body with `Content-Type: image/jpeg`.
4. Test magic-byte prefix: prepend `GIF89a;` to PHP code; validate whether server checks only header.
5. Test polyglot: file valid as both image and script.
6. Test SVG/HTML XSS: upload `<svg><script>alert(document.domain)</script></svg>` and view via returned URL.
7. Test XXE in DOCX: embed external entity in Office XML inside ZIP.
8. Test ZIP slip: archive with `../../../` paths; check extraction location.
9. Test filename injection: `; rm -rf /` or path traversal in filename.
10. Test ImageMagick/FFmpeg SSRF: upload MVG/SVG/m3u8/concat payloads; monitor OOB.
11. Test headless Chrome SSRF: submit HTML with iframe/CSS import to PDF/screenshot endpoints.
12. Validate each candidate with a second independent request/account; mark refuted if not proven.
13. For webshell hunting: formulate hypothesis, identify data sources, run detection queries, analyze, validate, correlate, report.

References by phase:
- Hunting: `references/hunt-file-upload.md`.
- Webshell hunting: `references/hunting-for-webshell-activity.md`.
- Detection queries: `references/hunting-for-webshell-activity-api-reference.md`.

## 8. Technique selection

Select techniques by observed behavior:
- Server trusts Content-Type -> MIME spoof.
- Server checks magic bytes only -> magic-byte prefix / polyglot.
- Server checks last extension -> double extension / case variants.
- Server checks first extension -> `shell.jpg.php`.
- Files served same-origin without sanitization -> SVG/HTML stored XSS.
- Office/ZIP/XML parsed -> XXE in DOCX.
- Archive extraction without path validation -> ZIP slip / symlink.
- Image processing (ImageMagick) -> MVG/SVG SSRF (ImageTragick).
- Video processing (FFmpeg) -> HLS/concat SSRF.
- PDF/screenshot generation (headless Chrome) -> HTML/CSS/iframe SSRF or local file read.
- Post-compromise IR -> webshell hunt via process trees and log patterns.

## 9. Execution steps

1. Establish baseline upload with a benign file; record all responses and returned URLs.
2. Replay with one controlled change at a time (extension, MIME, magic bytes, filename); record status, headers, body.
3. Use the bypass table to choose the correct technique; do not guess.
4. For RCE: upload shell, request via direct URL, confirm `whoami` output.
5. For XSS: upload SVG/HTML, open returned URL in browser, confirm popup/cookie exfil.
6. For SSRF: upload processing payload, monitor OOB callback / internal metadata.
7. For traversal: upload archive, verify file written outside intended directory.
8. For webshell hunt: run Splunk/KQL/Sigma queries; correlate process trees and log patterns.
9. Confirm exploitability with a clean reproduction.
10. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite (Repeater, Intruder, Comparer).
- Discovery: ffuf, httpx, dirsearch, KiteRunner.
- Automation: Python requests/httpx, curl, jq.
- Webshell payloads: evilarc, custom ZIP/TAR generators.
- Detection: CrowdStrike Falcon, MDE, Splunk, Elastic, Sysmon, Velociraptor, Sigma.
- Evidence: screenshots, saved requests/responses, canary values, OOB interactions, log entries.
- Detection agent: `hunting-for-webshell-activity/scripts/agent.py` and `hunting-for-webshell-activity/scripts/process.py` (defensive log analysis) plus `references/hunting-for-webshell-activity-standards.md` and `references/hunting-for-webshell-activity-workflows.md`.

See `references/hunt-file-upload.md` (ImageMagick/FFmpeg/Chrome/Archive sections) and `references/hunting-for-webshell-activity-api-reference.md`.

## 11. Payloads and test cases

Representative test cases (adapt to target):

Bypass table:
| Attack | How | Prevention |
|---|---|---|
| Extension bypass | `shell.php.jpg`, `shell.pHp`, `shell.php5` | Allowlist + extract final extension |
| Null byte | `shell.php%00.jpg` | Sanitize null bytes |
| Double extension | `shell.jpg.php` | Only allow single extension |
| MIME spoof | Content-Type: image/jpeg with .php body | Validate magic bytes, not MIME header |
| Magic bytes prefix | Prepend `GIF89a;` to PHP code | Parse whole file, not just header |
| Polyglot | Valid as JPEG and PHP | Process as image lib, reject if invalid |
| SVG JavaScript | `<svg onload="...">` | Sanitize SVG or disallow entirely |
| XXE in DOCX | Malicious XML in Office ZIP | Disable external entities |
| ZIP slip | `../../../etc/passwd` in archive | Validate extracted paths |
| Filename injection | `; rm -rf /` in filename | Sanitize + use UUID names |

Magic bytes:
| Type | Hex |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47 0D 0A 1A 0A` |
| GIF | `47 49 46 38` |
| PDF | `25 50 44 46` |
| ZIP/DOCX/XLSX | `50 4B 03 04` |

Stored XSS via SVG:
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

ImageMagick MVG SSRF:
```text
push graphic-context
viewbox 0 0 640 480
fill 'url(http://169.254.169.254/latest/meta-data/iam/security-credentials/)'
pop graphic-context
```

FFmpeg HLS SSRF:
```text
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
http://169.254.169.254/latest/meta-data/iam/security-credentials/
#EXT-X-ENDLIST
```

Headless Chrome SSRF:
```html
<html><body><iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" width="1000" height="1000"></iframe></body></html>
```

ZIP slip:
```bash
python3 evilarc.py shell.php -o unix -p "../../../var/www/html/" -d 5 -f /tmp/zipslip.zip
```

Webshell hunt output format:
```
Hunt ID: TH-HUNTIN-[DATE]-[SEQ]
Technique: T1505.003
Host: [Hostname]
User: [Account context]
Evidence: [Log entries, process trees, network data]
Risk Level: [Critical/High/Medium/Low]
Confidence: [High/Medium/Low]
Recommended Action: [Containment, investigation, monitoring]
```

Framework and variant details live in the corresponding references.

## 12. Evidence

Each finding must include:
- Exact request and response (raw HTTP or browser network capture).
- Authentication context and account/role used.
- Endpoint tested and technique applied.
- For RCE: uploaded filename, served URL, and command output (whoami).
- For XSS: browser popup/screenshot or cookie exfil proof.
- For SSRF: OOB callback or internal metadata content.
- For traversal: extracted file path and content proof.
- For webshell hunt: log entries, process trees, network data, Sigma/SPL/KQL queries used.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce RCE with the actual `whoami` round-trip from the uploaded shell.
- Reproduce XSS with popup firing in a victim browser, not just file existence.
- Reproduce SSRF with OOB callback or internal data read.
- Reproduce traversal with verified file write outside intended directory.
- Validate with a second account/endpoint where applicable.
- For webshell hunt: validate true positives vs false positives via contextual analysis.
- Mark as refuted if upload succeeds but file is never served/executed/parsed.

## 14. False-positive rejection

Reject or downgrade when:
- File uploaded but never served, executed, or parsed (write-only blob).
- Extension bypass succeeds but server renames/neutralizes the file.
- Magic-byte check actually parses the whole file and rejects polyglot.
- SVG/HTML is served with `Content-Disposition: attachment` or sandboxed.
- XXE parser has external entities disabled.
- Archive extraction validates paths and blocks traversal.
- SSRF payload uploaded but processor does not fetch remote URLs.
- Webshell alert is a legitimate admin tool or deployment artifact.
- Response differences are due to caching, localization, or benign metadata.

## 15. Impact

Impact guidance:
- Critical: RCE via uploaded webshell; archive traversal to overwrite system files; cloud metadata SSRF leading to credential theft.
- High: stored XSS on same origin leading to ATO; XXE file read of secrets/config; ImageMagick/FFmpeg SSRF to internal services.
- Medium: path traversal limited to non-sensitive files; PDF generator local file read; webshell presence (persistence).
- Low: upload of disallowed type without execution; information disclosure via metadata.
- Informational: upload accepted but fully neutralized by storage/processing.

Always tie impact to business risk and data scope; avoid severity inflation from upload acceptance alone.

## 16. Reporting

Report template:
- Summary: endpoint, vulnerability type, technique, impact.
- Scope/authorization: test account, test window, attacker origin.
- Steps to reproduce: numbered, minimal; include payload and served URL.
- Proof of concept: request/response, screenshot/console/OOB hit, command output.
- Bypass matrix and technique class.
- Impact: business and data scope.
- Remediation: strict extension allowlist (final extension), magic-byte validation of whole file, random UUID filenames, store outside web root or on separate domain/CDN, disable script execution in upload dir, disable external entities, validate archive paths, sandbox processors, patch ImageMagick/FFmpeg/libwebp, run processors with least privilege.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- No test account -> request credentials or scope clarification.
- WAF/gateway blocks payloads -> try encoding, content-type confusion, version downgrade.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows.
- Upload succeeds but no execution -> try alternate extensions, handlers, or storage paths.
- Processor does not trigger -> test different file types and endpoints.
- Webshell hunt inconclusive -> expand data sources, refine queries, check additional hosts.
- Inconclusive authorization/origin result -> repeat with fresh sessions and diff responses.

## 18. References

All sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-file-upload.md` | `hunt-file-upload` | Hunting methodology, bypass tables, payload suites |
| `references/hunting-for-webshell-activity.md` | `hunting-for-webshell-activity` | Threat-hunting workflow, scenarios, output format |
| `references/hunting-for-webshell-activity-api-reference.md` | `hunting-for-webshell-activity` | Splunk/KQL/Sigma queries, process-tree indicators |
| `references/hunting-for-webshell-activity-template.md` | `hunting-for-webshell-activity` | Hunt report template and metadata |
| `references/hunting-for-webshell-activity-standards.md` | `hunting-for-webshell-activity` | MITRE/data-source standards |
| `references/hunting-for-webshell-activity-workflows.md` | `hunting-for-webshell-activity` | Detailed hunt workflow phases |
| `hunting-for-webshell-activity/scripts/agent.py` | `hunting-for-webshell-activity` | Defensive webshell log hunter |
| `hunting-for-webshell-activity/scripts/process.py` | `hunting-for-webshell-activity` | Defensive Sysmon process/file detector |

Original sub-skills remain intact under `hunt-file-upload/` and `hunting-for-webshell-activity/` (including assets/template.md, standards.md, workflows.md, api-reference.md, and scripts/agent.py/process.py).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_file_upload_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger file upload labs, OWASP crAPI, VulnHub, and webshell detection exercises.
- Mastery criteria: independently discover, prove, and report a file-upload finding (RCE/XSS/SSRF/traversal) with full reproduction, impact, and remediation, and run a webshell hunt with validated detections.


## Knowledge sources

- WKS bug classes: file_upload
- Domain knowledge: file_upload
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
