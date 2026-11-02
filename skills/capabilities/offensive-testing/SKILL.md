---
name: offensive-testing
description: "Canonical offensive-testing capability consolidating 11 sub-skills: analyzing-ios-app-security-with-objection, conducting-mobile-app-penetration-test, performing-android-app-static-analysis-with-mobsf, performing-dynamic-analysis-of-android-app, performing-external-network-penetration-test, performing-ios-app-security-assessment, performing-mobile-app-certificate-pinning-bypass, performing-thick-client-application-penetration-test, performing-web-application-penetration-test, performing-web-application-scanning-with-nikto, performing-web-application-vulnerability-triage. Use when hunting or validating offensive-testing-related vulnerabilities."
sources: consolidated
---

# OFFENSIVE-TESTING — Canonical Capability

## 1. Identity and purpose

This is the single primary executable capability for offensive security testing across web, mobile (iOS/Android), thick-client desktop, and external network surfaces. It consolidates 11 previously separate sub-skills into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Plan and execute authorized penetration tests following PTES/OWASP methodologies.
- Perform static and dynamic analysis of mobile applications (Android/iOS) and bypass client-side protections for traffic inspection.
- Scan and triage web application vulnerabilities and orchestrate external network reconnaissance/exploitation.
- Produce reproducible, impact-rated findings with remediation guidance.

## 2. Scope

In scope:
- Web application penetration testing (OWASP WSTG): auth, authorization, input validation, session management, business logic.
- Web application scanning and vulnerability triage (Nikto, DAST/SAST output, OWASP Risk Rating).
- Mobile application security: Android static analysis (MobSF), dynamic analysis (Frida/Objection/ADB), iOS assessment (Frida/Objection/keychain/IPA), certificate pinning bypass.
- Thick-client desktop application testing: local storage, hardcoded creds, DLL hijacking, memory manipulation, insecure API comms.
- External network penetration testing (PTES): recon, scanning, exploitation, reporting.

Out of scope (hand off):
- Pure HTML reflection without script execution -> `hunt-html-injection` (escalate to XSS once execution is possible).
- Non-offensive vulnerability classes (SQLi, SSRF, SSTI, etc.) unless reached through an offensive-testing workflow -> their own capabilities.
- Infrastructure-only findings without an exploit path -> cloud/network capabilities.

## 3. Invocation and routing

Use this capability when:
- You need to plan or execute an authorized penetration test (web, mobile, thick-client, or external network).
- A target requires static/dynamic mobile app analysis or SSL pinning bypass for traffic interception.
- You need to scan a web server/application with Nikto or triage scanner findings.
- You are validating remediation or conducting compliance-driven assessments.

Routing notes:
- Web app pentest work routes to `references/performing-web-application-penetration-test.md`.
- Scanner output triage routes to `references/performing-web-application-vulnerability-triage.md`.
- Nikto scanning routes to `references/performing-web-application-scanning-with-nikto.md`.
- Android static analysis routes to `references/performing-android-app-static-analysis-with-mobsf.md`.
- Android dynamic analysis routes to `references/performing-dynamic-analysis-of-android-app.md`.
- iOS assessment routes to `references/performing-ios-app-security-assessment.md` and `references/analyzing-ios-app-security-with-objection.md`.
- Certificate pinning bypass routes to `references/performing-mobile-app-certificate-pinning-bypass.md`.
- Thick-client testing routes to `references/performing-thick-client-application-penetration-test.md`.
- Mobile pentest methodology routes to `references/conducting-mobile-app-penetration-test.md`.
- External network pentest routes to `references/performing-external-network-penetration-test.md`.

## 4. Inputs and outputs

Inputs:
- Target URLs/hosts, application binaries (APK/AAB/IPA), desktop installers, scope documents (SoW).
- Authentication material (test accounts at each privilege level), API specs, technology stack details.
- Optional: Burp Suite project, Frida/Objection tooling, MobSF instance, Nikto, dnSpy/Procmon.

Outputs:
- Confirmed or refuted findings with request/response or tool proof.
- Endpoint/attack-surface inventory and scan results.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale.

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include target hosts, apps, environments, and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Respect rate limits and avoid destructive operations on shared resources.
- Stop at account/tenant boundaries; do not access other users' data beyond proof of control.
- Document any out-of-scope target discovered and hand off rather than exploit.

## 6. Reconnaissance

Recon steps:
1. Collect scope and documentation: SoW, API specs, sitemap, technology stack.
2. Map attack surface: spider web apps, enumerate endpoints/parameters/headers/cookies/uploads/WebSockets.
3. Fingerprint technology stack from headers, cookies, page extensions, and framework markers.
4. For mobile: obtain APK/AAB/IPA, extract manifests, permissions, components, hardcoded secrets.
5. For external network: DNS/subdomain enumeration, port scanning, service fingerprinting.
6. For thick-client: identify local storage, config files, registry keys, IPC, and API endpoints.

See `references/performing-web-application-penetration-test.md`, `references/performing-external-network-penetration-test.md`, `references/conducting-mobile-app-penetration-test.md`.

## 7. Detection methodology

Core detection flow:
1. Inventory targets and parameters; classify by auth requirement and data sensitivity.
2. Test authentication and authorization weaknesses (credential enumeration, brute force, IDOR, privilege escalation).
3. Test input validation and injection (SQLi, XSS, SSRF, command injection, XXE, SSTI).
4. Test session management (token randomness, expiration, cookie flags, CSRF).
5. Test business logic (race conditions, workflow bypass, numeric manipulation, file upload bypass).
6. Perform static/dynamic mobile analysis and pinning bypass to enable traffic inspection.
7. Scan with Nikto and triage findings using OWASP Risk Rating.
8. Validate each candidate with a second, independent request/account and mark refuted if not demonstrable.

References by phase:
- Web app: `references/performing-web-application-penetration-test.md`.
- Mobile pentest: `references/conducting-mobile-app-penetration-test.md`.
- Android static: `references/performing-android-app-static-analysis-with-mobsf.md`.
- Android dynamic: `references/performing-dynamic-analysis-of-android-app.md`.
- iOS: `references/performing-ios-app-security-assessment.md`, `references/analyzing-ios-app-security-with-objection.md`.
- Pinning: `references/performing-mobile-app-certificate-pinning-bypass.md`.
- Thick client: `references/performing-thick-client-application-penetration-test.md`.
- External network: `references/performing-external-network-penetration-test.md`.
- Nikto: `references/performing-web-application-scanning-with-nikto.md`.
- Triage: `references/performing-web-application-vulnerability-triage.md`.

## 8. Technique selection

Select techniques by surface and observed behavior:
- Web app -> OWASP WSTG methodology across auth/authz/input/session/business logic.
- Mobile static (Android) -> MobSF automated analysis for secrets, permissions, components, crypto.
- Mobile dynamic (Android) -> Frida/Objection/ADB runtime instrumentation, function hooking, value modification.
- iOS -> Frida dynamic instrumentation, Objection runtime exploration, SSL pinning bypass, keychain extraction, IPA static analysis.
- Certificate pinning -> Frida/Objection/custom scripts for OkHttp, TrustManager, NSURLSession, third-party libraries.
- Thick client -> dnSpy, Procmon, Burp Suite for local storage, creds, DLL hijacking, memory, API comms.
- External network -> PTES: recon, scanning, exploitation, reporting.
- Scanning/triage -> Nikto for server/app scanning; OWASP Risk Rating for triage.

## 9. Execution steps

1. Establish scope, authorization, and test accounts.
2. Perform reconnaissance and attack-surface mapping per target type.
3. Run methodology-specific testing (web/mobile/thick-client/network).
4. For mobile, bypass certificate pinning to enable traffic interception when authorized.
5. Scan with Nikto where applicable and triage scanner output.
6. Confirm exploitability with a clean reproduction (curl/raw HTTP or tool proof).
7. Stop and document when a vector is not exploitable or out of scope.

## 10. Tool usage

- Proxy: Burp Suite Professional (Repeater, Intruder, Comparer, Logger++), mitmproxy.
- Web scanning: Nikto, OWASP ZAP (screening).
- Mobile static: MobSF.
- Mobile dynamic: Frida, Objection, ADB, apktool, class-dump.
- iOS: Frida, Objection, SSL pinning bypass tools, keychain dumper.
- Thick client: dnSpy, Procmon, Burp Suite, x64dbg.
- Network: nmap, masscan, ffuf, subfinder, httpx, KiteRunner.
- Automation: Python requests/httpx, curl, jq, nuclei (in-scope templates only).
- Evidence: screenshots, saved requests/responses, canary values, timing data.

See references for tool-specific details.

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Web auth: credential enumeration, brute force (10-20 rapid attempts), MFA bypass, session fixation, password reset token predictability.
- Web authz: IDOR via Account A/B identifier swap, vertical escalation to admin URLs, forced browsing, HTTP method tampering.
- Web input: SQLi (`' OR 1=1--`, time-based blind), XSS (reflected/stored/DOM), SSRF (169.254.169.254), command injection, XXE, SSTI (`{{7*7}}`).
- Web session: token randomness (Burp Sequencer), expiration, cookie flags (Secure/HttpOnly/SameSite), CSRF.
- Web business logic: race conditions (Burp Turbo Intruder), workflow bypass, numeric manipulation, file upload bypass.
- Mobile: hardcoded secrets in APK, insecure data storage, weak crypto, exported components, runtime tampering, pinning bypass.
- Network: port/service enumeration, default creds, outdated versions, exposed management interfaces.
- Thick client: local DB/creds, DLL hijacking, memory manipulation, insecure API comms.
- Nikto: `nikto -h https://target -o report.html`.
- Triage: OWASP Risk Rating (likelihood x impact) to confirm/dismiss/prioritize.

## 12. Evidence

Each finding must include:
- Exact request/response or tool proof (raw HTTP, scan output, Frida trace).
- Authentication context and account/role used.
- Canary values or modified fields and server-side effect.
- For authorization: paired requests showing cross-account/cross-role access.
- For mobile: runtime trace, keychain/file extraction proof, pinning bypass confirmation.
- Impact assessment and affected data scope.

## 13. Reproduction and validation

- Reproduce with curl or a saved raw request/script in a clean session.
- Validate with a second account/role where applicable.
- Confirm persistence for stored/mass-assignment issues.
- For race conditions, repeat multiple times and document success rate.
- For mobile, re-run instrumentation and confirm bypass stability.
- Mark as refuted if execution or unauthorized access cannot be demonstrated.

## 14. False-positive rejection

Reject or downgrade when:
- A field is reflected but not executed or persisted.
- An endpoint returns 401/403/404 without data leakage.
- A privileged field is echoed but not stored or enforced server-side.
- Header absence alone on read-only/public pages (informational only).
- Scanner findings not confirmed by manual validation.
- Mobile protections cannot be bypassed or no sensitive data is exposed.
- Network services are hardened with no exploit path.

## 15. Impact

Impact guidance:
- Critical: unauthenticated RCE, full DB/infrastructure access, global account takeover, payment manipulation.
- High: account takeover, cross-tenant data access, SSRF to internal network, mass PII exposure, mobile credential extraction.
- Medium: IDOR on sensitive data, function-level authorization bypass, pinning bypass enabling traffic inspection.
- Low: non-sensitive metadata disclosure, missing hardening without exploit path.

Always tie impact to business risk and data scope; avoid severity inflation from configuration presence alone.

## 16. Reporting

Report template:
- Summary: target, vulnerability type, action, impact.
- Scope/authorization: test accounts, test window.
- Steps to reproduce: numbered, minimal.
- Proof of concept: raw request/response, scan output, or tool trace.
- Impact: business and data scope.
- Remediation: specific control (authz middleware, input validation, header hardening, pinning, patching).
- References: relevant OWASP/PTES/MASTG sections.

See `references/performing-web-application-penetration-test.md` (Output Format) and `references/performing-web-application-vulnerability-triage.md`.

## 17. Failure modes

- Surface not fully discovered -> expand recon, check mobile/SPA, versions, content types.
- Auth required but no test account -> request credentials or scope clarification; do not bypass without authorization.
- WAF/gateway blocks payloads -> try content-type confusion, encoding, version downgrade, or parser differentials.
- Rate limiting stops testing -> coordinate throttling, use allowed test windows, or hand off.
- Mobile pinning cannot be bypassed -> document and limit testing to static analysis.
- Nikto false positives -> validate manually before reporting.
- Inconclusive result -> repeat with fresh sessions and diff responses; mark as not confirmed if ambiguous.

## 18. References

All 11 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/analyzing-ios-app-security-with-objection.md` | `analyzing-ios-app-security-with-objection` | Runtime iOS app security testing with Objection (Frida) |
| `references/conducting-mobile-app-penetration-test.md` | `conducting-mobile-app-penetration-test` | Mobile app pentest methodology (OWASP MASTG) |
| `references/performing-android-app-static-analysis-with-mobsf.md` | `performing-android-app-static-analysis-with-mobsf` | Android static analysis with MobSF |
| `references/performing-dynamic-analysis-of-android-app.md` | `performing-dynamic-analysis-of-android-app` | Android dynamic analysis (Frida/Objection/ADB) |
| `references/performing-external-network-penetration-test.md` | `performing-external-network-penetration-test` | External network pentest (PTES) |
| `references/performing-ios-app-security-assessment.md` | `performing-ios-app-security-assessment` | Comprehensive iOS security assessment |
| `references/performing-mobile-app-certificate-pinning-bypass.md` | `performing-mobile-app-certificate-pinning-bypass` | SSL/TLS certificate pinning bypass |
| `references/performing-thick-client-application-penetration-test.md` | `performing-thick-client-application-penetration-test` | Thick-client desktop app pentest |
| `references/performing-web-application-penetration-test.md` | `performing-web-application-penetration-test` | Web app pentest (OWASP WSTG) |
| `references/performing-web-application-scanning-with-nikto.md` | `performing-web-application-scanning-with-nikto` | Nikto web server/app scanning |
| `references/performing-web-application-vulnerability-triage.md` | `performing-web-application-vulnerability-triage` | Triage DAST/SAST findings (OWASP Risk Rating) |

Original sub-skills remain intact under their directories (including nested assets/references/scripts).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_offensive_testing_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: PortSwigger Web Security Academy, OWASP WebGoat, DIVA, InsecureBankv2, OWASP crAPI.
- Mastery criteria: independently discover, validate, and report an offensive-testing finding with full reproduction and impact, correctly refuting false positives.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: none mapped
- Domain knowledge: none mapped
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
