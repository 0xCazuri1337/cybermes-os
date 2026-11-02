# DoD VDP hunt (session 2026-10-03-kh) — curated lessons (2026-10-07)

Source material mined:
- `/mnt/e/bugbounty/DOD/sessions/2026-10-03-kh/findings/ALL-VERDICTS.md` (and triage-verdict*.md, XSS-VERDICTS.md, TRUST-BOUNDARY.md, CLASS-COVERAGE.md)
- `/mnt/e/bugbounty/DOD/sessions/2026-10-03-kh/reports/FINAL_REPORT.md`
- `/mnt/e/bugbounty/DOD/af.mil/findings/status-summary.md`

Filing rule applied: hard-won FP/kill rules go to `research/pending/fp/fp-dod-session-2026-10-03.json`
(pre-gate, NOT knowledge — ingest/wks.fp decides promotion). Cross-cutting instrument/tooling
lessons live here (learning gap). No skill body (SKILL.md) hand-edited; no taxonomy_write run;
no db/wks.db writes; no traffic to DoD targets.

| # | Lesson | WKS class | Home filed |
|---|---|---|---|
| 1 | WebForms: normalise `__VIEWSTATE`/volatile tokens before hashing — ASP.NET rotates viewstate per request, so raw SHA-diff noise ("8 of 8 distinct") measured session tokens, not records. Fetch the same URL twice first; if it differs, the detector is measuring tokens. | idor | research/pending/fp (fp_rule) + HISTORY.md bullet |
| 2 | Full form-field echo: ASP.NET WebForms POST replay must echo ALL named fields (`__VIEWSTATE` + `__EVENTVALIDATION` + 30 hidden mirrors). Posting a subset redirects to UnknownError.htm — a harness error, not a target refusal (hit twice before fixed). | authn | research/pending/fp + HISTORY.md bullet |
| 3 | Captcha forms ship BOTH reCAPTCHA and image-fallback controls — observable "image captcha present" is not a downgrade. Kill requires a fresh-session A/B control (no switch call vs switch call) before claiming control downgrade. | authn | research/pending/fp + HISTORY.md bullet |
| 4 | Impossible-name control splits "exists but denied" from "does not exist": `403 AccessDenied` (real) vs `404 NoSuchBucket` (impossible names) proves access control is working; a bucket name in a JS bundle is not access. | info_disclosure | research/pending/fp + HISTORY.md bullet |
| 5 | Takeover regex false-match: `<html class="login-pf">` is Okta/Keycloak login-portal-frame CSS, not an Azure default page. A provider-hosted endpoint is not a claimable asset — require a dangling DoD-controlled record + canary-path byte-identical check. | subdomain_takeover | research/pending/fp + HISTORY.md bullet |
| 6 | Wildcard-ACAO + ACAC:true is invalid per the Fetch spec (browsers make it opaque — no credentialed-CORS cookie theft). Independently: a cross-origin 401 with zero-byte body = no data to steal, hence no impact. | cors | research/pending/fp + HISTORY.md bullet |
| 7 | GraphQL "errors-without-data": an `{"errors":...}` rejection, a 401, or a zero-byte body is NOT a data-exposure signal. Only a 200 body containing real first-party records (differing from an impossible-name canary) counts. | graphql | research/pending/fp + HISTORY.md bullet |
| 8 | Open-redirect on auth pages: canary host must be IANA-reserved (`example.com`), redirects NOT followed (`NoRedirect`), evidence is the Location header only. A 130-req sweep of auth endpoints (`redirect_uri, ReturnUrl, RelayState, redirect_to, wreply`) returned all NO-REDIRECT. | open_redirect | research/pending/fp + HISTORY.md bullet |
| 9 | FOIA IDOR candidates: check programme semantics first — AF efoia's reading-room publishes the exact docids an inherited report called "unauthorized" (11 of 12 are deliberately published; distribution-A glossary = "Approved for public release"). Parameter real + id-scoped ≠ boundary crossed. | idor | research/pending/fp + HISTORY.md bullet |
| 10 | Count-pinning + reproducibility: a surfaced result set survives only if reproducible 3/3 with the same N rows / same document numbers / same normalised hash. "0 differing from canary" with peak + ceiling compliance means a measured negative, not an unexplored surface. | (cross-cutting) | this file (learning) |
| 11 | Identical bytes for real and nonsense paths (gitlab login wall, error-page catch-all, Confluence status banner, DISA 1116-byte catch-all) = working as designed. Byte-identical canary = catch-all IdP front, not a claimable per-path surface. | info_disclosure | research/pending/fp + HISTORY.md bullet |
| 12 | A JSON/XML content-type on a 404/Go-router body is not a data signal — Go's default handler returns JSON content-type on 404 too. Must pair content-type with body diff vs canary. | info_disclosure | research/pending/fp + HISTORY.md bullet |
| 13 | Browser percent-encodes `location.hash` before any JS reads it — `innerHTML` receives `%3Cimg...` (text), so a location.hash→innerHTML static finding must be disproved/confirmed in a real browser, not by reasoning. Query-string reflection in an attribute is likewise already-encoded (`%3c`) → not XSS. | xss | research/pending/fp + HISTORY.md bullet |
| 14 | Runtime capture of SPA bundles: `Network.enable` before navigation, read bodies inside the event pump on `Network.loadingFinished`, and pass `sessionId` to `Network.getResponseBody` (else: healthy script count, 0 bodies). Static script-tag capture misses code-split chunks. | xss | research/pending/fp + HISTORY.md bullet |
| 15 | Detector hygiene: a regex that silently matches nothing looks exactly like a clean result. Self-test every detector against BOTH defect shapes it must catch AND the correct shapes it must reject (13-case positive+negative) before scanning any corpus. Same class of failure as: token-bucket rate limiter passing mean but breaking peak (N points at exactly 1/rate puts N+1 in a closed 1s window — serialize inside the lock, gap > 1/rate). | (cross-cutting tooling) | this file (learning) |
| 16 | "UNREACHABLE"/`status 0` results are INCONCLUSIVE, not "not vulnerable" — validate against known-live controls through the same code path before accepting. UNREACHABLE vs BLOCKED_EDGE (Akamai 403 for this egress) vs app auth must stay distinct buckets. | (cross-cutting) | this file (learning) |
| 17a | Strapi JWT `alg:none` family (none/None/NONE/nOnE) → 401 "Missing or invalid credentials": signature enforcement confirmed across the family; a single-case alg:none test that 401s is consistent with enforcement, still confirm all four casings. HS256 weak-secret brute against a live token that succeeds on NONE of empty/"strapi"/defaults = strong random secret, case closed — no leaked .env gating. | jwt | research/pending/fp + HISTORY.md bullet |
| 17b | `POST /forgot-password` returning `{"ok":true}` for a non-existent email is SECURE (no account-enumeration oracle). Do not re-test as a finding; the vulnerable variant leaks existence in the response body. | authn | research/pending/fp + HISTORY.md bullet |
| 17 | Platform fingerprint before classing: `x-amzn-errortype: MissingAuthenticationTokenException` = AWS API Gateway, not Strapi; Strapi registration POST → 400 (route not deployed) ≠ an open registration. Secret-scan hits on key NAMES (`tokenClaimUrl`, …) are not values; sessionStorage token storage is origin-scoped framework default, not a reportable leak. | info_disclosure / session | research/pending/fp + HISTORY.md bullet (both) |

## New lessons from session 2026-10-07-hv2 (active hunt with explicit user authorization)

Source material mined:
- `/mnt/e/bugbounty/DOD/sessions/2026-10-07-hv2/findings/army_lane_findings.md`
- `/mnt/e/bugbounty/DOD/sessions/2026-10-07-hv2/findings/surface_lane_findings.md`
- `/mnt/e/bugbounty/DOD/sessions/2026-10-07-hv2/findings/rare_services_findings.md`
- `/mnt/e/bugbounty/DOD/sessions/2026-10-07-hv2/evidence/netlas_lane.json`

Filing rule: hard-won FP/kill rules go to `research/pending/fp/fp-dod-session-2026-10-07-hv2.json`
(pre-gate, NOT knowledge — ingest/wks.fp decides promotion). Cross-cutting instrument/tooling
lessons live here (learning gap). No skill body (SKILL.md) hand-edited; no taxonomy_write run;
no db/wks.db writes.

| # | Lesson | WKS class | Home filed |
|---|---|---|---|
| 18 | Army.mil 160-host sweep (prioritized from 2024 Netlas alive + uncovered) yielded 0 candidates: 71/160 reached, peak_1s=3. All depth-probed hosts killed by canary controls. Key FP shapes: EAMS-A fleet (sso1, core-dev, ikn, t.ikn, srp, srp2) all paths redirect to federation.eams.army.mil — SSO catch-all by design; DSMOA/USACE portals serve 200 error pages for `/.git/config`, `/.env`, `/web.config.bak` with identical sha (not exposure); ARL WordPress behind ADFS (wp-login redirects to ADFS, xmlrpc.php 403 denied); Armypubs 404.7 IIS filter for `/.env` (distinct from generic 404); history/sharp portals Akamai edge deny 403 on all paths incl. canary; ArcGIS Portal REST directory not at probed path; APEX/ORDS public/admin separation correct. | idor / info_disclosure / authn | research/pending/fp (fp_rule) + this file |
| 19 | Surface lane (monitoring/containers/collab/code_repos from Netlas 2024) yielded 0 candidates: 15/107 live, all NOT_REPORTABLE. F5 BIG-IP APM (oci.cdl, checkmarx.cdl) serves byte-identical logout page for `/v2/` and `/v2/_catalog` AND canary bucket — registry API not exposed. Azure AD US-GCC OIDC (bsrt.army.mil) returns login-redirect page for `/status` and `/rest/api/2/serverInfo` — byte-identical to canary path = auth wall by design. Apache "Error" page (730 B) on all API paths of www.nwd-wc.usace.army.mil — no repo data. Akamai/CloudFront 403 on all gcds.disa.mil `*.apps` routes — edge DENY before OpenShift router. | info_disclosure / subdomain_takeover | research/pending/fp + this file |
| 20 | Rare-service lane (GitLab×7, Keycloak×2, Nexus×3, SonarQube, Vault, Grafana×2, Kibana, Jenkins×2, MinIO, Registry, Harbor) — 20 DNS-resolves but all timeout from Cairo EG (140.x / 128.x / 206.x DoD internal ranges), 4 NXDOMAIN. UNREACHABLE = INCONCLUSIVE, not "not vulnerable". Liveness classification must separate NXDOMAIN (absent) from exists-but-unroutable (inconclusive) via public-DNS A record + curl --resolve on both ports. | (cross-cutting) | this file |
| 21 | Multi-threaded GapLimiter (threads=8, rate=2.0) still caused 429 Too Many Requests on CceLane, NetlasSvcLane, ApiJiraLane (remote rate limit, likely Akamai/WAF). Peak_1s measured OK (≤4) but burst on connection establishment exceeded remote tolerance. Fix: single-threaded or async with semaphore + exponential backoff on 429; concurrency 1 for VDP targets. | (cross-cutting tooling) | research/pending/fp + this file |
| 22 | CCE/AF.MIL deep-dive (takeoff, ar, mobileconnect, smartabase2, efoia SearchDocs sortBy/sortOrder, docid6047) was blocked by 429 before meaningful testing. The only reachable CCE host in prior session (federation.prod.cce.af.mil) was SSO login with no OIDC/Fed metadata endpoints (404). | (cross-cutting) | this file |
| 23 | Netlas 2024 data is heavily stale for internal services: many 140.x / 128.x hosts (NIPRNet) never answer from civilian egress. For VDP hunting, prioritize hosts that resolve to external-facing IPs (Akamai, CloudFront, public cloud) — those actually serve traffic. | recon | this file |
| 24 | Efoia SearchDocs.aspx parameter injection (ORDER BY via sortBy/sortOrder) and docid6047 catalog-resolution remain untested. Any future session must test these with single-threaded, 429-aware pacing, and canary controls. | sqli / idor | this file |

## What was NOT done / why
- CCE/AF.MIL deep-dive, efoia sortBy/sortOrder injection, docid6047 resolution, API/Jira fleet probes — all blocked by 429 rate limits before completion. Will retry with stricter pacing.
- No hand-edits to `knowledge/CLASS.md` / `DIGEST.md` (generated).
- No `taxonomy_write.py` run, no `wks.db` edits, no `wks.fp log` (avoid clobbering).
- SKILL.md bodies untouched; new evidence waits in `research/pending/fp/fp-dod-session-2026-10-07-hv2.json` for the normal gate.

## What was NOT done / why
- No hand-edits to `knowledge/CLASS.md` / `DIGEST.md` (generated).
- No `taxonomy_write.py` run, no `wks.db` edits, no `wks.fp log` (avoid clobbering).
- No network traffic to DoD targets — all sources are local artifacts under `/mnt/e/bugbounty/DOD/`.
- SKILL.md bodies untouched; new evidence waits in `research/pending/fp/fp-dod-session-2026-10-03.json` for the normal gate.
