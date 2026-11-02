---
name: clickjacking
description: "Canonical clickjacking capability consolidating 2 sub-skills: hunt-clickjacking, performing-clickjacking-attack-test. Use when hunting or validating clickjacking/UI-redressing vulnerabilities."
sources: consolidated
---

# CLICKJACKING — Canonical Capability

## 1. Identity and purpose

This is the single primary capability entry point for the `clickjacking` (UI redressing) security domain. It consolidates 2 previously separate sub-skills — `hunt-clickjacking` and `performing-clickjacking-attack-test` — into one operational entry point while preserving all source content in `references/` and the original sub-skill directories for rollback.

Primary objectives:
- Identify pages that lack anti-framing controls (`X-Frame-Options`, CSP `frame-ancestors`).
- Determine whether a sensitive state-changing action can actually be performed through a cross-site framed click.
- Account for SameSite cookies, framebusting JavaScript, and sandbox bypasses that may defeat or enable the attack.
- Produce a real-browser proof of concept with overlay screenshot/recording and impact assessment.

## 2. Scope

In scope:
- Web pages that perform state-changing actions: login flows, money transfers, account settings, password/email change, 2FA disable, OAuth consent, admin actions.
- Anti-framing headers: `X-Frame-Options` (DENY/SAMEORIGIN/ALLOW-FROM) and CSP `frame-ancestors`.
- JavaScript frame-busting defenses and bypass techniques (sandbox, double framing, onbeforeunload).
- Clickjacking variants: likejacking, cursorjacking, multi-step clickjacking.

Out of scope (hand off):
- Pure HTML reflection without script execution -> `hunt-html-injection` / XSS capability.
- Non-HTML/API endpoints (JSON, images) -> not clickjacking targets.
- Missing headers on read-only public pages -> informational only, no finding without a sensitive action.

## 3. Invocation and routing

Use this capability when:
- A target page lacks `X-Frame-Options` and CSP `frame-ancestors`.
- You need to test whether a sensitive action survives being framed cross-site.
- Assessing frame-busting defenses or building clickjacking PoCs during authorized testing.

Routing notes:
- Start with `references/hunt-clickjacking.md` for hypothesis, screening, and proof requirements.
- Use `references/performing-clickjacking-attack-test.md` for the step-by-step penetration-test workflow, PoC templates, and reporting format.
- Use `references/performing-clickjacking-attack-test-api-reference.md` for header/JS-pattern lookup and tooling details.
- Frame-busting bypass work routes to Step 5 of the performing reference.

## 4. Inputs and outputs

Inputs:
- Target URLs and sensitive action pages (login, settings, transfer, delete, OAuth consent, admin).
- Authenticated session context (test account) for verifying cookie survival in frames.
- Optional: Burp Suite project, browser DevTools, local web server for hosting PoCs.

Outputs:
- Confirmed or refuted clickjacking findings with real-browser frame PoC.
- Header analysis table per page.
- Proof-of-concept HTML overlay and screenshot/recording evidence.
- Reproduction steps, impact assessment, and remediation guidance.
- False-positive rulings with disproof rationale (SameSite cookies, framebusting JS, no sensitive action).

## 5. Preconditions and authorization

- Confirm written authorization and scope before testing; include target hosts and test accounts.
- Use only test accounts and non-production data unless explicitly authorized.
- Do not trick real users; PoCs are demonstrated in a controlled browser session.
- Respect scope: only test authorized applications; do not deploy PoCs against real victims.
- Document any out-of-scope or protected page and hand off rather than claim.

## 6. Reconnaissance

Recon steps:
1. Enumerate sensitive action pages: `/`, `/login`, `/settings`, `/account`, `/account/delete`, `/change-password`, `/change-email`, `/transfer`, `/admin`, OAuth consent URLs.
2. Fetch each page and inspect response headers for `X-Frame-Options` and `Content-Security-Policy`.
3. Check response body for JavaScript frame-busting (`top.location`, `window.top`, `parent.frames`, `top !== self`).
4. Identify whether actions are one-click or multi-step; note SameSite cookie attributes on session cookies.
5. Determine which pages are state-changing vs read-only to prioritize impact.

See `references/hunt-clickjacking.md` (header check) and `references/performing-clickjacking-attack-test.md` (Step 1).

## 7. Detection methodology

Core detection flow:
1. Header screening: fetch target page; if both `X-Frame-Options` and CSP `frame-ancestors` are absent, mark as candidate.
2. If either is present and restrictive (`DENY`/`SAMEORIGIN`/`frame-ancestors 'none'|'self'`), stop — protected.
3. Verify the page actually renders inside an iframe in a real browser (no framebusting JS that blanks/redirects).
4. Verify the sensitive action still succeeds while framed cross-site (session cookies survive; SameSite not Lax/Strict).
5. Confirm the target is a state-changing action, not a read-only page.
6. For JS frame-busting, attempt bypasses (sandbox attribute, double framing, onbeforeunload interception).

Header-absence alone is NOT a finding. Step 2 (real frame + click proof) is mandatory.

## 8. Technique selection

Select techniques by observed defenses:
- No headers at all -> basic iframe embedding + overlay PoC.
- JS frame-busting present -> sandbox attribute, double framing, onbeforeunload interception, data:/about:blank techniques.
- `X-Frame-Options: ALLOW-FROM` (deprecated, limited support) -> test whether browser enforces it; may be bypassable.
- Multi-step actions -> multi-step clickjacking PoC with decoy steps aligned to real buttons.
- OAuth consent / one-click actions -> single-click overlay with high impact.

See `references/performing-clickjacking-attack-test.md` (Steps 2-5) and `references/performing-clickjacking-attack-test-api-reference.md` (JS frame-busting patterns).

## 9. Execution steps

1. Establish baseline: fetch each sensitive page and record `X-Frame-Options` and CSP `frame-ancestors`.
2. Screen candidates where both are absent.
3. Build a minimal PoC iframe page and load it in a real browser; confirm the target renders inside the frame.
4. Log in as the test victim in the same browser; reload PoC; confirm the authenticated state carries into the frame.
5. Overlay decoy UI aligned to the sensitive button; click and verify the action executes on the target.
6. Adjust iframe opacity (e.g., 0.5) to capture screenshot evidence of overlap.
7. Test frame-busting bypasses if JS protection is present.
8. Repeat for each candidate page; document protected vs vulnerable.
9. Confirm exploitability with a clean reproduction; mark refuted if any proof requirement fails.

## 10. Tool usage

- Proxy: Burp Suite (examining `X-Frame-Options` and CSP headers).
- Browser: modern browser with DevTools (console framing errors, iframe rendering).
- Local server: Python `http.server` for hosting PoC pages.
- HTTP client: curl for header checks; Python requests for automated multi-endpoint checks.
- Automation: `performing-clickjacking-attack-test/scripts/agent.py` (header check, JS frame-busting check, PoC generation, report).
- Online scanners: OWASP ZAP, securityheaders.com (screening only).

See `references/performing-clickjacking-attack-test.md` (Prerequisites, Tools & Systems).

## 11. Payloads and test cases

Representative test cases (adapt to target):
- Header screen: `curl -sI https://target/account/transfer | grep -iE 'x-frame-options|content-security-policy'`.
- Multi-page screen loop over `/`, `/account/settings`, `/account/delete`, `/transfer`, `/admin/dashboard`, `/change-password`, `/change-email`.
- JS frame-busting grep: `curl -s https://target/ | grep -i "top.location\|parent.location\|frameElement"`.
- Basic frame test HTML with `<iframe src="https://target/account/settings" width="800" height="600">`.
- Overlay PoC with `opacity:0.0001`, `z-index:2`, decoy button aligned via `top`/`left`.
- Multi-step PoC with sequential decoy clicks aligned to settings link then delete button.
- Frame-busting bypass: `sandbox="allow-scripts allow-forms allow-same-origin"` (no `allow-top-navigation`).
- Double framing via intermediate page.
- onbeforeunload interception to block navigation.
- data:/about:blank nested iframe technique.

## 12. Evidence

Each finding must include:
- Exact page URL and response headers (or their absence).
- Real-browser proof: target rendered inside an attacker-controlled iframe.
- Sensitive state-changing action reachable by a framed click while the victim is authenticated (cookies survive cross-site context).
- Screenshot/recording of the overlay (opacity raised to ~0.5 to show overlap).
- Impact assessment and affected action.
- For refuted candidates: disproof rationale (SameSite cookie, framebusting JS, read-only page).

## 13. Reproduction and validation

- Reproduce with a clean browser session and the PoC HTML hosted locally.
- Validate that the action actually executes on the target (not just that the page frames).
- Confirm cookie survival: inspect `Set-Cookie` SameSite attribute; if `Lax`/`Strict`, the cross-site framed request will not carry the session and the finding is refuted.
- Confirm no framebusting JS defeats rendering; if present, test bypasses and document results.
- Mark as refuted if any proof requirement fails.

## 14. False-positive rejection

Reject or downgrade when:
- Only headers are missing on public/read-only pages (informational).
- APIs and non-HTML endpoints are flagged (not clickjacking targets).
- The page does not render inside the iframe due to framebusting JS (unless bypassed).
- The sensitive action fails while framed because SameSite cookies are not sent.
- The target action is read-only (no state change).
- `X-Frame-Options`/CSP is present and restrictive.
- Reporting missing headers with no working frame PoC is a documentation issue, not a vulnerability.

## 15. Impact

Impact guidance:
- Critical/High: account takeover via email/password change, fund transfer, admin action, 2FA disable, OAuth consent grant.
- Medium: account settings changes, profile modification requiring one click.
- Low/Informational: missing headers on read-only/public pages with no sensitive action.

Always tie impact to the specific action the victim is tricked into performing; avoid severity inflation from header absence alone. Reference CVSS 6.1 baseline for standard clickjacking.

## 16. Reporting

Report template:
- Summary: URL, vulnerability type (clickjacking/UI redressing), action, impact.
- Headers analysis table: Page | X-Frame-Options | CSP frame-ancestors | Vulnerable.
- Sensitive actions exploitable (numbered list).
- Impact (account takeover, financial loss, security downgrade).
- Proof: PoC HTML, screenshot of overlay, real-browser frame rendering.
- Remediation: CSP `frame-ancestors 'none'`, `X-Frame-Options: DENY` fallback, re-authentication for sensitive actions, confirmation dialogs, `SameSite=Strict` cookies.

See `references/performing-clickjacking-attack-test.md` (Output Format).

## 17. Failure modes

- Headers present and restrictive -> stop; page is protected.
- Framebusting JS blanks/redirects the frame -> attempt bypasses; if none work, refute.
- SameSite=Lax/Strict cookies -> cross-site framed request lacks session; refute or note partial.
- Action requires re-authentication/confirmation -> may reduce exploitability; document.
- Multi-step action with dynamic layout -> PoC alignment may be brittle; document fragility.
- WAF blocks PoC hosting -> use alternate local server/port.

## 18. References

All 2 sub-skill references are preserved and must resolve:

| Reference | Sub-capability | Load when |
|---|---|---|
| `references/hunt-clickjacking.md` | `hunt-clickjacking` | Hypothesis, screening, proof requirements |
| `references/performing-clickjacking-attack-test.md` | `performing-clickjacking-attack-test` | Full pentest workflow, PoC templates, reporting |
| `references/performing-clickjacking-attack-test-api-reference.md` | `performing-clickjacking-attack-test` | Header/JS-pattern lookup and tooling |

Original sub-skills remain intact under `hunt-clickjacking/` and `performing-clickjacking-attack-test/` (including nested api-reference.md and scripts/agent.py).

## 19. Testing and mastery

- Validate with the capability tests in `tests/test_clickjacking_capability.py`.
- Confirm all referenced files resolve and are non-empty.
- Confirm migration map paths/hashes/status are accurate.
- Practice on authorized labs: deliberately vulnerable clickjacking labs, OWASP WebGoat.
- Mastery criteria: independently discover, validate (real frame + cross-site click), and report a clickjacking finding with full reproduction and impact, correctly refuting header-only candidates.

---

Original sub-skills remain intact for reversibility. See `migration_map.json`.


## Knowledge sources

- WKS bug classes: clickjacking
- Domain knowledge: clickjacking
- WKS remains the structured source of truth; retrieve and validate items through WKS rather than duplicating the full corpus in this skill.
- Research and learning material is mapped in `stage-a/knowledge-source-map.json` and must be validated before promotion.
