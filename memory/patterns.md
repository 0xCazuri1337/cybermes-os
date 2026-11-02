# Patterns

(recurring patterns observed across targets)

## Standing biases (carried forward from the curated briefing)

MEASURED 2026-10-31: these six were hand-written into `agent-briefing.md`.
When the briefing's bias block became GENERATED (from this file and
`memory/report-lessons.md`), they were replaced by the bullets below --
because they lived in the briefing and in no generated source. They are
kept here now, which is where a recurring pattern belongs, so the
generation is lossless instead of a silent deletion.

- JS intelligence wins hunts — bundles/source maps leak hidden routes and undocumented APIs.
- GraphQL authenticates but fails ownership — auth ≠ authorization.
- SSRF strongest when chained — callback alone is a lead, not a finding.
- Parser differentials create real bypasses — content-type/method/header mismatches.
- Auth bugs live in recovery/fallback paths — reset, magic link, invite, MFA bypass.
- Medium signals become critical chains — compose weak signals into impact.

## 2026-10-30 — Files.com (H1 "files") hunt patterns
- Create-time vs connect-time validation gap: Files.com accepts internal URLs (169.254.169.254, 127.0.0.1) when CREATING webhook event_targets and automation import_file nodes, and only blocks at delivery (`RestrictedIpOrHostnameError`). The block is real (redirect chains, DNS-rebind names, decimal/hex IPs all stopped), but a target that validates only at creation is one refactor away from SSRF. When you see "accepted at write, blocked at fetch", verify WHICH layer blocks by reading delivery logs, not the create response.
- Unauth webhook trigger URLs (`/api/webhooks/{uuid}`) fire automations with zero auth and no observed rate limit — usable as an unauth trigger primitive on any site that has one; check for throttling explicitly.
- "Mass assignment on PATCH /users/{id}" as a lead: always test as the LOWEST-privilege role you can create, not as admin. Admin-set flags without reauth are by-design; only self/folder-admin escalation counts. Files.com gates this correctly (403 Insufficient Permission For Params; admin_group_ids accepted-but-ignored).
- Multi-tenant SaaS on wildcard subdomains (*.files.com): every host serves the CALLER's site — cross-tenant probing must use object IDs and site_id/workspace_id params, not host swapping. Host-swap sessions don't cross sites.
- Reauth gates (`X-Files-Reauthentication`) accept the account password OR a valid API key of the acting user — test both credential types when probing whether a gate can be satisfied with a weaker credential.
- API-key scoping is enforced server-side per role (user-level key got 403 on site-admin endpoints even with self-reauth) — good reference implementation to compare against.
- Login/reset error uniformity + 429 rate limiting on forgot endpoints was correct; always measure timing/error-body uniformity before calling enumeration.
