# FALSE_POSITIVE_DB

Known false-positive patterns; consult before reporting.

## 2026-10-30 — files.com
- "Mass assignment PATCH /users/{id} permission flags" → FP for non-admin users (403 Insufficient Permission For Params); admin-setting flags on own site users is by-design (reauth only for site_admin/api_keys).
- "SSRF via webhook/behaviors/event_targets/automation import_file/SIEM" → blocked at connection time (Restricted hostname or resolved IP); create-time validation missing but not exploitable; redirect chains and DNS-rebind names also blocked.
- "IDOR on /users/{id}, permissions, snapshots, automations, bundles" → 404/403 across roles/tenants; site_id/workspace_id injection rejected 422.
- "as_user impersonation from regular user" → 401 Invalid session.
- "Path traversal in /files/{path} et al." → 404, no traversal.
- "Stored XSS via uploaded SVG/HTML" → S3 serves Content-Disposition: attachment; app CSP nonce'd.
