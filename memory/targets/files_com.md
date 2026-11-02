# Target memory: Files.com (HackerOne program "files")

Scope: *.files.com (Web App), *.hosted-by-files.com (public hosting). Base API: https://app.files.com/api/rest/v1 (session via POST /sessions -> X-FilesAPI-Auth, or X-FilesAPI-Key). Swagger: /api/rest/v1/swagger_doc.json (12.9MB). App bundle main.js (3.1MB, sourcemap exposed but map itself 404-sized stub).

## Architecture facts (verified 2026-10-30)
- Every *.files.com host serves the caller's own site (wildcard multi-tenant); host-swapping does NOT cross tenants. Cross-tenant tests must use object IDs / site_id / workspace_id params.
- Roles: regular user < folder-admin < site_admin. Reauth (X-Files-Reauthentication: password OR own API key) required for site_admin, api_keys, 2fa/reset, unlock, as_user-adjacent actions.
- Permission flags (billing/ftp/sftp/dav/restapi/attachments) settable only by higher admin — 403 for self.
- API keys are role-scoped server-side; user-level key cannot reach site-admin endpoints.

## Known-hardened surfaces (verified blocked 2026-10-30)
- SSRF: webhook test/behaviors/event_targets/automation import_file/SIEM all enforce resolved-IP allowlist at connection time (incl. redirect chains + rebind names). Creation-time validation is missing for event_targets/import_file — check delivery logs, not create responses.
- IDOR: id-based endpoints 404/403 cross-role/cross-tenant.
- Uploads: served via S3 signed URLs with Content-Disposition: attachment (no inline XSS).
- Auth: uniform 401s, reset rate-limited (429), session invalidated on DELETE.

## Promising-but-unproven areas if revisited
- Unauth automation webhook URLs /api/webhooks/{uuid}: no observed rate limit; any automation (import_file etc.) triggerable by anyone with the UUID. Look for UUID predictability or unauth triggering of destructive automations on OTHER customers' sites.
- AI chat /api/ai/chat/v1/sessions/{id}/messages accepted (202) but no assistant output observed — check tool-use paths (file access tools) for authz gaps.
- Inbound email trigger: <site>-automation-<uuid>@inbox.files.com — email-borne automation triggers.
- Event delivery attempts log (site-admin readable) leaks blocked-target error detail.
- Dev/staging hosts (pentest., staging-wopi., tmp., open., vault.) expose full swagger and accept the same sessions — diff their API versions for removed/older vulnerable endpoints.
