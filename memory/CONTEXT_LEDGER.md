# CONTEXT_LEDGER

Running context ledger for long sessions.
| 2026-10-30 | files.com hunt (H1 program "files") | tested REST API v1 as site_admin + non-admin: SSRF (behaviors/event_targets/automation import_file/SIEM) all blocked at connection time (RestrictedIpOrHostnameError) despite create-time acceptance of internal URLs; IDOR 404/403 across roles+tenants; self mass-assignment 403 for non-admin; unauth webhook trigger URLs work by design but unthrottled; prior mass_assignment lead = FP for regular users; site left clean | testing/files.com/app.files.com/notes/session-2026-10-30.md |
