# Report lessons — distilled training data

(lessons distilled from accepted/rejected reports; append new entries)

## 2026-10-30 — Files.com session (no reportable finding; lessons from FP'd leads)
- The folder's prior "mass assignment" note was written from an ADMIN session — it proved admin capability, not escalation. Lesson: record the role/tenant of every PoC; a PoC run as site_admin cannot support a privilege-escalation claim.
- SSRF "accepted" responses at creation time are not findings — the delivery log (`event_delivery_attempts`, `automation_logs`) is the ground truth. Two surfaces (event_targets, import_file nodes) looked vulnerable on create and were blocked at fetch; both logged `Restricted hostname or resolved IP`.
- Before claiming stored XSS from uploads, fetch the actual bytes via `?action=redirect` and check `Content-Disposition`/`Content-Type` on the signed URL — S3-served files with `attachment` disposition are not XSS.
- Webhook test endpoints reflecting upstream status codes ("Failed with status 403") are only an info signal for allowlisted URLs, not SSRF proof.

<!-- BEGIN GENERATED -->
_Generated 2026-10-31T05:46:53+00:00 — 0 lessons from the canonical store._

_No lessons have been promoted past `captured` yet._
<!-- END GENERATED -->
