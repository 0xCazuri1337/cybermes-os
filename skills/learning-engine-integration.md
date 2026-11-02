---
name: learning-engine-integration
description: load and use the persistent learning engine for adaptive hunting, signal scoring, memory retrieval, and triage feedback ingestion across hunts
---

# learning-engine-integration — ADAPTIVE LEARNING SKILL

Loaded SECOND in every session (right after master-bugbounty-rules), before any
recon.

## PURPOSE

This skill is loaded automatically before every hunt and provides pre-hunt
intelligence, real-time signal scoring, finding persistence, post-triage
learning, report-lesson retrieval, and exploitability ranking.

## PREREQUISITES

The engine lives at learning_engine/ — pure Python, no external dependencies.

Import snippet:
```python
from learning_engine import LearningEngine
engine = LearningEngine()
```

## INTEGRATION POINTS

1. Before Recon — Load Intelligence: engine.before_recon(target, technologies);
   call after scope parse, before any recon tool runs; retrieves target profile,
   similar targets, historically successful signals; read the plan and
   prioritize high-value surfaces first. ALSO: read memory/report-lessons.md
   before opening processed write-ups — the index is for retrieval only, the
   lesson file is the hunter's distilled memory.

2. During Testing — Score Signals: engine.during_testing(signals); call every
   time a new signal is discovered (endpoint, JS leak, header, etc.); scores
   each signal by historical outcomes; high scores → deep test, low → note and
   move on.

3. After Finding — Persist Memory: engine.after_finding(target=...,
   subdomain=..., ...); call after documenting a finding in notes/; saves to
   learning memory and updates the target profile; ALWAYS call after every
   finding, even low-confidence observations.

3.5) On Strong Lead — Expand Similar Cases: search local write-up + memory
sources for highly similar patterns when a lead looks credible enough for
confirmation or impact expansion; start from memory/report-lessons.md, then
search writeups/index.md by vuln class, mechanism, affected feature, and trust
boundary; read matching processed write-ups only after the lesson pass, before
deciding reportability or final severity.

3.75) During /update — Learn From Reports: convert collected reports into
memory/report-lessons.md plus methodology, patterns, and target checklists; the
agent should learn reusable hunting judgment, not merely accumulate searchable
documents; extract entry point, trust boundary, precondition, bypass, proof
method, false-positive trap, chain opportunity, matching skills, and how the
lesson changes future priority.

4. After Triage — Learn from Feedback: engine.after_triage(finding_id,
   feedback_type, notes, provenance); call when the program responds (accepted,
   duplicate, informative, false_positive); atomically moves the finding,
   records feedback provenance, recalibrates outcomes; reinforce successful
   patterns, penalize noisy ones. Never use session-level outcomes as feedback.

5. Before Summary — Rank by Exploitability: engine.before_summary(findings);
   call before structured-summary-reporting; ranks by historical
   exploitability, accept rate, chain value; present highest-value findings
   first.

## SIGNAL REGISTRY

The engine tracks these signal types by default; weights configurable in
learning_engine/scoring/signals.json:

High value (7-9): graphql_introspection, internal_admin_route,
api_key_exposed, sourcemap_exposed, admin_panel_exposed, pii_in_response,
cross_tenant_access, hidden_api_endpoint, unauthenticated_graphql,
s3_bucket_listed, payment_bypass_candidate, debug_endpoint,
default_credential_candidate, template_injection_hint.

Medium value (4-6): jwt_token_found, oauth_flow_detected, idor_parameter,
mass_assignment_candidate, hidden_graphql_field, ssrf_url_parameter,
prototype_pollution_gadget, race_condition_candidate, unauthenticated_endpoint,
host_header_injection, staging_system, legacy_endpoint, blind_ssrf_candidate,
xml_external_entity.

Low value (1-3): reflected_param_only, stack_trace_exposed, cacheable_sensitive,
open_redirect_param, version_disclosure, rate_limit_missing, cors_wildcard,
cookie_without_flags.

## SCORING AUTO-ESCALATION

The engine automatically boosts scores: cross_tenant +30%, admin_bypass +30%,
state_changing +20%, sensitive_data +20%, auth_bypass +30%, chainable +20%,
payment_impact +30%.

## MEMORY BUCKETS

| Bucket | Purpose | Learning effect |
|---|---|---|
| heuristics/ | Validated signal patterns only — outcome-calibrated tracking | Trains heuristics |
| pending finding state | Initial storage for observations — traceability only | Never trains heuristics |
| accepted/ | Signal reinforced from triage evidence | Reinforce |
| duplicates/ | Signal penalized, pattern refined | Penalize |
| informative/ | Signal weight may reduce | Reduce |
| false_positive/ | Signal penalized, pattern downgraded | Downgrade |
| chains/ | Chain frequency tracked | Track |
| target_profiles/ | Technology/surface/bug class accumulation | Accumulate |

## ANALYTICS

Available after hunts: engine.get_statistics(); get_tuning(); get_heatmap();
get_chains(); rebuild_graph();
engine.analytics.highest_signal_surfaces(limit=10);
engine.analytics.duplicate_heavy_patterns();
engine.analytics.target_summary(target).

## QUICK REFERENCE

Complete python snippet: initialize once at agent start; before_recon(target,
techs) → plan; during_testing(signals) → score; after_finding(target=...,
vulnerability_class=..., signals=...) → f; after_triage(f["id"], "accepted" |
"duplicate" | "informative" | "false_positive", provenance={"source":
"program_triage", "actor": "tester"}); before_summary(all_findings) → ranked;
analytics anytime.

## FILE LOCATIONS

Engine code: learning_engine/; skill file:
.agents/skills/learning-engine-integration/SKILL.md; signal config:
learning_engine/scoring/signals.json; memory source of truth:
learning_engine/memory/learning.db; legacy JSON and .bak folders =
migration/recovery artifacts only; audit: python
learning_engine/scripts/audit_learning_engine.py --report-only; schemas:
learning_engine/schemas/*.json; docs: learning_engine/docs/*.md.

## TESTING REQUIREMENT

After writing this skill, verify the engine contract: run python
learning_engine/scripts/audit_learning_engine.py --report-only and the
learning-engine test suite; confirm all 5 hooks accept and return the
documented shapes and that signal scoring is bounded. Report pass/fail.
