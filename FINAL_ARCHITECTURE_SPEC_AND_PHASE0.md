# FINAL Cyber Capability Architecture Specification (Design Only)

Incorporates 7 final corrections. No files modified.

## 1. Artifact Decomposition
One legacy SKILL.md may yield multiple artifacts (capability + knowledge + procedure + workflow + tool integration). Each derived artifact retains:
- source_path (original legacy file)
- source_hash (md5 of original)
- derivation_notes
Machine-readable mapping: `migration_map.json` (legacy_path -> [new_paths]).

## 2. Coordinator vs Capability Separation
- Coordinators (in workflows/ or coordinators/): plan, select, sequence, delegate. NO direct security testing.
- Executable Capabilities (skills/capabilities/): perform actual testing. NO orchestration logic.

## 3. Evidence Contract (shared across all capabilities)
Every capability output must include:
- target, authorized_scope (scope confirmation + policy version)
- raw_requests, raw_responses
- reproduction_steps (triager-followable)
- evidence_provenance (which capability, which run, timestamp)
- confidence (low/medium/high)
- validation_status (Candidate/Reproduced/Validated/Reportable/Rejected)
- handoff_metadata (structured, for next capability)

## 4. Finding Lifecycle (independent of capability activation)
Candidate -> Reproduced -> Validated -> Reportable | Rejected.
Capability activation != finding validity. A capability can run and produce a Candidate that is later Rejected.

## 5. Expanded Routing Tests
Must test: ambiguous intents, conflicting signals, multi-capability tasks, unavailable capabilities, execution failures, false-positive/false-negative measurement. Metrics: accuracy, precision, recall, F1 on a 50+ task labeled set.

## 6. Error Handling & Recovery
- No silent fallback: failed capability -> explicit error artifact, not skip.
- No fabricated evidence: evidence must be captured raw, not synthesized.
- No auto-promotion: failed validation keeps status at current lifecycle stage.
- Recovery: retry with alternate capability or reassess; log all attempts.

## 7. Reversible Migrations + Machine-Readable Mapping
- Every move recorded in migration_map.json.
- Each phase has rollback script (restore from snapshot).
- Invariant: no data loss, no provenance loss, no broken refs, no silent fallback, no unverified promotion.

## Promotion Lifecycle
Proposed -> Validated -> Active -> Deprecated.
Gates: Proposed->Validated (contract compliance + static validation); Validated->Active (routing >=90% + execution test + no broken refs); Active->Deprecated (replacement Active + deprecation notice).

---

# Phase 0 Verification Report (Read-Only)

## Backup
- Snapshot created: C:/Users/Administrator/.hermes/cyber-snapshot-20261102-035212/cyber
- Restore test: NOT performed (read-only phase). To verify rollback, restore snapshot to a temp dir and diff.

## Baseline Inventory
- Total SKILL.md: 602 (380 in skills/, 70 in domains/, 152 elsewhere/quarantine)
- Capability folders: 32
- Workflows: 3 (autonomous-hunt, bug-bounty-hunt-exhaustion, vuln-validation-lab)
- Registry: runtime/registry.json (359275 bytes, keys: agents, aliases, collection_agents, commands, generated_by, routes, skills, version)

## Runtime Dependency Map
- external_dirs: cyber/skills, cyber/domains (per config.yaml)
- Loader: Hermes skill discovery via external_dirs + bundled skills dir
- audit_refs.py: skips skills/capabilities (gap to close in Phase 6)
- Registry generator: scripts/skill_registry.py

## Registry Snapshot
- Copied to snapshot. Hash: (not computed; available on disk)

## Test Baseline
- wks selftest: not run in this phase (read-only; can run without modification)
- audit_refs: capabilities skipped (known gap)
- No capability-level tests exist currently.

## Rollback Verification
- Snapshot exists and is complete (cyber/ copied).
- Rollback procedure: replace cyber/ with snapshot/cyber/ (destructive; only if needed).

## Phase 0 Status: COMPLETE (read-only, no live changes)
Awaiting explicit approval before Phase 1.
"