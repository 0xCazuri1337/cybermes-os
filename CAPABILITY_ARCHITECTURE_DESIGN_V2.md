# Revised Next-Generation Cyber Capability Architecture — Design Document

**Status:** DESIGN ONLY. No files modified. Awaiting explicit approval.
**Revision:** addresses 10 architectural requirements from review.

## 1. Artifact Classification (not all 380 become capabilities)

Each of the 380 SKILL.md files must be classified into ONE of five artifact types:

| Type | Definition | Count (estimated) | Location |
|---|---|---|---|
| Executable Capability | Has activation, inputs, outputs, procedure, validation | ~120 | skills/capabilities/ |
| Knowledge Resource | Reference material, payload lists, cheat sheets | ~140 | knowledge/ |
| Procedure | Step-by-step how-to without I/O contract | ~60 | procedures/ |
| Workflow | Multi-step orchestration (autonomous-hunt, reporting) | ~10 | workflows/ |
| Tool Integration | Wrapper for external tool (nmap, sqlmap) | ~50 | tools/ |

Classification must be evidence-based: a SKILL.md with frontmatter only is NOT automatically an Executable Capability.

## 2. Capability Independence (no forced merging)

Vulnerability classes remain independently executable:
- xss, sqli, ssrf, ssti, xxe, nosqli, cmd-injection, prototype-pollution, path-traversal, file-upload, deserialization, csrf, cors, clickjacking, open-redirect, host-header, html-injection, cache-poisoning, request-smuggling, race-conditions, business-logic, idor, mass-assignment, oauth, jwt, graphql, grpc, websocket, etc.

Higher-level COORDINATORS compose them:
- `web-injection-coordinator`: orchestrates sqli/ssrf/ssti/xxe/nosqli/cmd based on surface signals.
- `client-side-coordinator`: orchestrates xss/csrf/cors/clickjacking/open-redirect.
- `auth-coordinator`: orchestrates authn/authz/jwt/oauth/session.
- `api-coordinator`: orchestrates api/authz/mass-assignment/graphql.

Coordinators do not replace capabilities; they compose them.

## 3. Routing & Orchestration Layer

Dedicated layer (not embedded in skills):
- **Intent Classifier**: maps user task -> intent category (recon, hunt, validate, report).
- **Context Classifier**: extracts target type, tech stack, scope, auth context.
- **Capability Selector**: selects primary + supporting capabilities from registry based on intent + context.
- **Dependency Resolver**: resolves capability dependencies (e.g., xss depends on client-side + auth).
- **Execution Planner**: orders capabilities (recon first, then hunt, then validate).
- **Handoff Manager**: structured output from one capability feeds next (artifact passing).
- **Retry/Reassessment**: on failure or weak evidence, reassess and try alternate capability.
- **Duplicate-Work Prevention**: tested-variant ledger per surface; skip already-tested variants.
- **Evidence Propagation**: findings accumulate evidence across capability chain.

## 4. Hybrid Knowledge Architecture

Four tiers:
1. **Shared Canonical Knowledge** (`knowledge/shared/`): payloads, wordlists, tool refs — single source.
2. **Domain-Specific Knowledge** (`knowledge/domains/web/`, `knowledge/domains/api/`, etc.): domain context.
3. **Capability-Specific References** (`skills/capabilities/<cap>/references/`): pointers to shared/domain knowledge, plus capability-specific notes.
4. **No duplicated canonical content**: capabilities reference shared knowledge by path; never copy.

## 5. Domain-Generated Skills Audit

The 70 domain skills (`domains/web/*/skills/SKILL.md`, `domains/network/*/skills/SKILL.md`) must be audited for actual runtime role:
- Are they loaded by Hermes? (check external_dirs + loader)
- Do they contain unique content vs capabilities?
- Are they generated (projections of DB) or hand-written?

Decision (pending audit): if they are pure projections of capabilities with no unique content, convert to pointers. If they contain unique domain context, merge that context into knowledge/domains/ and make SKILL.md a pointer. Do NOT delete without verifying no runtime dependency.

## 6. Separate Contracts Per Artifact Type

Each artifact type has its own schema:

**Executable Capability (SKILL.md):**
- name, description, version, status
- purpose, scope, activation_conditions
- required_inputs, expected_outputs
- dependencies, execution_procedure, validation_criteria
- safety_boundaries, knowledge_refs

**Knowledge Resource (knowledge/*.md):**
- title, topic, scope, last_updated
- content (reference material)
- canonical_owner (capability or domain)
- consumers (list of capabilities that reference it)

**Procedure (procedures/*.md):**
- name, purpose, steps, preconditions, expected_result
- no I/O contract (lighter than capability)

**Workflow (workflows/*.md):**
- name, trigger, stages, stage_dependencies, handoff_format, exit_conditions

**Tool Integration (tools/*.md):**
- tool_name, invocation, inputs, outputs, error_handling, safety_notes

## 7. Expanded Pilot Design (Recon, API Investigation, XSS)

### Recon
- Routing scenarios: "enumerate target.com", "discover API endpoints", "scope mapping"
- Handoffs: outputs asset inventory (JSON) -> consumed by API/XSS/other capabilities
- Expected artifacts: host list, tech stack, endpoint list, prioritized surface
- Negative cases: out-of-scope host -> stop + log; no live hosts -> report empty + suggest alternatives
- Measurable tests: on authorized lab target, verify host count >= 1, endpoints discovered, all in scope

### API Investigation
- Routing scenarios: "test API auth", "find IDOR in /api/users", "GraphQL security"
- Handoffs: receives endpoint list from recon; outputs findings with raw request/response
- Expected artifacts: endpoint inventory, authz test matrix, finding reports
- Negative cases: no auth token -> request from user; non-API target -> redirect to web-injection
- Measurable tests: two-account authz comparison produces clear allow/deny matrix

### XSS
- Routing scenarios: "find XSS in search", "stored XSS in comments"
- Handoffs: receives surface from recon; outputs PoC with browser evidence
- Expected artifacts: reflection points, validated PoC, impact assessment
- Negative cases: no reflection -> report clean; CSP blocks -> report blocked + bypass hypothesis
- Measurable tests: PoC renders in real browser on lab target; evidence captured

## 8. Hermes / WKS Integration

- **Hermes loader**: discovers skills via external_dirs. Must verify new structure (capabilities/, knowledge/, procedures/, workflows/, tools/) is registered.
- **Registry**: runtime/registry.json generated by scripts/skill_registry.py. Must be extended with artifact_type field.
- **WKS knowledge system**: wks.domains, wks.cli, knowledge_engine. Must verify knowledge/ integration doesn't conflict with WKS knowledge dirs.
- **audit_refs.py**: currently skips capabilities; must be updated to audit internal refs once schema stable.
- Do NOT assume compatibility; test each integration point.

## 9. Migration Invariants

1. No data loss: every SKILL.md content preserved (move, not delete).
2. No provenance loss: source references and metadata retained.
3. No broken references: registry, manifest, skill_registry.py updated atomically per phase.
4. No silent fallback: if a capability fails to load, error explicitly (no silent skip).
5. No unverified capability promotion: new/migrated capabilities start as Proposed, pass gates to become Active.
6. Rollback after every phase: backup restored if validation fails.

## 10. Promotion Lifecycle

States: Proposed -> Validated -> Active -> Deprecated.

Quality gates to promote:
- Proposed -> Validated: contract compliance (all required sections), static validation pass, registry entry valid.
- Validated -> Active: routing test passes (>= 90% accuracy), capability execution test passes on lab target, no broken refs.
- Active -> Deprecated: replacement exists and is Active; deprecation notice in SKILL.md.

No capability may be Active without passing all gates. New/migrated capabilities start at Proposed.

---

## Deliverables Summary

A. Architecture: capabilities/ + knowledge/ + procedures/ + workflows/ + tools/ + coordinators.
B. Contracts: 5 separate schemas (capability, knowledge, procedure, workflow, tool).
C. Taxonomy: 5 artifact types, evidence-based classification.
D. Routing: dedicated orchestration layer with 9 functions.
E. Knowledge: 4-tier hybrid, no duplication.
F. Registry: extended schema, backward-compatible.
G. Pilots: recon, API, XSS with routing scenarios, handoffs, artifacts, negative cases, tests.
H. Tests: static, routing, capability, integration, regression, evidence quality.
I. Migration: 7 phases, invariants, rollback per phase.
J. Risks: loader compat, redteam split, knowledge drift, no-git baseline.

---

*Design only. No files modified. Awaiting explicit approval before any implementation.*
"