# Next-Generation Cyber Capability Architecture — Design Document

**Status:** DESIGN ONLY. No files modified. Awaiting explicit approval.
**Based on:** Cyber Skills Deep Audit (SKILLS_AUDIT_REPORT.md), inspected corpus (380 SKILL.md, 32 capability dirs, registry, loaders).

## A. Proposed Architecture & Directory Structure

```
cyber/
  skills/
    capabilities/                 # executable capability specs (SKILL.md per capability)
      <capability>/
        SKILL.md                  # contract-compliant spec
        references/               # knowledge pointers (not duplicated)
        tests/                    # capability-level tests
    knowledge/                    # centralized reference material (cheat sheets, payloads)
    workflows/                    # autonomous-hunt, orchestration, reporting, supporting (non-skill)
  domains/                        # generated pointers (not duplicates) -> capabilities
  runtime/
    registry.json                 # generated, validated
  tools/
    audit_refs.py                 # must NOT skip capabilities
```

Key change: separate `knowledge/` (reference material) from `skills/` (executable capability specs). Each capability owns a SKILL.md contract.

## B. Formal Skill Contract Specification

Every SKILL.md MUST contain frontmatter + sections:

Frontmatter:
- name (kebab-case, unique)
- description (<= 60 chars for skill_manage; longer allowed in audit but recommend <= 120)
- version
- status: draft | active | deprecated
- owner: capability group

Required body sections:
1. Purpose & Scope (what it does, what it does NOT do)
2. Activation Conditions (when Hermes should load it)
3. Required Inputs (what context/data it needs)
4. Expected Outputs (structured artifact it produces)
5. Dependencies (other capabilities, tools, env)
6. Execution Procedure (numbered steps)
7. Validation Criteria (how to verify the result)
8. Safety & Authorization Boundaries (scope gate, data handling)
9. Knowledge References (links to knowledge/, not inline dumps)

## C. Capability Inventory & Old-to-Proposed Mapping

Evidence-based grouping (from 380 skills):
- Recon (29) -> capability: recon
- API (35) -> api-investigation
- Web injection (sqli 4, ssrf 4, xss 5, ssti 2, xxe 3, nosqli 2, cmd 2, proto-pollution 1) -> web-injection
- Client-side (cors 3, csrf 2, clickjacking 2, open-redirect 3, host-header 2, html-injection 1) -> client-side
- Auth (identity 18, jwt 5, oauth 14, session) -> auth-investigation
- Business logic (4) + race (2) -> business-logic
- File upload (2), deserialization (2), path-traversal (2) -> file-and-deserialization
- Cloud (26) -> cloud (keep, already coherent)
- Redteam (170) -> split by evidence: cloud-redteam, identity-redteam (AD), network-redteam, web-redteam, ad-redteam
- LLM/AI (11) -> ai-security
- Serverless (3), cache-poisoning (4), request-smuggling (3) -> keep as-is (coherent)
- Offensive-testing (11) -> fold into web-injection / redteam as needed
- Info-disclosure (3) -> fold into recon

## D. Routing & Orchestration Design

- Task -> classifier maps to capability set (primary + supporting).
- Multi-capability chains declared via `dependencies` + `chain` metadata.
- Lazy loading: load only primary capability; pull dependencies on demand.
- Conflict handling: if two capabilities claim same scope, prefer the more specific one; log ambiguity.
- Domain-generated skills (70) become pointers: each domain SKILL.md references the canonical capability SKILL.md path.
- No global load of all 380; load by task classification.

## E. Knowledge Separation Strategy

- Move reference-style content (payload lists, cheat sheets, version tables) to `knowledge/<topic>.md`.
- SKILL.md keeps only procedure + validation + pointers to knowledge/.
- Canonical ownership: one knowledge file per topic; capabilities reference it.
- Prevent drift: knowledge files are the single source; capabilities never duplicate.

## F. Registry & Loader Compatibility Plan

- Extend runtime/registry.json schema to include: name, path, capabilities, triggers, dependencies, version, status.
- Regenerate via scripts/skill_registry.py (existing generator) with new fields.
- Backward compat: keep `skills` array; add `capabilities` array alongside.
- Enable audit_refs.py to audit capabilities (remove skip) once schema stable.
- Versioning: skill version in frontmatter; registry tracks version.

## G. Pilot Capability Specifications

### 1. Recon
- Purpose: discover attack surface (subdomains, tech, endpoints, params).
- Activation: task contains "recon", "enumerate", "discover surface", "scope mapping".
- Inputs: target domain, scope file, auth context.
- Outputs: asset inventory (hosts, tech, endpoints), prioritized surface list.
- Dependencies: none (entry point).
- Procedure: scope check -> subdomain enum -> live host probe -> tech fingerprint -> endpoint discovery -> prioritize.
- Validation: at least one host verified in scope; output artifact saved.
- Safety: scope gate first; no out-of-scope hosts.
- Knowledge refs: knowledge/recon-tools.md, knowledge/dns-wordlists.md.

### 2. API Investigation
- Purpose: discover and test API endpoints for authz/authn/logic flaws.
- Activation: task mentions API, REST, GraphQL, gRPC, endpoints.
- Inputs: base URL, auth tokens, schema (if available).
- Outputs: endpoint inventory, authz test results, findings.
- Dependencies: recon (for endpoint discovery), auth-investigation (for token handling).
- Procedure: discover (spec/crawl) -> map endpoints -> test authn/authz -> test mass assignment/IDOR -> report.
- Validation: each endpoint tested with two accounts; raw request/response captured.
- Safety: only owned accounts; no third-party data.
- Knowledge refs: knowledge/api-payloads.md, knowledge/graphql-introspection.md.

### 3. XSS
- Purpose: detect and validate cross-site scripting.
- Activation: task mentions XSS, reflected/stored/DOM, script injection.
- Inputs: target URL/param, account context, CSP info.
- Outputs: PoC (payload + response evidence), impact assessment.
- Dependencies: client-side (for CSP/frame analysis), auth-investigation (for stored context).
- Procedure: identify reflection points -> context analysis -> payload selection -> validation in browser -> impact assessment.
- Validation: working PoC in real browser; CSP bypass proven if claimed.
- Safety: no third-party data exfiltration; use owned account for stored XSS.
- Knowledge refs: knowledge/xss-payloads.md, knowledge/csp-bypass.md.

### Task Routing Example
User: "Hunt XSS on target.com/api/search"
1. Classifier -> primary: xss; supporting: recon (surface), client-side (CSP).
2. Load xss SKILL.md; pull recon + client-side on demand.
3. Recon outputs endpoint inventory -> xss tests search param.
4. xss outputs PoC -> client-side validates CSP impact.
5. Final finding artifact with evidence.

## H. Test Strategy & Acceptance Criteria

- Static: every SKILL.md has required contract sections; frontmatter valid; unique names.
- Routing: given N representative tasks, classifier selects correct primary capability (accuracy >= 90%).
- Capability execution: each pilot capability runs end-to-end on a test target producing expected artifact.
- Multi-capability integration: chain test (recon -> api -> xss) produces coherent findings.
- Regression: registry refs all resolve after changes; audit_refs clean.
- Evidence quality: every finding has raw request/response + two-account proof.

Acceptance criteria (measurable):
- 100% SKILL.md contract compliance.
- 0 broken registry refs.
- Routing accuracy >= 90% on 50-task test set.
- All 3 pilots produce valid artifacts on a lab target.
- No duplicate knowledge (single canonical per topic).

## I. Phased Migration Plan (with rollback)

Phase 0: Backup (already done: skills.pre-refactor-*). Keep until validated.
Phase 1: Define contract + schema. Validate all 380 (static only, no moves).
Phase 2: Split redteam into 5 groups (move skill dirs, update registry, update manifest). Rollback: restore from backup.
Phase 3: Fold narrow capabilities. Update registry.
Phase 4: Separate knowledge/ (move reference content, update pointers).
Phase 5: Convert domains/ to pointers.
Phase 6: Add tests (routing, capability, integration).
Phase 7: Enable audit_refs on capabilities; fix findings.
Each phase: run wks selftest + registry regen + audit_refs before proceeding. Stop on failure.

## J. Risk Assessment & Unresolved Decisions

Risks:
- Redteam split may break existing skill paths referenced by agents/manifest.
- Knowledge separation may lose provenance if not careful.
- No git baseline -> rollback relies on tarball backups.
- Hermes loader behavior with new schema unknown (needs testing).

Unresolved:
- Should `knowledge/` be per-capability or centralized? (Recommend centralized with pointers.)
- Should domains/ be removed entirely or kept as pointers? (Recommend pointers for backward compat.)
- What is the minimum viable capability count? (Do not optimize for count; optimize for cohesion.)

---

*Design only. No files modified. Awaiting explicit approval before any implementation.*
"