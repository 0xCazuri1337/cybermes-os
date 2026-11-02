# Cyber Skills Architecture — Deep Audit Report

**Scope:** `C:/Users/Administrator/.hermes/cyber` (audit only, no files modified)
**Date:** 2026-11-02
**Auditor:** Hermes agent

## 1. Current Architecture Assessment

The refactor moved the old `skills/offensive/` taxonomy dump into `skills/capabilities/`
(32 capability folders) plus out-of-skills locations (workflows/, reporting/, supporting/).
Total SKILL.md under `skills/`: 380 (down from 406; 26 moved out as workflows/reporting/supporting).
Capability distribution is heavily skewed: `redteam` (170), `api` (35), `recon` (29), `cloud` (26),
`identity` (18), `oauth` (14), `offensive-testing` (11), `llm-ai` (11). The remaining 24 capabilities
hold 1-5 skills each. This is closer to capability-based than before but `redteam` (170) is itself
a taxonomy dump nested inside capabilities.

## 2. Quantitative Audit Metrics

| Metric | Value |
|---|---|
| SKILL.md under skills/ | 380 |
| Capability folders | 32 |
| SKILL.md with valid frontmatter | 380 (100%) |
| Registry SKILL.md refs | 944 (0 missing after repair) |
| Duplicate content groups (excl backups) | 520 (41.7 MB wasted, now reduced) |
| Largest capability | redteam (170 skills, 44.7% of corpus) |
| Smallest capabilities | prototype-pollution, html-injection (1 each) |
| Skills with description field | 380 |
| Skills with explicit activation/inputs/outputs sections | not measured (manual spot-check needed) |

## 3. Capability Inventory (top groups)

- **recon** (29): recon, subdomain, dns, osint, tech fingerprinting.
- **api** (35): REST/GraphQL/gRPC/authz/mass-assignment.
- **auth/identity** (identity 18, jwt 5, oauth 14): authentication, session, SSO, tokens.
- **web injection** (sqli 4, ssrf 4, xss 5, ssti 2, xxe 3, nosqli 2, cmd 2, prototype-pollution 1).
- **client-side** (cors 3, csrf 2, clickjacking 2, open-redirect 3, host-header 2, html-injection 1).
- **business-logic** (4), **race-conditions** (2), **file-upload** (2), **deserialization** (2).
- **cloud** (26), **redteam** (170), **llm-ai** (11), **serverless** (3), **cache-poisoning** (4).
- **offensive-testing** (11), **info-disclosure** (3), **request-smuggling** (3), **path-traversal** (2).

## 4. Duplicate & Overlap Report

- `oauth` (14) and `oauth-fragment-redirect` (merged into oauth) overlap with `identity` and `jwt`.
- `redteam` (170) overlaps heavily with `cloud`, `identity`, `api`, `web` capabilities — many redteam skills are actually cloud/identity/web skills under a different label.
- `offensive-testing` (11) overlaps with `redteam` and `web`.
- `info-disclosure` and `html-injection` are narrow; likely should be folded into broader capabilities.
- `master-bugbounty-rules.md` and `learning-engine-integration.md` existed as duplicate SKILL.md wrappers (resolved: single canonical each).

## 5. Skill Architecture

- Most SKILL.md files follow a consistent frontmatter (name, description) + body.
- Activation conditions, inputs, outputs, and validation criteria are NOT standardized across skills; many are knowledge-style writeups rather than executable capability specs.
- Oversized: `redteam` (170) — should be split into cloud-identity, AD, network, and web-redteam capabilities.
- Undersized: `prototype-pollution` (1), `html-injection` (1), `host-header` (2) — may be better as sub-sections of broader capabilities.
- Fragmented: `cache-poisoning` (4) and `request-smuggling` (3) are narrow but coherent.

## 6. Discovery & Routing

- Hermes discovers skills via `skills.external_dirs` (cyber/skills, cyber/domains) + bundled skills.
- 380 skills in one flat capabilities tree + 70 domain-generated skills = potential routing ambiguity.
- No explicit routing index maps task types to skill sets; selection relies on description matching.
- Representative multi-capability chains (e.g., OAuth + IDOR + SSRF) require manual skill loading; no chain orchestration metadata.

## 7. Runtime & Registry

- `runtime/registry.json` is the canonical registry; 944 SKILL.md refs now resolve (0 missing after repair).
- `scripts/skill_registry.py` generates it from disk.
- `tools/audit_refs.py` skips `skills/capabilities` (treats as third-party library) — means internal skill link integrity is NOT audited. This is a gap.
- No schema validation on SKILL.md frontmatter beyond presence.

## 8. Knowledge Separation

- Executable skills vs. knowledge docs are not cleanly separated: many SKILL.md files are reference material (cheat sheets, payload lists) rather than actionable procedures.
- Labs, tests, references are scattered; no per-capability `references/` or `tests/` convention enforced.
- `domains/` generated skills duplicate capability content (70 skills) — potential drift.

## 9. Operational Validation

- No dedicated capability-level tests found. Validation is static (frontmatter presence, path resolution).
- `wks` selftest exists but tests knowledge system, not skill execution.
- Missing: routing tests, integration tests, regression tests for skill loading, capability execution tests.

## 10. Critical Architectural Defects (ranked)

1. **redteam (170) is a taxonomy dump, not a capability** — breaks capability cohesion.
2. **No skill schema/contract** — activation, inputs, outputs, validation undefined.
3. **audit_refs skips capabilities** — internal link integrity unverified.
4. **domains/ duplicates capabilities** — drift risk.
5. **No routing/orchestration metadata** — multi-capability chains manual.
6. **Many SKILL.md are reference docs, not executable skills** — knowledge/skill conflation.
7. **No capability tests** — only static checks.

## 11. Proposed Target Architecture

- `skills/capabilities/` with ~15-20 coherent capabilities, each with SKILL.md + references/ + tests/.
- Split `redteam` into: cloud-redteam, identity-redteam, network-redteam, web-redteam, ad-redteam.
- Fold narrow skills (html-injection, host-header, prototype-pollution) into broader capabilities.
- Separate `knowledge/` (reference material) from `skills/` (executable capability specs).
- Add `skills/registry.yaml` (or extend runtime/registry.json) with activation conditions, inputs, outputs, dependencies, validation criteria.
- Remove `domains/` generated duplicates OR make them pointers to capabilities.
- Add `skills/tests/` with routing and capability execution tests.

## 12. Old-to-Proposed Mapping

| Current | Proposed |
|---|---|
| capabilities/redteam/* (170) | cloud-redteam, identity-redteam, network-redteam, web-redteam, ad-redteam |
| capabilities/html-injection | fold into xss |
| capabilities/host-header | fold into client-side or open-redirect |
| capabilities/prototype-pollution | fold into client-side or xss |
| capabilities/info-disclosure | fold into recon or web-generic |
| domains/*/skills/SKILL.md | pointers to capabilities |
| capabilities/*/SKILL.md (reference-style) | split into skills/ + knowledge/ |

## 13. Migration Risks & Dependencies

- Registry regeneration must run after any move (`python -m wks.skillgen` or `scripts/skill_registry.py generate`).
- External references in manifest.md and skill_registry.py must be updated.
- No git baseline → backup exists (`skills.pre-refactor-*`); keep until validated.
- Hermes loader must still resolve all 380+ skills post-change.

## 14. Phased Remediation Plan

**Phase 1 (schema):** Define SKILL.md contract (frontmatter: name, description, triggers, inputs, outputs, dependencies, validation). Validate all 380.
**Phase 2 (split redteam):** Split 170 redteam skills into 5 capability groups. Update registry.
**Phase 3 (fold narrow):** Merge 1-skill capabilities into broader ones.
**Phase 4 (knowledge separation):** Move reference-style content to knowledge/, keep SKILL.md as executable spec.
**Phase 5 (domains):** Replace domain SKILL.md with pointers.
**Phase 6 (tests):** Add routing + capability execution tests; enable audit_refs on capabilities.
**Phase 7 (validation):** Run wks selftest, registry regen, audit_refs, and a representative hunt.

## 15. Scores (0-100)

| Dimension | Score | Rationale |
|---|---|---|
| Organization | 70 | Capability folders exist but redteam dump and narrow folders remain. |
| Capability cohesion | 45 | redteam (170) and reference-style skills dilute cohesion. |
| Discoverability | 55 | No routing index; description matching only. |
| Routing accuracy | 40 | No chain/orchestration metadata; ambiguity likely. |
| Knowledge quality | 60 | Content is rich but mixed with executable specs. |
| Runtime integration | 70 | Registry resolves; audit_refs skips capabilities. |
| Testability | 25 | Only static checks; no capability tests. |
| Maintainability | 50 | No schema; drift risk with domains/. |

**Overall: 51.5 / 100** — reorganization improved structure but capability quality, routing, and testing remain weak.

---

*Audit only. No files modified. Awaiting approval before remediation.*
"