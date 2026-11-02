# references/MASTER_CONFIG.md — Complete agent system overview

## System architecture

Configuration files in load order:
1. agent-briefing.md (read first every session)
2. AGENTS.md (constitution — wins on conflict)
3. prioritization.md (signal engine P1-P4)
4. AGENT_SKILL_ACTIVATION.md (on demand)
5. AGENT_INIT_TEMPLATE (on demand)
6. VERIFICATION_CHECKLIST (audit)

Skill sources:
- skills/ (mirrors)
- .agents/skills/ (active runtime copies)
- learning-engine-integration (mandatory every hunt)

Working directory tree:
testing/<root-domain>/<subdomain>/ with the 11 standard artifact folders
(notes, requests, responses, screenshots, scripts, scans, wordlists, urls,
subdomains, evidence, reports).

## Execution flow

Phase 1 BOOT (<5 min): briefing → foundations → scope lock → fingerprint →
prior-history → bootstrap → ready.

Phase 2 DISCOVERY↔EXPLOIT interleaved.

Phase 3 DEEP EXPLOIT (bypass ladder, response-diff).

Phase 4 REPORT gated.

## When to debug structure

This file is the overview; load only when debugging the architecture.
