# references/CONFIG_INDEX.md — Lightweight runtime map (keep SHORT)

## Runtime load order
1. agent-briefing.md
2. AGENTS.md
3. prioritization.md
4. (on demand) AGENT_SKILL_ACTIVATION.md, AGENT_INIT_TEMPLATE, VERIFICATION_CHECKLIST

## Active skill sources
- mirrors: skills/
- runtime copies: .agents/skills/

## Knowledge sources
- report-lessons.md (read first)
- patterns.md, methodology.md, targets/ (guide)
- index.md (retrieval only)

## Command / agent entry points
- .opencode/commands/* (hunt, recon, scan, update, report, dorking, mindmap, understand)
- update pipeline (scripts/update.sh)
- .opencode.json (browser config)

## Scope guardrail
Exact-host scope; no *. fuzzing without approval; stay on supplied target;
others passive context only.

## Target stickiness
Stay until surfaces tested or documented not-applicable with skills loaded.

## Skill gate
Before any test: "What skills does this trigger?" → load matching skills first.

## Target workspace rule
All artifacts under testing/<root>/<subdomain>/ standard folders; never project root.

## Current status
Ready for supervised autonomous hunting.
