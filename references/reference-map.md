# references/reference-map.md — Cross-file dependencies & routing

## Reference conventions
- ../FILE.md = project root
- FILE.md = same directory
- ../ = up one level

## File cross-reference matrix

| File | Purpose | Referenced BY | References TO |
|---|---|---|---|
| agent-briefing.md | Session briefing | AGENTS.md, commands, loader | AGENTS.md, prioritization.md |
| AGENTS.md | Constitution | agent-briefing, commands, loader | prioritization.md, registry.json |
| prioritization.md | Signal engine | AGENTS.md, agent-briefing, commands | AGENTS.md |
| ORCHESTRATION.md | Multi-agent manual | loader, manifest, commands | AGENTS.md, prioritization.md, registry.json |
| loader.md | Boot loader | ORCHESTRATION.md, manifest | agent-briefing, AGENTS.md, prioritization.md |
| manifest.md | Runtime manifest | loader | registry.json, ORCHESTRATION.md, agent-briefing |
| skill-router.md | Trigger map | ORCHESTRATION.md, commands | registry.json, skill_registry.py |
| registry.json | Canonical registry | ORCHESTRATION.md, manifest, skill_router | — |
| skill_registry.py | Resolver | skill-router, commands, loader | registry.json |
| runtime_preflight.py | Boot gate | loader, commands | — |
| master-bugbounty-rules | Foundation skill | loader, commands, AGENTS.md | — |
| learning-engine-integration | Adaptive learning skill | loader, commands | learning_engine/ |
| memory/ | Knowledge base | AGENTS.md, agent-briefing, commands | — |
| writeups/ | Evidence repo | agent-briefing, commands, /update | — |
| .opencode/commands/* | Command definitions | loader, manifest | AGENTS.md, prioritization.md, agent-briefing |

## Dependency note

The resolver (scripts/skill_registry.py) and registry (runtime/registry.json) are
the hub. Every reference must resolve to an existing path — run a link check
and report any broken references found.
