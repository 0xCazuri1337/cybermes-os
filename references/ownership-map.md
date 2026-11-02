# references/ownership-map.md — File governance & responsibility

## Core principle
Shared files are immutable; runtime files are orchestration-only; no duplication.

## Table 1 — Shared knowledge (immutable, root level)
| File | Owner | Purpose | Modification policy |
|---|---|---|---|
| agent-briefing.md | /update pipeline | Session briefing | Updated via /update only |
| AGENTS.md | Human | Constitution | DO NOT MODIFY |
| prioritization.md | Human | Signal engine | DO NOT MODIFY |
| master-bugbounty-rules | Human | Foundation skill | DO NOT MODIFY |
| learning-engine-integration | Human | Adaptive learning skill | DO NOT MODIFY |
| runtime templates | Reference only | Templates | Reference only |

## Table 2 — Shared knowledge subdirectories (append-only)
| Directory | Owner | Purpose | Modification policy |
|---|---|---|---|
| skills/ | Human + /update | Skill mirrors | Update via /update pipeline |
| memory/ (methodology, patterns, report-lessons, targets) | /update + agent | Knowledge base | Append-only; regenerate on new classes |
| writeups/ (index, processed, raw) | /update pipeline | Evidence repo | Regenerate on new classes |
| learning_engine/ | Human | Engine code | Coordinated changes only |

## Table 3 — Runtime configuration (lightweight orchestration)
| Directory | Owner | Purpose | Modification policy |
|---|---|---|---|
| runtime/opencode/ (loader, manifest, ORCHESTRATION, agents) | Orchestrator | Orchestration-only | Coordinated changes only |
| .opencode/commands/ | Human | Command definitions | Coordinated changes only |

## Table 4 — Target workspace
| Directory | Owner | Purpose | Modification policy |
|---|---|---|---|
| testing/ | Hunting agent | Per-target artifacts | No governance review needed |
