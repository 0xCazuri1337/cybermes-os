# AGENTS.md — Cyber Hunting Knowledge System

Root: `~/.hermes/cyber`. All paths below are relative to this root.

## CENTRAL ROUTING AUTHORITY

`wks/routing.py` is the sole routing authority for every update entering the system.
All agents and acquisition channels must call `preliminary_route()` on intake and
`finalize_route()` after validation. No agent may invent alternative routing logic.

### Update kinds

KNOWLEDGE, ATTACK_CHAIN, FP_RULE, SKILL_PROCEDURE, NO_CHANGE, CONFLICT, UNROUTED.

### Two-stage lifecycle

- Preliminary routing: at intake. Classifies, records confidence/alternatives/missing
  evidence. Performs NO artifact changes.
- Final routing: after validation. Re-evaluates, confirms routes, executes eligible
  ones, queues approval-required ones, records outcomes.

### Multi-label routing

One candidate may yield multiple independent routes. Each route has its own
execution state. Aggregate status reflects partial completion. One failed route
must not erase or falsely report success for other valid routes.

### Hybrid classification

Deterministic rules are authoritative. AI suggestions are advisory only; they
never authorize, bypass policy, or execute. Material disagreement between AI
and rules → UNROUTED or review. AI unavailable → deterministic for unambiguous
cases; ambiguous → UNROUTED.

### UNROUTED

When confidence is insufficient or the destination cannot be determined safely:
mark UNROUTED, preserve the candidate, record alternatives and reasons, block
all automatic modifications, require review. Never guess a destination.

### NO_CHANGE / CONFLICT

- NO_CHANGE: record classification and reason; perform no modification.
- CONFLICT: preserve both claims, link records, preserve validation states
  independently, use existing conflict workflow. Never resolve by similarity alone.

### Per-kind execution policies

- KNOWLEDGE: automatic only after WKS quality gate + eligibility + provenance.
- ATTACK_CHAIN: automatic only after chain validation (eligible items, ordering).
- FP_RULE: automatic only after FP validation + reusable evidence.
- SKILL_PROCEDURE: proposal only; requires eval + regression tests + HISTORY diff
  + explicit approval before activation. Never auto-activated.
- NO_CHANGE / CONFLICT / UNROUTED: no mutation.

### Direct-write prohibitions

- No direct writes to CLASS.md, DIGEST.md, SKILL.md, or any generated artifact.
- No direct validation_state modifications outside WKS authorized mechanisms.
- No direct knowledge promotion from ORCH or any agent.

### Audit

Every routing decision is recorded in `routing_decision` / `route` tables
(append-only). Includes preliminary and final stages, reasons, alternatives,
confidence, before/after hashes, execution status, approval references.

## ORCHESTRATION ENTRY POINT (OMH)

OMH (oh-my-hermes) is the main orchestration layer. Cyber remains the security-domain
authority (authorization, scope, evidence gate, knowledge validity, mastery, finding gate).
OMH never becomes the authority; every OMH result is a CLAIM, never a verdict.

Entry point: `python -m orch.omh_cli` (run with `PYTHONPATH=~/.hermes/cyber`).

Subcommands:
- `brief <task>` — Cyber → OMH mission contract
- `lanes` — derive parallel lanes
- `authz` — Phase 8 hard authorization gate
- `gap <class_id>` — what is missing for a class
- `research <class_id>` — write a research intake file
- `unknown` — open both paths (Phase 9)
- `refuted` — failure → learning (Phase 10)
- `loop` — loop control (Phase 13)
- `qa` — adversarial verification (Phase 15)
- `report` — integration status

Adapter module: `orch/omh.py` (thin adapters only; no duplicated mechanisms).
OMH primitives are reachable from Cyber and Cyber state is translatable to OMH work contracts.
All OMH results flow back through Cyber's own gate (claim → gate → verdict).

## ARCHITECTURE INVARIANTS

- `skills/` is the sole active Skills root (70 bug classes).
- `knowledge/` is the sole knowledge-acquisition root.
- `db/wks.db` is the canonical knowledge store.
- `wks/unified_ingest.py` is the single ingestion entry point.
- `wks/eligibility.py` governs AUTHORITATIVE / INVESTIGATION / HISTORICAL retrieval.
- `wks/dedup.py` handles duplicate detection and merge proposals.
- `orch/hunt_history.py` owns durable hunt sessions.
- Quarantine and superseded are preserved and excluded from active reads.
- Quality gate (10 dimensions, 15 blocking tags) is unchanged.
- ORCH performs active testing only under explicit authorization.
path: C:/Users/Administrator/.hermes/cyber/AGENTS.md