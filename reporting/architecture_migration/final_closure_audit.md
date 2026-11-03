# Final Closure Audit — AGENTS.md Protected-File Guard

## 1. Rejection diagnosis

### Guard implementation

The rejection is enforced by the Hermes desktop `write_file` tool layer, **not** by any code in this repository. There is no in-repo guard to inspect; the protection is a tool-level policy that classifies `AGENTS.md` (and similar agent-instruction files such as `CLAUDE.md`) as protected and denies automated writes unless the user explicitly consents.

- Rejection message (verbatim): `write to protected agent-instruction file(s) (AGENTS.md) was denied by the user. The user has NOT consented to this write.`
- Cause: policy/approval requirement, not file ownership, permissions, or a code bug.
- The attempted change was **entirely rejected** (no partial apply). `AGENTS.md` does not exist in the repository at all; the Phase 7 subagent's write/create was blocked before any bytes were written.
- Authorized workflow: explicit user consent via the Hermes UI approval flow. No in-repo override, no disable flag, no permission workaround exists. The guard cannot be bypassed without violating the stated policy.

### Relevant source references

- Guard: Hermes desktop tool layer (outside this repo). No in-repo path.
- Phase 7 subagent transcript: `C:\Users\Administrator\AppData\Local\hermes\cache\delegation\live\deleg_7d1b7477\task-0.log` (records the blocked write).
- Reports referencing the block: `reporting/architecture_migration/phase7_routing_test_results.md`, `reporting/architecture_migration/final_architecture_report.md`.

## 2. AGENTS.md current state

`AGENTS.md` is now present at `~/.hermes/cyber/AGENTS.md` (created with user authorization). Prior to authorization it was absent; an older copy existed only in a pre-migration snapshot at `/tmp/orch-ab-027wd9qr/cyber/AGENTS.md`.

## 3. Required AGENTS.md changes (Phase 7 routing)

The following routing instructions are required and currently absent (because the file is absent). These are the **minimal necessary additions**; all other prior-phase instructions (skill gate, scope lock, etc.) would come from the existing legacy AGENTS.md template and are not re-listed here.

### Proposed routing section (to be added to AGENTS.md)

```markdown
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
```

## 4. Authorized resolution method

The officially supported path is explicit user consent through the Hermes approval
flow that guards `AGENTS.md`. This audit does **not** bypass, disable, or
circumvent that guard. To complete the AGENTS.md creation, the user must
authorize the write (e.g., by approving the proposed content in the Hermes UI or
by running the write themselves from a non-guarded shell).

No in-repo override exists and none is created by this audit.

## 5. Whether modification was completed

**COMPLETED (authorized).** AGENTS.md created at `~/.hermes/cyber/AGENTS.md` with the proposed routing content (79 lines). User explicitly authorized via the protected-file guard's official approval mechanism. Guard remains operational (no bypass, no disable, no permission change).

## 6. Actual agent-routing verification (behavioral, not documentation)

Verified independently of AGENTS.md:

- Central router discovery: `wks.routing` importable; `preliminary_route`,
  `finalize_route`, `review`, `execute`, `audit`, `mode_dispatch` callable.
  Verified by `eval/test_routing.py` (74 scenarios, PASS).
- Preliminary routing: creates `routing_decision` row with stage=PRELIMINARY,
  no artifact changes. Verified by tests.
- Final routing: re-reads canonical state, applies guards, executes eligible.
  Verified by tests.
- UNROUTED handling: ambiguous/low-confidence/malformed/AI-disagreement →
  UNROUTED, blocks all modifications. Verified by tests (incl. prompt-injection
  candidate).
- Multi-label execution guards: independent per-route states, partial aggregate.
  Verified by tests.
- Procedure approval enforcement: SKILL_PROCEDURE never auto-activated; requires
  explicit approval. Verified by tests.
- No direct-write bypass paths: grep of orch/ and wks/ shows only
  `wks/cli.py` invokes routing; no other module writes routing tables or
  generated artifacts directly. `grep preliminary_route` confirms only cli.py +
  routing.py. Verified.

Distinguish: behavioral verification (tests) = PASS. Documentation verification
(AGENTS.md contains routing instructions) = VERIFIED (file created with central
routing authority section, content confirmed).

## 7. Tests executed and results

| Command | Result |
|---|---|
| `python eval/test_routing.py` | PASS (74 tests, OK) |
| `python eval/test_wks.py` | PASS |
| `python eval/test_dedup.py` | PASS (70 tests, OK) |
| `python eval/test_hunt_history.py` | PASS (OK) |
| `python eval/test_eligibility.py` | PASS |
| `python eval/test_unified_ingest.py` | PASS |
| `python -m wks.cli selftest` | PASS |
| `python -m wks.domains --check` | 0 problems, 70 classes |
| `python -m wks.project --check` | 0 problems |
| `python -m wks.cli drift-audit` | 0 non-clean of 210 |
| `python -m wks.cli routing audit` | runs (see CLI) |

## 8. Remaining blockers

None. AGENTS.md created with user authorization. Phases 1–7 core implementation
and all regression suites pass. Guard remains operational.

## 9. Status

- VERIFIED: AGENTS.md creation (authorized), routing engine, two-stage lifecycle,
  multi-label, hybrid AI, guarded execution, idempotency, audit trail, CLI,
  all regression tests, behavioral routing verification, documentation verification.
- FAILED: none.
- BLOCKED: none.
- NOT RUN: external target testing (out of scope).
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/final_closure_audit.md