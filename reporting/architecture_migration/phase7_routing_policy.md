# Phase 7 — Routing Policy

## Update-kind registry

| Kind | Auto-apply? | Guard |
|---|---|---|
| KNOWLEDGE | Yes, after WKS gate | Quality gate + eligibility |
| ATTACK_CHAIN | Yes, after chain validation | Eligible items only, ordering valid |
| FP_RULE | Yes, after FP validation | Reusable, evidence recorded, no duplicate |
| SKILL_PROCEDURE | No — approval required | Eval + tests + HISTORY + explicit approval |
| NO_CHANGE | N/A (no mutation) | Recorded with reason |
| CONFLICT | N/A (preserve both) | Existing conflict workflow |
| UNROUTED | N/A (block all) | Preserve candidate + alternatives |

## Hybrid classification

- Deterministic rules engine is authoritative.
- AI suggestions are advisory only; never authorize, never bypass policy, never execute.
- AI unavailable → deterministic for unambiguous cases; ambiguous → UNROUTED.
- AI/deterministic material disagreement → UNROUTED or review.

## Two-stage lifecycle

- Stage 1 (Preliminary): at intake, classify + record confidence/alternatives/missing evidence. No artifact changes.
- Stage 2 (Final): after validation, re-evaluate, confirm routes, execute eligible, queue approval-required, record outcomes.

## Multi-label

- One candidate may produce multiple independent routes. Each has own execution state. Aggregate status reflects partial completion. One failed route does not erase others.

## Idempotency

- Stable candidate-to-route identity. Repeated preliminary/final routing detected. No duplicate side effects. Reconciliation + rollback where needed.

## Audit

- Every decision recorded (success, failure, pending, rejected, NO_CHANGE, UNROUTED, CONFLICT, approval, execution failure, rollback). Append-only. No secrets in logs.
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase7_routing_policy.md