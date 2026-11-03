# Phase 6 — Conflict Analysis

## Contradiction detection

Potential contradictions identified via:
- Negation polarity mismatch (one claim asserts, other denies) under identical scope/version/preconditions.
- Opposing outcomes under identical conditions.
- Conflicting disproof evidence.

## Protection rules

- High similarity score never overrides contradiction indicator.
- Potential contradictions → POTENTIAL_CONTRADICTION relationship, never merged.
- Submitted to existing conflict workflow or linked conflict proposal.
- Both original claims, validation states, source sets, evidence, disproofs, scope/environment preserved.
- No automatic rejection of either side.
- No automatic marking as disputed unless existing gate justifies.

## Context-dependent vs contradictory

- Different versions/contexts → CONTEXT_DEPENDENT (not contradiction, not merged).
- Conditional success vs unconditional failure under different conditions → CONTEXT_DEPENDENT.
- Only identical conditions with opposing assertions → POTENTIAL_CONTRADICTION.

## Uncertainty handling

- When classification is ambiguous → UNCERTAIN, requires review.
- Safe default: preserve both records, do not merge.

## Results

- Open conflicts (pre-existing): 13.
- Potential contradiction proposals generated: see audit output.
- No contradictions merged during this phase.
path: C:/Users/Administrator/.hermes/cyber/reporting/architecture_migration/phase6_conflict_analysis.md