# CONTROL/README.md — the control surface

Provenance map: what is authoritative, and where superseded material went.

| File | Role | Mutability |
|---|---|---|
| [`CONTROL.md`](CONTROL.md) | constitution — mission + invariants I1–I10 | changes only when the mission changes |
| [`rules.md`](rules.md) | R1–R19, each stating **how it is checked** | changes when a check changes |
| [`state.md`](state.md) | phase, architecture as built, known defects, next work | changes every run |
| [`OPERATOR.md`](OPERATOR.md) | the command grammar (`Learn X`, `Review X`, …) | changes when the loop changes |

Root [`../CONTROL.md`](../CONTROL.md) is a pointer to this directory. It exists
because the control surface was originally a single file that drifted against a
second copy of itself.

## The split, and why

The two original files each mixed **invariants** with **per-session state**, so
a hunt with a bad day resulted in editing a constitution. A constitution
rewritten each session is not a constitution. Splitting by kind makes the
mutable part obvious and small.

## Precedence

1. `CONTROL.md` (invariants) — nothing may contradict it.
2. `rules.md` — each rule is subordinate and states its check.
3. `OPERATOR.md` — the command grammar.
4. `state.md` — the only mutable file; records current reality.

A conflict is resolved toward the higher layer, and the lower layer is updated.
`state.md` describing a component that no longer exists is a stale claim in the
one file allowed to be stale, and is corrected rather than archived.

## Superseded material

Never deleted (invariant I8). Each entry names the file that replaced it.

| Preserved at | Replaced by |
|---|---|
| [`superseded/CONTROL.md.e2317629.md`](superseded/CONTROL.md.e2317629.md) | `CONTROL.md` — second, conflicting control surface |
| [`superseded/RAG_ARCHITECTURE.md.legacy.md`](superseded/RAG_ARCHITECTURE.md.legacy.md) | [`../RAG_ARCHITECTURE.md`](../RAG_ARCHITECTURE.md) — described `rag_engine.py` / `knowledge_engine`, both removed |
| [`../domains/web/methodology/superseded/METHODOLOGY.md.736a4e9b.md`](../domains/web/methodology/superseded/METHODOLOGY.md.736a4e9b.md) | [`../domains/web/methodology/INDEX.md`](../domains/web/methodology/INDEX.md) |

## Reading order for a new engineer

1. This file — what is authoritative.
2. `CONTROL.md` — the ten invariants and layer ownership.
3. `OPERATOR.md` — how a one-word command becomes a hunt.
4. `../README.md` — the tree, the engine, and the quality gate.
5. `rules.md` — and run the commands it lists; every claim it makes is
   checkable, and a rule with no check is a wish.