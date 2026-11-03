# Learning workspace

The **working area** of the learning loop. Nothing here is canonical knowledge
until it has passed the gate.

## What belongs here

| Directory | Holds |
|---|---|
| `goals/` | the active Goal, its measurable criteria, and current wave |
| `tasks/` | task briefs, one per delegated specialist, with status |
| `evidence/` | raw research output — staging only, never trusted |
| `knowledge/` | findings promoted after review |
| `gaps/` | what the last wave failed to close |

## What does NOT belong here

- Canonical class definitions → `bug-classes/`
- Anything promoted without `wks/ingest.py` verifying every quote against the
  live page

## The loop

```
goals/ → tasks/ → evidence/ → (gate) → db/wks.db → knowledge/ → gaps/ → goals/
```

## Related

- The gate: `validation/validation-gates.md`
- The orchestrator: skill `cyber-learning-orchestrator`
