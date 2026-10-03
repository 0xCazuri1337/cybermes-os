# Evidence Requirements

What a finding must carry before it can be reported.

## Required

1. **Two accounts you control**, fully separated, for any authorization claim.
   Reading your own second account proves the boundary is missing without
   involving anyone else.
2. **A disproof clause** — the condition that would prove the claim *wrong*.
   An item with no disproof is a checklist line, not knowledge.
3. **The request/response pair**, not a description of it.
4. **Downstream state evidence** for anything involving timing or a counter:
   the HTTP trace proves the attempt, the resulting state proves the effect.
5. **Quantified scope** limited to what was actually performed. Bulk extraction
   that was not carried out does not go in the report.

## Insufficient on its own

- A `200` without a comparison against a second identity.
- A tool's severity label with no stated basis.
- A screenshot with no reproducible request.
- Behaviour reproduced only on dev/staging, where the hostname is out of scope.

## Boundary

`wks/config.py` carries `RESEARCH_ONLY = True` and `CAN_AUTHORIZE = False`.
This system fetches published documentation; it does not scan, fuzz, or exploit
any target. Active testing requires explicit, user-provided authorization and
lives outside this pipeline.
