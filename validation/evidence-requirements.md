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
The `wks/` layer is research-only by construction: it fetches published
documents and curates knowledge, and it holds no authority to authorize
target testing. The `orch/` hunt layer performs active testing when an
authorized hunt is started — explicitly via `python -m orch.cli hunt` or
implicitly when the operator says "start hunt" / "we are hunting" / "begin
hunting" (which triggers `AuthorizationContext` registration) — and it holds
that authority separately, through its own `scope_grant` rows.
