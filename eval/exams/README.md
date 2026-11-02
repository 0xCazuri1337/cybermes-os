# Black-box exams

Each subdirectory is one exam: a generated lab, a solver, and a graded verdict.

| Directory | Class | Lab shape | Outcome |
|---|---|---|---|
| [idor-9091](idor-9091/) | idor | `/rest/workspace/`, cookie auth, `ContosoWeb/2.1` | PASS — closes `transfer` |
| [idor-5150](idor-5150/) | idor | `/api/v2/policy/`, cookie auth, `InternalOps/1.7` | PASS — closes `black_box` |
| [idor-4242](idor-4242/) | idor | `/policy/`, cookie auth | DISQUALIFIED — see `DISQUALIFIED.json` |
| [sqli-909](sqli-909/) | sqli | `/rest/orders/` | FAIL — planted-lab rehearsal, no solver |

## Files

- `card.json` — what the solver is given. Never names the vulnerability.
- `ground_truth.json` — what the lab actually plants. Never served over HTTP.
- `SOLVER_REPORT.md` — the solver's own findings, graded by `eval/grade_exam.py`.
- `GRADE.json` — the verdict, re-derived from the lab rather than from the prose.
- `DISQUALIFIED.json` — present only when a run is permanently ineligible.

Regenerate a lab: `python eval/labforge.py serve CLASS --seed N --port P --card <path>`
Grade a finished exam: `python eval/run_exam.py grade eval/exams/<dir> [gate]`


## Solver reports

These are the graded findings, kept as evidence:

- [idor-9091 SOLVER_REPORT.md](idor-9091/SOLVER_REPORT.md) — the transfer exam
- [idor-5150 SOLVER_REPORT.md](idor-5150/SOLVER_REPORT.md) — the black-box exam
- [sqli-909 SOLVER_REPORT.md](sqli-909/SOLVER_REPORT.md) — a planted-lab rehearsal, not a real solve
