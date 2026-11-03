# WKS Ingest Repair Report

## Exact root cause
`wks/ingest.py` lines 132-173: the `if v == "FABRICATED":` block body was
dedented to the same level as the `if`, so Python raised
`IndentationError: expected an indented block after 'if' statement on line 132`.
This blocked module import, hence `wks.cli selftest` and `eval/test_wks.py`.

A secondary defect: `wks/sweep_citations.py` line 78 passed `None` instead of the
loop variable `q` to `resolver.resolve(d["url"], ...)`, so the quote-gated
laundering guard never actually checked the quote. Test
`"sweeper passes the quote down, so it cannot accept any live page"` caught this.

## Files changed
- `wks/ingest.py`: re-indented lines 133-173 (the FABRICATED branch) by one
  level so `rejected.append(...)`, the conflict-recording block, and `continue`
  form the body of the `if`.
- `wks/sweep_citations.py`: `resolver.resolve(d["url"], None)` → `resolver.resolve(d["url"], q)`.

## Minimal patch explanation
No logic changed. The ingest fix restores the intended control flow:
FABRICATED items are recorded as rejected conflicts (idempotent by fingerprint)
and skipped; all other items proceed to the normal ingest_claim path. The
sweep fix makes quote verification actually bind (a successor is accepted only
when the original quote is present on it).

## Tests executed and actual results
- `python -c "import ast; ast.parse(...)"` → syntax ok
- `python -m wks.cli selftest` → `ALL WKS GATE TESTS PASS` (exit 0)
- `python eval/test_wks.py` → `ALL WKS GATE TESTS PASS`
- `python -m wks.domains --check` → `tree check: 0 problem(s) across 70 classes`
- `python -m wks.project --check` → `skills drift: 0 problem(s)`
- `python -m wks.cli drift-audit` → `drift-audit: 0 non-clean of 210`

## Evidence that the ingestion pipeline still enforces every existing gate
- selftest exercises sanitization, quote verification, quality assessment (10
  dimensions, 15 blocking tags), publisher-host corroboration, validation_state
  ownership, provenance/disproof requirements, and projection refresh.
- All gates remain intact; no thresholds changed; no validation bypassed.

## Remaining defects
- Rollback-interruption test introduced during Phase 2 was NOT committed as a
  test file; only ad-hoc verification was performed. No `eval/test_stage_gen.py`
  or equivalent exists. Recorded as follow-up.
- `COMPETENCY.md` (assessment/) not tracked in projection_manifest yet.
- Staged generation tests for interrupted/injected-failure rollback are not
  committed.

## Status
- VERIFIED: ingest repair, sweep quote fix, selftest, test_wks.
- BLOCKED (previously): none new.
- NOT RUN: full eval suite beyond test_wks (not required by this task).
EOF