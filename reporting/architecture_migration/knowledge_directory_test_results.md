# Knowledge Directory Test Results (Phase 3.5)

- `python -m wks.cli selftest`: PASS (ALL WKS GATE TESTS PASS)
- `pytest eval/test_wks.py eval/test_unified_ingest.py`: 13 passed
- `python -m wks.domains --check`: tree check: 0 problem(s) across 70 classes
- `python -m wks.project --check`: skills drift: 0 problem(s)
- `python -m wks.cli drift-audit`: 0 non-clean of 210
