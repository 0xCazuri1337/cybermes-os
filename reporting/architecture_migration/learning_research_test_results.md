# Learning/Research Test Results

Command: `python eval/test_unified_ingest.py`

Result: 13 tests, OK.

All required scenarios covered and passing:
- valid learning candidate
- valid research candidate
- provenance preserved
- sanitization/quote verification/quality gate invoked
- insufficiently corroborated learning claim unpromoted
- fabricated quote rejected
- injection treated as untrusted data
- duplicate acquisition no uncontrolled duplicate
- learning progress preserved
- projections eligible only
- manifest/drift present
- missing fields raises
- verify flag false skips quote
