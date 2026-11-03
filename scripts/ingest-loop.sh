#!/usr/bin/env bash
# Batch ingest + regenerate for WKS web-class research wave.
# Usage: bash scripts/ingest-loop.sh [file1.json file2.json ...]
# With no args: ingests every knowledge/incoming/pending/*.json, then regenerates skills,
# then re-runs `wks.cli gaps` to measure delta.
set -u
cd "$(dirname "$0")/.." || exit 1

INGEST=(python -m wks.cli ingest)
GENERATE="python -m wks.skillgen"
GAPS="python -m wks.cli gaps"

if [ $# -gt 0 ]; then
  for f in "$@"; do
    echo "=== INGEST $f ==="
    python -m wks.cli ingest "$f"
  done
else
  echo "=== BATCH INGEST all knowledge/incoming/pending/*.json ==="
  for f in knowledge/incoming/pending/*.json; do
    [ -f "$f" ] || continue
    echo "--- $f"
    python -m wks.cli ingest "$f" | tail -3
  done
  echo "=== REGENERATE SKILLS ==="
  $GENERATE
  echo "=== GAPS DELTA ==="
  $GAPS
fi
