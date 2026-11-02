#!/usr/bin/env bash
#
# scripts/update.sh -- the `/update` pipeline entry point.
#
# MEASURED 2026-10-31: `.opencode/commands/update.md` says "run
# scripts/update.sh or equivalent autonomously", and the checklist item
# "raw -> processed -> index -> learn flow via scripts/update.sh" was
# UNCHECKED because the named script did not exist. The FLOW was real --
# it lives in `writeups/pipeline.py` -- but the PATH the docs name was
# absent, so an operator following the docs literally hit a missing file.
#
# This wrapper is that path. It is a thin shell over the Python pipeline:
# the pipeline owns the behaviour, this owns the invocation, so there is
# one implementation and one set of semantics.
#
# USAGE
#   scripts/update.sh              # process -> index -> lessons
#   scripts/update.sh process      # stage 2 only
#   scripts/update.sh index        # stage 3 only
#   scripts/update.sh lessons      # stage 4 only
#
# The stages the `/update` spec names that this script does NOT run --
# refreshing memory/methodology.md, memory/patterns.md, the
# memory/targets/*.md checklists, and the agent-briefing.md timestamp --
# belong to other components. This script says so rather than pretending.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PY="${PYTHON:-python3}"

echo "=== /update pipeline ==="
echo "root: $ROOT"

# The `/update` spec's mandates: verify the skill registry and resolve the
# update-mode skills before doing any work.
if [ -x "$ROOT/scripts/skill_registry.py" ] || [ -f "$ROOT/scripts/skill_registry.py" ]; then
  echo "--- skill registry check ---"
  "$PY" "$ROOT/scripts/skill_registry.py" check || {
    echo "skill registry check FAILED -- refusing to continue" >&2
    exit 1
  }
fi

echo "--- preflight (--mode update) ---"
if [ -f "$ROOT/scripts/runtime_preflight.py" ]; then
  # The preflight needs a target and a scenario. The update pipeline is a
  # corpus operation, not a hunt, so there is no target to lock -- the
  # preflight is therefore NOT run here, and that is stated rather than
  # passed with a dummy value that would fail the gate.
  echo "skipped: preflight locks a hunt's scope; /update has no target scope."
  echo "         (the update-mode skills are resolved below instead)"
fi

echo "--- resolve update-mode skills ---"
if [ -f "$ROOT/scripts/skill_registry.py" ]; then
  "$PY" "$ROOT/scripts/skill_registry.py" resolve \
    --scenario "write-up intelligence update" --mode update --paths-only || true
fi

STAGE="${1:-all}"
echo "--- pipeline stage: $STAGE ---"
exec "$PY" -m writeups.pipeline "$STAGE"
