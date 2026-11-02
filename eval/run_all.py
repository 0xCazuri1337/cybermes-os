#!/usr/bin/env python3
"""Run the whole eval suite and report per-file results.

MEASURED 2026-10-31: the suite is 40+ files with no single entry point, so
"run the tests" meant running them one at a time and losing track of which
had been run. This runs every `eval/test_*.py` in a subprocess, isolates
each one's exit code, and reports a summary table.

Each test file is run with its OWN timeout, because several of them copy the
whole repository into a sandbox and take two to three minutes.

Usage:
    python eval/run_all.py            # everything
    python eval/run_all.py --quick    # skip the slow sandbox-copy files
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

EVAL = Path(__file__).resolve().parent

# Files that copy the whole repository (and its database) into a sandbox.
# They are the slow ones, and they are the ones most likely to expose a
# real regression, so they are included by default and skipped only by
# --quick.
SLOW = {
    "test_isolation.py",
    "test_scheduler.py",
    "test_regressions.py",
    "test_wks_infra.py",
}

# The masterprompt score is a scoring harness, not a pass/fail gate; it is
# run separately because it takes several minutes.
EXCLUDE = {
    "masterprompt_score.py",
    "run_all.py",
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true",
                    help="skip the slow sandbox-copy test files")
    ap.add_argument("--timeout", type=int, default=420,
                    help="per-file timeout in seconds")
    args = ap.parse_args()

    files = sorted(p for p in EVAL.glob("test_*.py")
                   if p.name not in EXCLUDE)
    if args.quick:
        files = [p for p in files if p.name not in SLOW]

    results: list[tuple[str, int, float, str]] = []
    failed: list[str] = []

    # MEASURED 2026-10-31: several test files read `os.environ["WKS_ROOT"]`
    # at import time (`eval/test_mastery_gates.py:26` and three others).
    # Without it they die with `KeyError: 'WKS_ROOT'` before a single check
    # runs -- which looks like a failing test but is a missing environment.
    env = dict(os.environ)
    env["WKS_ROOT"] = str(EVAL.parent)
    env["PYTHONPATH"] = str(EVAL.parent) + os.pathsep + env.get("PYTHONPATH", "")

    for p in files:
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                [sys.executable, str(p)],
                capture_output=True, text=True,
                timeout=args.timeout, cwd=str(EVAL.parent), env=env)
            rc = proc.returncode
            tail = (proc.stdout or "").strip().splitlines()[-1:] or [""]
            note = tail[0][:110]
            if proc.stderr.strip() and rc != 0:
                note = (proc.stderr.strip().splitlines() or [""])[-1][:110]
        except subprocess.TimeoutExpired:
            rc = -1
            note = f"TIMEOUT after {args.timeout}s"
        dt = time.monotonic() - t0
        results.append((p.name, rc, dt, note))
        mark = "PASS" if rc == 0 else "FAIL"
        print(f"[{mark}] {p.name:42s} {dt:6.1f}s  {note}", flush=True)
        if rc != 0:
            failed.append(p.name)

    print()
    print("=" * 78)
    passed = sum(1 for _, rc, _, _ in results if rc == 0)
    print(f"SUITE: {passed}/{len(results)} files passed")
    if failed:
        print("FAILED FILES:")
        for f in failed:
            print("  -", f)
    print("=" * 78)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
