"""Negative control for T23: revert the chain-assembly wiring and confirm the
test goes RED. A test that has only ever passed protects nothing.

Removes the `it.get("chain")` read from wks/ingest.py (the pre-fix behaviour:
the chain block was silently dropped), runs T23, then restores byte-for-byte.
"""
import io
import os
import shutil
import subprocess
import sys

ROOT = r"C:/Users/Administrator/.hermes/cyber"
TARGET = os.path.join(ROOT, "wks", "ingest.py")
BACKUP = TARGET + ".t23neg.bak"

orig = io.open(TARGET, encoding="utf-8").read()
shutil.copyfile(TARGET, BACKUP)
try:
    # Pre-fix behaviour: the chain block is never read.
    bad = orig.replace('spec = it.get("chain")', 'spec = None  # NEGATIVE CONTROL')
    if bad == orig:
        print("MUTATION DID NOT APPLY - the read text moved; T23 is not "
              "exercising what it claims")
        sys.exit(2)
    io.open(TARGET, "w", encoding="utf-8").write(bad)

    r = subprocess.run([sys.executable, "eval/test_wks_chains.py"],
                       cwd=ROOT, capture_output=True, text=True, timeout=600)
    out = r.stdout + r.stderr
    print("--- T23 under MUTATION (chain block ignored, the pre-fix bug) ---")
    for ln in out.splitlines():
        if "[FAIL]" in ln or "[PASS]" in ln or "checks," in ln or "FAILED:" in ln:
            print(ln)
    reds = [ln for ln in out.splitlines() if "[FAIL]" in ln]
    print("\nfailing assertions under mutation:", len(reds))
    print("exit code:", r.returncode)
    print("NEGATIVE CONTROL", "HOLDS (T23 detects the silent drop)"
          if reds else "DID NOT FIRE - T23 is vacuous")
finally:
    shutil.copyfile(BACKUP, TARGET)
    os.remove(BACKUP)
    print("\nrestored byte-for-byte:",
          io.open(TARGET, encoding="utf-8").read() == orig)