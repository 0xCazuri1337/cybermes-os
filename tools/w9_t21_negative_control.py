"""Negative control for T21: break the sweeper's laundering guard and confirm
the test goes RED. A test that cannot fail is not a test.

Temporarily rewrites wks/sweep_citations.py so `sweep()` accepts ANY live
successor (the exact corruption the guard exists to prevent), runs the T21
checks, then restores the file byte-for-byte.
"""
import io
import shutil
import subprocess
import sys

TARGET = r"C:/Users/Administrator/.hermes/cyber/wks/sweep_citations.py"
BACKUP = TARGET + ".t21neg.bak"
ROOT = r"C:/Users/Administrator/.hermes/cyber"

orig = io.open(TARGET, encoding="utf-8").read()
shutil.copyfile(TARGET, BACKUP)
try:
    # Corruption 1: accept a successor without the quote test (laundering).
    bad = orig.replace('res = resolver.resolve(d["url"], q)',
                       'res = resolver.resolve(d["url"], None)')
    if bad == orig:
        print("MUTATION DID NOT APPLY - the guard text moved; test is not "
              "exercising what it claims")
        sys.exit(2)
    io.open(TARGET, "w", encoding="utf-8").write(bad)

    r = subprocess.run([sys.executable, "-m", "wks.cli", "selftest"],
                       cwd=ROOT, capture_output=True, text=True, timeout=600)
    out = r.stdout + r.stderr
    t21 = [ln for ln in out.splitlines()
           if "sweeper" in ln or "launder" in ln or "T21" in ln
           or "dead url" in ln]
    print("--- T21 output under MUTATION (laundering guard removed) ---")
    for ln in t21:
        print(ln)
    reds = [ln for ln in t21 if "[FAIL]" in ln]
    print("\nfailing T21 assertions under mutation:", len(reds))
    print("NEGATIVE CONTROL", "HOLDS (test detects the corruption)"
          if reds else "DID NOT FIRE - T21 is vacuous")
finally:
    shutil.copyfile(BACKUP, TARGET)
    io.open(BACKUP, "w", encoding="utf-8").close()
    import os
    os.remove(BACKUP)
    print("\nrestored:", io.open(TARGET, encoding="utf-8").read() == orig)