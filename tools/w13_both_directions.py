"""BOTH-DIRECTIONS validation of a child's citation checker.

MEASURED: both children reported `unknown=0 unpromoted=0` and I re-derived the
same numbers with my own query. A checker that has only ever PASSED proves
nothing about itself, so this tampers with a COPY (never the real artifact) and
requires the checker to FAIL.

Three tamper cases, because they fail for different reasons:
  T1 fabricated-but-plausible item_key  -> must be UNKNOWN
  T2 a real key from a DIFFERENT class -> must be UNKNOWN
  T3 a real key demoted to under_review -> must be UNPROMOTED

Run:  python tools/w13_both_directions.py <class_id>
Exit 0 only when every case failed as required AND the untampered original
still passes. Any other exit means the checker cannot be trusted.
"""
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile

WKS = os.environ.get("WKS_ROOT", ".")
os.chdir(WKS)
CLASS = sys.argv[1]
ART = f"knowledge/activity/sessions/methodology-bootcamp/{CLASS}"
CHECK = f"{ART}/verify_citations.py"

db = sqlite3.connect(f"{WKS}/db/wks.db")
rows = {r[0]: r[1] for r in db.execute(
    "SELECT i.item_key, q.validation_state FROM item i "
    "JOIN quality q ON q.item_id = i.id WHERE i.class_id = ?", (CLASS,))}
if not rows:
    sys.exit(f"no items for class {CLASS}")

real = [k for k, v in rows.items() if v in ("high_confidence", "supported")]
held = [k for k, v in rows.items() if v not in ("high_confidence", "supported")]
other = db.execute(
    "SELECT item_key FROM item WHERE class_id != ? LIMIT 1", (CLASS,)
).fetchone()[0]


def run_checker(d):
    """Run a child's checker against a COPY that may live anywhere.

    MEASURED: the first version of this harness copied each class dir to a temp
    dir and then invoked the child's own `verify_citations.py`, which hardcodes
    ART = knowledge/activity/sessions/methodology-bootcamp/<class> and reads from there.
    Every tamper case therefore scored exit 0 -- not because the checker passed
    a fabricated key, but because it never SAW the tampered copy. A harness that
    cannot fail is not a harness. The copy is now rewritten to point at itself.
    """
    src = os.path.join(d, "verify_citations.py")
    txt = open(src, encoding="utf-8").read()
    # Repoint the copy's ART at the copy, and its db at the real corpus.
    # A Windows temp path contains `\U` and `\t`, which a replacement TEMPLATE
    # reads as regex escapes -> re.error "bad escape \U". A lambda returns the
    # string literally, so the path survives intact.
    txt = re.sub(r'^ART\s*=.*$',
                 lambda _m: f'ART = r"{d}"', txt, count=1, flags=re.M)
    txt = txt.replace('os.environ["WKS_ROOT"] + "/db/wks.db"',
                      repr(os.path.join(WKS, "db", "wks.db")))
    patched = os.path.join(d, "_check_copy.py")
    with open(patched, "w", encoding="utf-8") as fh:
        fh.write(txt)
    p = subprocess.run([sys.executable, patched, CLASS],
                       capture_output=True, text=True)
    return p.returncode, (p.stdout + p.stderr).strip()


failures = []

# --- control: the untampered original must PASS -----------------------
rc, out = run_checker(ART)
print(f"[control] untampered {CLASS}: exit={rc} (MUST be 0)")
if rc != 0:
    failures.append(f"control: untampered checker exited {rc}: {out}")
    print(out)
else:
    print("        ", out.splitlines()[0])

work = tempfile.mkdtemp(prefix=f"w13_{CLASS}_")

# --- T1 fabricated-but-plausible key ----------------------------------
d1 = os.path.join(work, "t1")
shutil.copytree(ART, d1)
with open(os.path.join(d1, "recognize.md"), "a", encoding="utf-8") as fh:
    fh.write("\nFabricated: [xss.technique.wasm_mutation_via_service_worker]\n"
             .replace("xss", CLASS))
rc, out = run_checker(d1)
ok = rc != 0 and "UNKNOWN" in out.upper()
print(f"[T1] fabricated plausible key -> exit={rc} (MUST be non-zero + UNKNOWN)  {'OK' if ok else 'FAIL'}")
if not ok:
    failures.append(f"T1: checker passed a fabricated key (exit={rc})")

# --- T2 a real key from a different class ------------------------------
d2 = os.path.join(work, "t2")
shutil.copytree(ART, d2)
with open(os.path.join(d2, "recognize.md"), "a", encoding="utf-8") as fh:
    fh.write(f"\nCross-class: [{other}]\n")
rc, out = run_checker(d2)
ok = rc != 0 and "UNKNOWN" in out.upper()
print(f"[T2] cross-class real key {other[:40]!r} -> exit={rc} (MUST be non-zero + UNKNOWN)  {'OK' if ok else 'FAIL'}")
if not ok:
    failures.append(f"T2: checker passed a cross-class key (exit={rc})")

# --- T3 a real key that is NOT promoted -------------------------------
if held:
    d3 = os.path.join(work, "t3")
    shutil.copytree(ART, d3)
    with open(os.path.join(d3, "recognize.md"), "a", encoding="utf-8") as fh:
        fh.write(f"\nUnpromoted: [{held[0]}]\n")
    rc, out = run_checker(d3)
    ok = rc != 0 and "UNPROMOTED" in out.upper()
    print(f"[T3] unpromoted key {held[0][:40]!r} -> exit={rc} (MUST be non-zero + UNPROMOTED)  {'OK' if ok else 'FAIL'}")
    if not ok:
        failures.append(f"T3: checker passed an unpromoted key (exit={rc})")
else:
    print("[T3] SKIPPED - class has no held items to tamper with")

shutil.rmtree(work, ignore_errors=True)

print()
if failures:
    print(f"BOTH-DIRECTIONS: FAIL ({len(failures)} problem(s))")
    for f in failures:
        print("  -", f)
    sys.exit(1)
print(f"BOTH-DIRECTIONS: PASS — checker catches fabricated, cross-class and "
      f"unpromoted citations, and passes the untampered original ({CLASS})")