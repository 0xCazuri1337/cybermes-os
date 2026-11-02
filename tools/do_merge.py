"""One command, the correct order, for the whole merge.

The ordering is the whole difficulty. MEASURED, by doing it wrong several
times:

  1. `retarget_refs --apply` on the PRE-MERGE tree — rewrites prose links in
     `methodology/`, `README.md`, `CONTROL/` before anything moves.
  2. `merge_skills --apply` — builds `skills/<Domain>/<class>/` and retires
     `classes/`, `chains/`, `attack-chains/`, `bug-classes/`.
  3. `taxonomy_write` — regenerates the class pages, stubs, area READMEs and
     chain files INTO the merged tree. It must run AFTER the merge, because it
     is what writes the destination paths.
  4. `fill_subdocs --apply` — writes the sub-document pages into
     `skills/<Domain>/<class>/topics/`.
  5. `retarget_refs --apply` again — the generated files' internal links
     (`../../web/xss/xss.md` and friends) still name the retired tree, and step 3
     wrote them fresh. Skipping this is why an earlier run sat at 130+ findings.
  6. verify: R15 (`--check`), R14 (`audit_taxonomy`), R22 (`audit_refs`).

Steps 3 and 5 must repeat in that order after ANY generator change: the
generator re-emits old-style links, and only the retargeter converts them. The
loop is `taxonomy_write -> retarget_refs` until the audit is clean.

    python tools/do_merge.py --dry      # print the plan
    python tools/do_merge.py --apply    # run all six steps
    python tools/do_merge.py --check    # verify only
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable


def run(label: str, argv: list[str], allow_fail: bool = False) -> tuple[int, str]:
    p = subprocess.run([PY, *argv], capture_output=True, text=True, cwd=ROOT,
                       env={**os.environ, "WKS_ROOT": str(ROOT)})
    tail = (p.stdout or "").strip().splitlines()[-3:]
    print(f"  {label:28} exit={p.returncode}  {' | '.join(t.strip()[:60] for t in tail)}")
    if p.returncode != 0 and not allow_fail:
        print((p.stderr or p.stdout)[-700:])
    return p.returncode, p.stdout or ""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="do_merge")
    ap.add_argument("--dry", action="store_true")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)

    if a.check:
        print("verify:")
        run("R15 taxonomy --check", ["tools/taxonomy/taxonomy_write.py", "--check"])
        run("R14 audit_taxonomy", ["tools/taxonomy/audit_taxonomy.py"])
        run("R22 audit_refs", ["tools/audit_refs.py"])
        run("merged tree", ["tools/merge_skills.py", "--check"])
        return 0

    print("PLAN:")
    for i, s in enumerate([
        "retarget prose links (pre-merge)",
        "merge bundles + retire legacy dirs",
        "regenerate class pages / stubs / chains into the merged tree",
        "write sub-document pages into bundles",
        "retarget generated links (post-merge)",
        "verify R14/R15/R22 + tree shape",
    ], 1):
        print(f"  {i}. {s}")
    if a.dry:
        return 0

    print("\nrunning:")
    run("1 retarget (pre-merge)", ["tools/retarget_refs.py", "--apply"])
    run("2 merge + retire", ["tools/merge_skills.py", "--apply"])
    run("3 taxonomy_write", ["tools/taxonomy/taxonomy_write.py"])
    run("4 fill_subdocs", ["tools/fill_subdocs.py", "--apply"])
    run("5 retarget (post-merge)", ["tools/retarget_refs.py", "--apply"])

    # The generator re-emits old-style links, so one more generate+retarget
    # cycle is required for the tree to settle.
    for i in range(3):
        _, o1 = run(f"6.{i}a taxonomy_write", ["tools/taxonomy/taxonomy_write.py"])
        _, _ = run(f"6.{i}b retarget", ["tools/retarget_refs.py", "--apply"])
        _, audit = run(f"6.{i}c audit_refs", ["tools/audit_refs.py"])
        if "TOTAL 0 finding" in audit:
            break

    print("\nverify:")
    run("R15", ["tools/taxonomy/taxonomy_write.py", "--check"])
    run("R14", ["tools/taxonomy/audit_taxonomy.py"])
    run("R22 selftest", ["tools/audit_refs.py", "--selftest"])
    _, final = run("R22 clean tree", ["tools/audit_refs.py"])
    run("tree shape", ["tools/merge_skills.py", "--check"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())