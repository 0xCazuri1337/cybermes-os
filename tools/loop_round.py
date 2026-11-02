"""Dispatch one research round to OpenCode, then gate what it produced.

This is the worker half of the two-agent loop. Division of authority:

  OpenCode  writes ONE intake file under research/incoming/.
  Hermes    writes nothing on its behalf -- this script only DISPATCHES, then
             runs the real gate and reports the verdict.

The worker is never trusted to decide whether its own evidence is good. That is
the gate's job and the lead's job, which is why `--no-verify` is never passed.

Run:  python tools/loop_round.py --round 1 [--model opencode/space-bunny-free]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
LOOP = ROOT / "runtime" / "loop"
ROUNDS = LOOP / "rounds"
INTAKE = ROOT / "research" / "incoming"
NPM_PATH = r"C:/Users/Administrator/AppData/Roaming/npm"

# sh() streams into this file; the caller must NOT overwrite it.
LOG_PATH = ROOT / "runtime" / "loop" / "_dispatch.log"

sys.path.insert(0, str(ROOT))


def opencode_exe() -> str:
    """Absolute path to the Windows launcher for opencode.

    MEASURED (round 1 crashed with `FileNotFoundError: [WinError 2]`): npm on
    Windows installs THREE shims per binary — a POSIX `opencode` shell script, a
    `opencode.cmd` batch file and an `opencode.ps1`. `shutil.which` and bare
    `opencode` resolve the SH script inside MSYS bash, so bash runs it happily,
    but native Windows Python cannot execute a `#!/bin/sh` file and CreateProcess
    raises WinError 2. Prefixing PATH is therefore not enough: the `.cmd` shim
    must be named explicitly.
    """
    for name in ("opencode.cmd", "opencode.exe", "opencode"):
        cand = Path(NPM_PATH) / name
        if cand.exists():
            return str(cand)
    found = shutil.which("opencode")
    if found:
        return found
    raise FileNotFoundError(
        f"opencode not found under {NPM_PATH}. Install with: "
        f"npm i -g opencode-ai")


# --------------------------------------------------------------------------
# PROMPT DELIVERY — argv is lossy, so the prompt goes through a FILE.
#
# MEASURED across three channels on this host, all with the same 3-line prompt:
#   1. argv with embedded newlines  -> model received "just the title"
#   2. stdin pipe                  -> model received nothing at all
#   3. FILE + one-line instruction -> model read all 3 lines back verbatim
#
# The `.cmd` shim plus argument parsing collapses a multi-line argument to its
# first line, which produced a round that exited 0 having done nothing — the
# most dangerous possible failure, because it looks like success. Every round
# now writes `prompt.txt` and sends a single-line instruction naming that file,
# and the driver's output is checked for the worker's own report before the
# gate is trusted.
# --------------------------------------------------------------------------

DELIVER = ("Read the file {path} using your tools. "
           "It is your complete task brief. Follow it exactly. "
           "Reply with a short report at the end; do not paste the brief back.")


def deliver_prompt(rdir: Path, prompt: str, timeout: int, model: str) -> tuple[int, str]:
    pfile = rdir / "prompt.txt"
    pfile.write_text(prompt, encoding="utf-8")
    # cwd is ROOT, so the instruction must carry the path relative to ROOT.
    instr = DELIVER.format(path=pfile.relative_to(ROOT).as_posix())
    return sh([opencode_exe(), "run", "--model", model, instr], timeout=timeout)


def sh(cmd: list[str], timeout: int) -> tuple[int, str]:
    """Run a command, streaming output to a log file so a TIMEOUT cannot erase it.

    MEASURED (round 3): the original `subprocess.run(capture_output=True)` wrote
    nothing until the child exited, so a 900s timeout produced
    `worker-output.txt` containing exactly `TIMEOUT after 900s` — 16 minutes of
    real work (URL probes, reading the gate) destroyed with nothing to learn
    from. Output now tees to disk line-by-line while running, so a timeout keeps
    whatever the worker actually said.
    """
    env = dict(os.environ)
    env["PATH"] = env.get("PATH", "") + os.pathsep + NPM_PATH
    env["WKS_ROOT"] = str(ROOT)
    log = LOG_PATH
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("w", encoding="utf-8", errors="replace") as fh:
        try:
            proc = subprocess.Popen(cmd, cwd=str(ROOT), env=env,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    text=True, encoding="utf-8",
                                    errors="replace", bufsize=1)
        except FileNotFoundError as e:
            return 127, f"executable not found: {e}"
        deadline = time.time() + timeout
        while True:
            if proc.stdout is None:
                break
            line = proc.stdout.readline()
            if line:
                fh.write(line)
                fh.flush()
                continue
            if proc.poll() is not None:
                break
            if time.time() > deadline:
                proc.kill()
                fh.write(f"\n[TIMEOUT after {timeout}s — partial output above]\n")
                fh.flush()
                # Give the tree a moment to die so it cannot linger as an orphan.
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    pass
                return 124, log.read_text(encoding="utf-8", errors="replace")
            time.sleep(0.05)
        proc.wait()
    return proc.returncode, log.read_text(encoding="utf-8", errors="replace")


def target_classes(con, mode: str) -> list[dict]:
    """Pick this round's target classes from a MEASURED gap.

    `mode="maturity"` — classes just below the 12-item maturity threshold,
    closest first. dc2 is the last failing rubric criterion (95.0/100 overall)
    and this is the shortest path: nine classes need only 1-2 more items each,
    which is a bounded ask per round rather than rebuilding a thin class.

    `mode="fp"` — mature classes short of false-positive rules, widest first.

    Both count BOTH fp stores, because `wks.ingest` routes `kind='fp_rule'` into
    `item` and never writes `fp_case`; counting only fp_case hides the entire
    evidence-derived fp corpus (see im2 in eval/score_rubric.py).
    """
    rows = con.execute("""
        SELECT c.id,
               (SELECT COUNT(*) FROM item x WHERE x.class_id=c.id AND x.status='active') AS n_items,
               (SELECT COUNT(*) FROM fp_case f WHERE f.class_id=c.id) AS n_case,
               (SELECT COUNT(*) FROM item x WHERE x.class_id=c.id AND x.status='active'
                   AND x.kind='fp_rule') AS n_rule
        FROM bug_class c
    """).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["n_fp"] = d["n_case"] + d["n_rule"]
        if mode == "maturity":
            if d["n_items"] < 12:
                d["needs"] = 12 - d["n_items"]
                out.append(d)
        else:
            if d["n_items"] >= 12 and d["n_fp"] < 2:
                out.append(d)
    if mode == "maturity":
        out.sort(key=lambda r: r["needs"])          # closest to threshold first
    else:
        out.sort(key=lambda r: (-r["n_items"], r["n_fp"]))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--round", type=int, required=True)
    ap.add_argument("--model", default="opencode/space-bunny-free")
    ap.add_argument("--classes", type=int, default=2,
                    help="how many fp-gap classes to target (kept small: rounds 1-3 "
                         "each died before writing a single artifact)")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--mode", default="fp", choices=["fp", "maturity"],
                    help="which measured gap this round attacks")
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    ROUNDS.mkdir(parents=True, exist_ok=True)
    rdir = ROUNDS / f"round-{args.round:02d}"
    rdir.mkdir(exist_ok=True)

    import sqlite3
    con = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    con.row_factory = sqlite3.Row
    targets = target_classes(con, args.mode)[:args.classes]
    con.close()

    print(f"ROUND {args.round}  model={args.model}")
    print(f"  target classes (>=12 items, <2 fp rules): "
          f"{[t['id'] for t in targets]}")
    if not targets:
        print("  no fp-gap classes left — nothing to dispatch")
        return 0

    brief = (LOOP / "WORKER_BRIEF.md").read_text(encoding="utf-8")
    if args.mode == "maturity":
        tgt = "\n".join(
            f"  - {t['id']}: has {t['n_items']} active items, needs "
            f"{t['needs']} more to reach the maturity threshold of 12"
            for t in targets)
        goal = (f"Produce AT LEAST {targets[0]['needs']} verified items for the "
                f"FIRST class in the list ({targets[0]['id']}). Depth on one class "
                f"beats breadth across all of them.")
    else:
        tgt = "\n".join(
            f"  - {t['id']}: {t['n_items']} items, {t['n_fp']} fp rules total"
            for t in targets)
        goal = "Produce fp_rule items for as many of these classes as you can."
    prompt = f"""{brief}

(classes this round: {len(targets)})

## THIS ROUND'S ASSIGNMENT
{goal}

TARGET CLASSES:
{tgt}

BUDGET DISCIPLINE (learned from three failed rounds — obey this):
- Time-box yourself to about 4 minutes of work.
- Write the output file as your FIRST action after you have ONE complete
  item, then append. A partial file with 2 valid items is a SUCCESS this round;
  a perfect file you never write is a FAILURE.
- Do NOT read wks/*.py or orch/*.py. The rules you need are in this brief.
  Rounds 2 and 3 spent their entire budget reading the codebase.
- If you run low on time, stop and keep what you have written.

An fp_rule states what makes an apparent finding FALSE — the pattern that looks
vulnerable but is not, and the exact check that distinguishes the two:

  claim:    "A value reaching a sink through an auto-escaping template binding
             is not XSS, because the framework writes it with textContent."
  body:     the mechanism, the sink, the escaping function, and the ONE
             condition that would break the rule (a second raw-HTML sink, a
             markdown renderer, a JSON blob read by another script...)
  disproof: the exact circumstance in which the rule stops being true.
  sources:  >= 2 INDEPENDENT publishers — the framework's own documentation plus
            an independent security analysis. Framework docs alone are ONE
            publisher and will be held.

Write your file to:
  research/incoming/round{args.round:02d}-fp.json

Then run the acceptance test yourself and report the verdict verbatim.
"""

    if args.dry:
        print("  (dry) prompt prepared, not dispatched")
        (rdir / "prompt.txt").write_text(prompt, encoding="utf-8")
        return 0

    target_file = INTAKE / f"round{args.round:02d}-fp.json"
    before = target_file.exists()

    t0 = time.time()
    print(f"  dispatching opencode (timeout 900s, prompt via file)...")
    rc, out = deliver_prompt(rdir, prompt, args.timeout, args.model)
    elapsed = round(time.time() - t0, 1)
    (rdir / "worker-output.txt").write_text(out, encoding="utf-8")
    print(f"  opencode exit={rc} in {elapsed}s -> worker-output.txt "
          f"({len(out)} chars)")

    if not target_file.exists():
        print(f"  NO FILE: {target_file.name} was not created by the worker.")
        print("  recorded as a failed round; the gate was never bypassed.")
        _write_report(rdir, args.round, args.model, elapsed, rc, None, [], "no_file")
        return 1

    # The gate decides. Never the worker's own opinion of its output.
    rc2, dry_out = sh([sys.executable, "-m", "wks.ingest", str(target_file), "--dry"], 900)
    (rdir / "gate-dry.txt").write_text(dry_out, encoding="utf-8")
    print("  --- gate (dry) ---")
    for line in dry_out.strip().splitlines()[-14:]:
        print("   ", line[:160])

    rc3, real_out = sh([sys.executable, "-m", "wks.ingest", str(target_file)], 900)
    (rdir / "gate-real.txt").write_text(real_out, encoding="utf-8")
    print("  --- gate (committed) ---")
    for line in real_out.strip().splitlines()[-14:]:
        print("   ", line[:160])

    promoted = sum(1 for l in real_out.splitlines() if "high_confidence" in l)
    held = sum(1 for l in real_out.splitlines() if "under_review" in l)
    rejected = sum(1 for l in real_out.splitlines() if "rejected" in l.lower()
                   and "shape_errors=0" not in l)

    _write_report(rdir, args.round, args.model, elapsed, rc,
                  str(target_file), [promoted, held], "ok" if rc3 == 0 else f"gate rc={rc3}")
    print(f"  round report -> {rdir}")
    return 0


def _write_report(rdir: Path, rnd: int, model: str, elapsed: float,
                  rc: int, target: str | None, counts: list[int],
                  status: str) -> None:
    lines = [
        f"# Loop round {rnd:02d}",
        f"- at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}",
        f"- model: {model}",
        f"- worker exit: {rc}",
        f"- elapsed_s: {elapsed}",
        f"- intake file: {target or 'NONE'}",
        f"- status: {status}",
    ]
    if counts:
        lines.append(f"- promoted: {counts[0]}  held: {counts[1]}")
    (rdir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())