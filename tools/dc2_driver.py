"""Close dc2 with dispatched research — measured need, not guesswork.

MEASURED SCOPE (2026-10-04, from `quality.maturity`, not from a count of items):
17 classes are immature. The missing dimensions are ONLY:
    items            15 classes   (MATURITY_MIN_ITEMS = 12)
    supported_items   3 classes   (MATURITY_MIN_HIGH_CONF = 4)
`fp_rules`, `chain`, `methodology` and `skill` ALREADY PASS for every one of
them. So the entire remaining gap is 57 items of real evidence — nothing else.
An earlier count of mine omitted `supported_items` and would have dispatched
work at the wrong classes.

TWO CLASSES NEED A DIFFERENT FIX
`ad_acl_abuse` and `password_attacks` already have 20-21 items but only 3
supported. They do NOT need more items — they need the existing held ones to
PASS the gate. Manufacturing new items for them would add to a deficit they do
not have. This driver separates the two cases and only ever dispatches real
research.

ANTI-GAMING
Success is measured by `quality.maturity` recomputed from the db, never by
counting what the worker claims. A round that promotes nothing moves nothing and
is reported as a failure.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
NPM = r"C:/Users/Administrator/AppData/Roaming/npm"
LOOP = ROOT / "runtime" / "loop" / "dc2"
sys.path.insert(0, str(ROOT))

from wks import quality, store  # noqa: E402


def need() -> dict:
    """Exactly what is missing, per class, from the db."""
    con = store.open_db(create=False)
    gaps = quality.gap_report(con)
    out = {"needs_items": [], "needs_supported": [], "mature": 0,
           "classes": len(gaps)}
    for g in gaps:
        if g["state"] == "mature":
            out["mature"] += 1
            continue
        miss = set(g["missing"])
        entry = {"class_id": g["class_id"], "n_items": g["n_items"],
                 "n_supported": g["n_supported"],
                 "deficit": max(0, 12 - g["n_items"]),
                 "supported_deficit": max(0, 4 - g["n_supported"]),
                 "priority": g["priority"]}
        if "items" in miss:
            out["needs_items"].append(entry)
        if "supported_items" in miss:
            out["needs_supported"].append(entry)
    con.close()
    for k in ("needs_items", "needs_supported"):
        out[k].sort(key=lambda e: (e["deficit"], -e["priority"]))
    out["item_deficit_total"] = sum(e["deficit"] for e in out["needs_items"])
    return out


def brief_for(entry: dict) -> str:
    return f"""# Research task — {entry['class_id']}

The `{entry['class_id']}` class is BELOW the maturity threshold and needs
**{entry['deficit']} more gate-passing item(s)**. It currently has
{entry['n_items']} active items and {entry['n_supported']} supported.

## Your job
Produce **{entry['deficit']} NEW items** for class `{entry['class_id']}`.
Each must be independently verifiable and cite TWO INDEPENDENT PUBLISHER ORGS.

Do NOT:
- re-state claims the corpus already holds (read the digest first)
- paraphrase one mechanism into several items
- write a claim you cannot cite a verbatim quote for
- add course-catalogue prose ("In this module we will cover...") — that is
  `BOILERPLATE_DISPROOF` and is held

## Read these before writing (they define the contract)
- `runtime/loop/WORKER_BRIEF.md` — the item schema and hard rules
- `skills/*/{entry['class_id']}/DIGEST.md` — what is ALREADY known

## Kind
Prefer `technique`, `test`, `variant` or `signal` items — those are what feed the
hunting runbooks. An `fp_rule` does NOT help this class: it already passes the
fp_rules check.

## Output
Write ONE file: `knowledge/incoming/dc2-{entry['class_id']}.json`
Last line: `// COMPLETE <n>`

Then run the acceptance test yourself and report the verdict verbatim:
    cd C:/Users/Administrator/.hermes/cyber
    python -m wks.ingest knowledge/incoming/dc2-{entry['class_id']}.json --dry
A rejection is information — report it, do not hide it. Never pass `--no-verify`.
"""


def dispatch(entry: dict, model: str, timeout: int) -> tuple[int, str]:
    LOOP.mkdir(parents=True, exist_ok=True)
    bf = LOOP / f"brief-{entry['class_id']}.md"
    bf.write_text(brief_for(entry), encoding="utf-8")
    msg = (f"Read the file {bf.relative_to(ROOT).as_posix()} using your tools. "
           f"It is your complete task brief. Follow it exactly. End with a short "
           f"report.")
    env = dict(os.environ)
    env["PATH"] = env.get("PATH", "") + os.pathsep + NPM
    try:
        p = subprocess.run([str(Path(NPM) / "opencode.cmd"), "run", "--model", model, msg],
                           cwd=str(ROOT), env=env, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except subprocess.TimeoutExpired:
        return 124, f"[TIMEOUT after {timeout}s]"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=4)
    ap.add_argument("--classes", type=int, default=3, help="classes per round")
    ap.add_argument("--model", default="opencode/space-bunny-free")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--dry", action="store_true")
    args = ap.parse_args()

    n = need()
    print("=" * 66)
    print("DC2 DRIVER — measured need, recomputed from the db")
    print("=" * 66)
    print(f"classes {n['classes']} | mature {n['mature']} "
          f"({100*n['mature']/n['classes']:.2f}%) | item deficit {n['item_deficit_total']}")
    print(f"needs items:   {len(n['needs_items'])} classes")
    print(f"needs supported:{len(n['needs_supported'])} classes")
    for e in n["needs_supported"]:
        print(f"    !! {e['class_id']} has {e['n_items']} items but only "
              f"{e['n_supported']} supported — needs GATE PASSES, not new items")
    print()
    for e in n["needs_items"][:12]:
        print(f"    {e['class_id']:28} +{e['deficit']} items "
              f"(has {e['n_items']}, supported {e['n_supported']})")
    if args.dry:
        return 0

    # db backup before any mutating round
    bak = ROOT / "db" / f"wks-pre-dc2-{datetime.now().strftime('%Y%m%d-%H%M%S')}.db"
    shutil.copy2(ROOT / "db" / "wks.db", bak)
    print(f"\nbackup: {bak.name}")

    done = []
    for rnd in range(1, args.rounds + 1):
        n = need()
        if not n["needs_items"]:
            print("\nNO ITEM DEFICIT REMAINS")
            break
        batch = n["needs_items"][: args.classes]
        print(f"\n--- round {rnd}: {[e['class_id'] for e in batch]} "
              f"(need {sum(e['deficit'] for e in batch)} items)")
        for e in batch:
            cid = e["class_id"]
            target = ROOT / "research" / "incoming" / f"dc2-{cid}.json"
            if target.exists():
                target.unlink()          # never re-ingest a stale file
            t0 = time.time()
            rc, out = dispatch(e, args.model, args.timeout)
            (LOOP / f"out-{cid}.txt").write_text(out, encoding="utf-8")
            print(f"    {cid:26} worker exit={rc} in {round(time.time()-t0)}s")
            if not target.exists():
                print(f"      NO FILE ({len(out)} chars of output kept)")
                continue
            r = subprocess.run([sys.executable, "-m", "wks.ingest", str(target)],
                               capture_output=True, text=True, cwd=str(ROOT),
                               timeout=900)
            tail = [l for l in (r.stdout or "").splitlines() if l.strip()][-6:]
            for l in tail:
                print("      " + l[:150])
            done.append((cid, "ok" if r.returncode == 0 else "gate-fail"))

    after = need()
    print("\n" + "=" * 66)
    print(f"RESULT: mature {n['mature']} -> {after['mature']} "
          f"({100*n['mature']/n['classes']:.2f}% -> "
          f"{100*after['mature']/after['classes']:.2f}%)")
    print(f"item deficit {n['item_deficit_total']} -> {after['item_deficit_total']}")
    print(f"still needs items: {[e['class_id'] for e in after['needs_items']]}")
    print(f"still needs supported: {[e['class_id'] for e in after['needs_supported']]}")
    summary = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "mature_before": n["mature"], "mature_after": after["mature"],
               "deficit_before": n["item_deficit_total"],
               "deficit_after": after["item_deficit_total"],
               "rounds": done}
    (LOOP / "last-result.json").write_text(json.dumps(summary, indent=2),
                                          encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())