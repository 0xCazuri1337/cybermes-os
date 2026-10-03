"""Author fp_case and chain rows through the store, not raw SQL.

A false positive is the most expensive training data available (brief §17) and
it is the scarcest kind in the corpus: measured, 3 of 8 classes with items have
zero fp_case rows. This module exists so a delegated writer fills a reviewed
schema instead of hand-writing SQL, which is how a malformed row or a fabricated
rejection rule gets into the corpus.

Every row is accepted only when it carries the two fields that make it teach
something: `invalidated_by` (the signal that killed it) and `rejection_rule` (the
durable lesson). A "false positive" with no disproof is just a discarded guess.

    python -m wks.authoring fp --class sqli --json research/pending/sqli-fp.json
    python -m wks.authoring chain --json research/pending/sqli-chain.json
    python -m wks.authoring fp --list
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import store


def _load(path: str) -> Any:
    raw = Path(path).read_text(encoding="utf-8")
    # Tolerate a trailing completion marker; json.loads rejects it outright.
    lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("// COMPLETE")]
    return json.loads("\n".join(lines))


def add_fp(con, spec: dict[str, Any]) -> tuple[bool, str]:
    cid = spec["class_id"]
    if store.get_class(con, cid) is None:
        return False, f"unknown class {cid!r}"
    for field in ("hypothesis", "test_performed", "invalidated_by", "rejection_rule"):
        if not (spec.get(field) or "").strip():
            return False, f"missing required field {field!r}"
    if len(spec["rejection_rule"]) < 40:
        return False, ("rejection_rule is too short to be a durable rule; state "
                       "what to check NEXT TIME, not just what was false here")
    key = spec.get("fp_key") or f"{cid}.fp.{spec['hypothesis']}"
    fp_id = store.add_fp(
        con, key, cid, spec["hypothesis"], spec["test_performed"],
        spec["invalidated_by"], spec["rejection_rule"],
        looked_vulnerable_because=spec.get("looked_vulnerable_because"),
        early_signal_missed=spec.get("early_signal_missed"),
        skill_updated=spec.get("skill_updated"),
    )
    con.commit()
    return True, f"fp_case {fp_id} <- {key}"


def add_chain(con, spec: dict[str, Any]) -> tuple[bool, str]:
    if not spec.get("name") or not spec.get("goal"):
        return False, "chain needs both name and goal"
    steps = spec.get("steps") or []
    if len(steps) < 2:
        return False, "a chain needs at least 2 steps; one step is just a finding"
    for i, s in enumerate(steps):
        if not (s.get("action") or "").strip():
            return False, f"step {i+1} has no action"
        if not (s.get("why") or "").strip():
            # §10: a chain step with no justification is an assumed chain.
            return False, f"step {i+1} has no justification -- an unjustified " \
                          f"chain is worse than no chain"
    key = spec.get("chain_key") or spec["name"].lower().replace(" ", "-")
    chain_id = store.add_chain(con, key, spec["name"], spec["goal"],
                               summary=spec.get("summary"),
                               impact=spec.get("impact"))
    for i, s in enumerate(steps, start=1):
        # add_chain_step's trailing params are keyword-only (a subagent tightened
        # the signature in wks/store.py); passing them positionally raises
        # TypeError and takes down the whole import.
        store.add_chain_step(con, chain_id, i, s["action"], s["why"],
                             item_id=s.get("item_id"),
                             class_id=s.get("class_id"),
                             needs=s.get("needs"))
    con.commit()
    return True, f"chain {chain_id} <- {key} ({len(steps)} steps)"


def cmd_fp(args) -> int:
    if args.list:
        con = store.open_db()
        rows = con.execute(
            """SELECT c.id, count(f.id) n FROM bug_class c
               LEFT JOIN fp_case f ON f.class_id=c.id
               GROUP BY c.id HAVING n>0 ORDER BY n DESC""").fetchall()
        for r in rows:
            print(f"  {r['id']:20} {r['n']} fp_case")
        weak = con.execute(
            """SELECT c.id FROM bug_class c
               WHERE (SELECT count(*) FROM item i WHERE i.class_id=c.id
                      AND i.status='active') > 0
                 AND (SELECT count(*) FROM fp_case f WHERE f.class_id=c.id)=0
               ORDER BY c.id""").fetchall()
        print("\nclasses with items and ZERO fp_case (highest value work):")
        for r in weak:
            print(f"  {r['id']}")
        con.close()
        return 0

    data = _load(args.json)
    cases = data["fp_cases"] if isinstance(data, dict) else data
    con = store.open_db(create=True)
    ok = bad = 0
    for c in cases:
        good, msg = add_fp(con, c)
        print(("  ok  " if good else "  FAIL") + f" {msg}")
        ok, bad = (ok + 1, bad) if good else (ok, bad + 1)
    con.close()
    print(f"\nfp_case written={ok} rejected={bad}")
    return 0 if bad == 0 else 1


def cmd_chain(args) -> int:
    data = _load(args.json)
    chains = data["chains"] if isinstance(data, dict) else data
    con = store.open_db(create=True)
    ok = bad = 0
    for c in chains:
        good, msg = add_chain(con, c)
        print(("  ok  " if good else "  FAIL") + f" {msg}")
        ok, bad = (ok + 1, bad) if good else (ok, bad + 1)
    con.close()
    print(f"\nchains written={ok} rejected={bad}")
    return 0 if bad == 0 else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.authoring")
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fp")
    f.add_argument("--class", dest="cls")
    f.add_argument("--json")
    f.add_argument("--list", action="store_true")
    f.set_defaults(fn=cmd_fp)

    c = sub.add_parser("chain")
    c.add_argument("--json", required=True)
    c.set_defaults(fn=cmd_chain)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
