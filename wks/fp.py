"""False-positive learning (brief §17).

A false positive is not a failed hunt; it is the most expensive kind of training
data available, because the hunter already spent the effort and already formed
the wrong hypothesis. Capturing it produces a durable rejection rule that stops
the same report being written twice.

    python -m wks.fp log --class idor \
        --hypothesis "GET /api/invoice/{id} returns another user's invoice" \
        --looked-because "status 200 and a populated JSON body for an id I do not own" \
        --test "re-ran with a second account whose id is outside my tenant" \
        --invalidated-by "response was byte-identical to my own invoice; the id is scoped by tenant server-side" \
        --missed "checked whether the object was tenant-scoped before assuming ownership" \
        --rule "a 200 with data is not a finding until the same id is shown to resolve differently for a second identity"

    python -m wks.fp list --class idor
"""
from __future__ import annotations

import argparse
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import config, retrieval, store  # noqa: E402


def slug(s: str, n: int = 40) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")[:n].strip("-")


def log(args) -> int:
    con = store.open_db(create=True)
    key = args.key or f"{args.class_id}.fp.{slug(args.hypothesis)}"
    if store.get_class(con, args.class_id) is None:
        print(f"unknown class {args.class_id!r}")
        return 1
    if not args.invalidated_by or not args.rule:
        print("--invalidated-by and --rule are required: an FP with no rejection "
              "rule teaches nothing")
        return 1
    fp_id = store.add_fp(
        con, key, args.class_id, args.hypothesis, args.test, args.invalidated_by,
        args.rule,
        looked_vulnerable_because=args.looked_because,
        early_signal_missed=args.missed, skill_updated=args.skill_updated,
    )
    con.commit()
    m = store.get_class(con, args.class_id)
    con.execute(
        "UPDATE bug_class SET last_reviewed=? WHERE id=?", (store.now(), args.class_id))
    con.commit()
    print(f"logged FP {key} (id={fp_id}) for class {args.class_id}")

    # The rejection rule is only useful if it reaches the skill and the class doc.
    from wks import skillgen
    r = skillgen.write_skill(con, args.class_id)
    print(f"skill regenerated: {'yes' if r['changed'] else 'no change'}")
    print(f"next: review `skills/{args.class_id}-hunting/SKILL.md` "
          f"-> 'Rejected before you report'")
    con.close()
    return 0


def list_fps(args) -> int:
    con = store.open_db(create=False)
    q = "SELECT * FROM fp_case"
    p: list = []
    if args.class_id:
        q += " WHERE class_id=?"
        p.append(args.class_id)
    q += " ORDER BY id"
    rows = con.execute(q, p).fetchall()
    if not rows:
        print("no false-positive cases recorded")
    for r in rows:
        print(f"\n[{r['fp_key']}]  class={r['class_id']}")
        print(f"  hypothesis : {r['hypothesis']}")
        if r["looked_vulnerable_because"]:
            print(f"  looked like: {r['looked_vulnerable_because']}")
        print(f"  test       : {r['test_performed']}")
        print(f"  killed by  : {r['invalidated_by']}")
        if r["early_signal_missed"]:
            print(f"  missed     : {r['early_signal_missed']}")
        print(f"  RULE       : {r['rejection_rule']}")
    con.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.fp")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("log")
    a.add_argument("--class", dest="class_id", required=True)
    a.add_argument("--key")
    a.add_argument("--hypothesis", required=True)
    a.add_argument("--looked-because", dest="looked_because")
    a.add_argument("--test", required=True)
    a.add_argument("--invalidated-by", dest="invalidated_by", required=True)
    a.add_argument("--missed", dest="missed")
    a.add_argument("--rule", required=True)
    a.add_argument("--skill-updated", dest="skill_updated")
    a.set_defaults(fn=log)

    a = sub.add_parser("list")
    a.add_argument("--class", dest="class_id")
    a.set_defaults(fn=list_fps)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
