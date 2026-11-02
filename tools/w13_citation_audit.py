"""Canonical citation audit for a mastery artifact directory.

MEASURED: the checker template in CONTRACT.md scoped its regex to the class
prefix -- a literal-bracket class-prefix pattern -- and matched citations
against `WHERE class_id = <class>`. That combination has a hole the children
inherited:

  T1 (fabricated key, right prefix)   -> caught
  T3 (real key, under_review)         -> caught
  T2 (key with the WRONG class prefix) -> NOT caught, silently ignored

A citation the regex never matches is invisible, so a hallucinated
`[sqlis.technique.union_select]` or a cross-class `[race.prereq.x]` reads as a
clean pass. That is the measured lesson "a filter that matches nothing returns
a clean, confident, EMPTY report" in a new place: the artifact is scored 0
errors not because it is clean but because the check never looked.

This audit matches ANY item-key-shaped token, then resolves it against the db,
so a wrong prefix, a cross-class key and a fabricated key are all VISIBLE and
classified rather than ignored.

Read-only. Exit 1 on any real problem.

Usage:  python tools/w13_citation_audit.py <class_id> [artifact_dir]
"""
from __future__ import annotations

import os
import re
import sqlite3
import sys

WKS = os.environ.get("WKS_ROOT", ".")
os.chdir(WKS)

# `<class_id>.<kind>.<name>` — the class segment is captured so a wrong prefix
# is REPORTED instead of filtered out.
KEY_RE = re.compile(r"\[([a-z0-9_]+)\.([a-z_]+)\.([a-z0-9_\-]+)\]")


def audit(class_id: str, art: str) -> int:
    db = sqlite3.connect(f"{WKS}/db/wks.db")
    own = {r[0]: r[1] for r in db.execute(
        "SELECT i.item_key, q.validation_state FROM item i "
        "JOIN quality q ON q.item_id = i.id WHERE i.class_id = ?", (class_id,))}
    every = {r[0]: r[1] for r in db.execute(
        "SELECT i.item_key, q.validation_state FROM item i "
        "JOIN quality q ON q.item_id = i.id")}

    problems: list[tuple[str, str, str]] = []
    cited: set[str] = set()
    for fname in sorted(os.listdir(art)):
        if not fname.endswith(".md"):
            continue
        text = open(os.path.join(art, fname), encoding="utf-8").read()
        for cls, kind, name in KEY_RE.findall(text):
            key = f"{cls}.{kind}.{name}"
            cited.add(key)
            if key in own:
                if own[key] not in ("high_confidence", "supported"):
                    problems.append((fname, key, f"UNPROMOTED ({own[key]})"))
                continue
            if key in every:
                problems.append((fname, key, "CROSS_CLASS (real key, wrong class)"))
            else:
                problems.append((fname, key, "UNKNOWN (no such item_key in db)"))

    print(f"class={class_id} dir={art}")
    print(f"  own_items={len(own)} cited={len(cited)} problems={len(problems)}")
    for f, k, why in problems[:30]:
        print(f"  {why:42} {f}  {k}")
    if not cited:
        print("  NOTE: zero citations found -- the artifact is ungrounded")

    # Distinct kinds actually used, so a reviewer can see the spread.
    kinds = sorted({k.split(".")[1] for k in cited})
    print(f"  kinds_cited={','.join(kinds)}")
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    cls = sys.argv[1]
    d = sys.argv[2] if len(sys.argv) > 2 else f"learning/sessions/methodology-bootcamp/{cls}"
    raise SystemExit(audit(cls, d))