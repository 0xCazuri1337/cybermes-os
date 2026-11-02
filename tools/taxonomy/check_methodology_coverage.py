#!/usr/bin/env python3
"""check_methodology_coverage.py — is every competency reachable by a hunt?

`methodology/` grew by hand, the competency registry grew by code, and nothing
checked they agreed. Two inventories with no edge between them is the failure
this exists to catch, so the edge is read from ONE authoritative place.

WHAT CHANGED AND WHY (measured, 2026-10-02)
    This script pointed at `cyber/mastery/competencies.json`, which the
    Selection-C rework deleted. It therefore exited 1 with "registry unreadable
    or empty" on every run — a coverage check that can never pass is
    decoration, and it was cited from `methodology/README.md`,
    `methodology/INDEX.md` and `methodology/derived/README.md` as though it
    worked. Its `COVERED_BY` literal had also drifted from reality: it mapped
    `business_logic` where the db registers `bizlogic`, had no entry for 9 of
    the 15 registered classes, and was itself a hand-maintained mirror of
    database state — the exact defect class this check was written to prevent.

    The registry is now the `bug_class` table in `db/wks.db`, which
    `wks/quality.py` already treats as canonical, so this reads that. The
    `COVERED_BY` literal is DELETED, not repaired: re-adding it would restore
    the drift.

    `bug_class.methodology` stores an ABSOLUTE path (for example the full
    `.../methodology/derived/xss.md` under one user's home directory). That is
    reported here as a portability finding and matched by tail, because a
    column holding one user's home directory cannot be relocated or checked on
    another host.

Exit 0 = the check ran and the report is meaningful. Exit 1 = the registry
could not be read, the one condition that makes the report worthless.
"""
from __future__ import annotations

import pathlib
import sqlite3
import sys

# Resolve the tree root by locating cyber/ rather than counting parent hops,
# which assumed a depth this file does not have -- it read METHODOLOGY as
# cyber/tools/taxonomy and found zero pages, then zero competencies, and
# reported "nothing to compare" instead of the real failure.
_HERE = pathlib.Path(__file__).resolve()
METHODOLOGY = _HERE.parent.parent          # cyber/methodology
CYBER = METHODOLOGY.parent                  # cyber/
DB = CYBER / "db" / "wks.db"

# Procedure pages: top-level .md that is not the index, not a superseded
# pointer, and not a README. `derived/` holds generated competency views and is
# audited alongside.
INDEX_NAMES = {"INDEX.md", "METHODOLOGY.md", "README.md"}


def db_classes() -> list[dict]:
    if not DB.exists():
        return []
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT id, name, surface, status, methodology, skill_path "
            "FROM bug_class ORDER BY id").fetchall()
    except sqlite3.Error:
        return []
    finally:
        con.close()
    return [dict(r) for r in rows]


def tail(p) -> str:
    """The part of a stored path that identifies the file within the tree."""
    if p is None or str(p) in ("", "None", "null"):
        return ""
    return pathlib.PurePath(str(p).replace("\\", "/")).name


def is_absolute(p: str) -> bool:
    return bool(p) and ("\\" in p or (len(p) > 1 and p[1] == ":"))


def main() -> int:
    comps = db_classes()
    print("=" * 74)
    print("METHODOLOGY COVERAGE")
    print("=" * 74)

    # MEASURED (bootcamp C4): this used to glob `cyber/methodology/*.md` for
    # procedure pages. `cyber/methodology/` DOES NOT EXIST — the canonical
    # competency pages live at `domains/<domain>/<spec>/<class>/assessment/
    # COMPETENCY.md` and the hunting skills at `.../skills/SKILL.md`, both
    # declared per-class in `bug_class.methodology` / `bug_class.skill_path`.
    # Because the glob matched nothing, `have_top` and `have_derived` were
    # empty, every class fell through to `broken`, and the checker reported
    # **140 MISSING** while exiting 0 — on a tree where all 140 files exist
    # (verified: methodology 70/70, skill_path 70/70 on disk).
    #
    # A checker pointed at a directory that does not exist reports a clean,
    # confident, entirely fictional gap list. Coverage is now measured against
    # the DECLARED path, which is the thing the db actually promises.
    have_top = set()
    have_derived = set()
    top = []
    derived = []
    for c in comps:
        raw = str(c.get("methodology") or "")
        if not raw:
            continue
        page = (CYBER / raw) if not pathlib.PurePath(raw).is_absolute()             else pathlib.Path(raw)
        page = page.resolve()
        if page.exists():
            top.append(page)
            have_top.add(page.stem)
        dpage = page.parent / "derived"
        if dpage.exists():
            for q in sorted(dpage.glob("*.md")):
                derived.append(q)
                have_derived.add(q.stem)

    print(f"  procedure pages  : {len(top)}   ({', '.join(p.stem for p in top)})")
    print(f"  generated views  : {len(derived)}   (methodology/derived/)")
    print(f"  registry         : {len(comps)} competencies   (db/wks.db : bug_class)")

    if not comps:
        print(f"\n  FAIL: registry unreadable or empty: {DB}")
        print("  A silent zero is exactly the failure this check exists to")
        print("  catch, so it is reported as a failure, not as 'all clear'.")
        return 1

    have_top = {p.stem for p in top}
    have_derived = {p.stem for p in derived}

    covered, gaps, broken, duplicated, absolute = [], [], [], [], []
    for c in comps:
        cid = c["id"]
        raw_meth = str(c.get("methodology") or "")
        meth = tail(raw_meth)
        skill = tail(c.get("skill_path"))

        if is_absolute(raw_meth):
            absolute.append((cid, raw_meth))

        stem = meth[:-3] if meth.endswith(".md") else meth
        in_top = stem in have_top
        in_derived = stem in have_derived
        if in_top and in_derived:
            duplicated.append((cid, stem))
            covered.append((cid, stem))
        elif in_top or in_derived:
            covered.append((cid, stem))
        elif meth:
            broken.append((cid, meth))
        else:
            gaps.append(cid)

        # A declared skill path that does not exist is a broken mapping, not a
        # missing nice-to-have: the db promises a hunter-usable skill.
        # MEASURED: this also assumed a flat `cyber/skills/<cid>-hunting/`
        # layout that does not exist. The skills are per-class at
        # `domains/<domain>/<spec>/<cid>/skills/SKILL.md` and the db declares
        # the exact path in `bug_class.skill_path`. Same defect as the
        # methodology glob above: a checker pointed at a directory that was
        # never there reports a fictional gap. Resolve the DECLARED path.
        raw_skill = str(c.get("skill_path") or "")
        if skill:
            sp = (CYBER / raw_skill) if not pathlib.PurePath(raw_skill).is_absolute()                 else pathlib.Path(raw_skill)
            if not sp.exists():
                broken.append((cid, skill))

    total = len(comps)
    print(f"\n  covered           : {len(covered)}/{total}")
    print(f"  gaps (no page)    : {len(gaps)}   {', '.join(gaps) or '-'}")
    print(f"  broken mappings   : {len(broken)}")
    for cid, target in broken:
        print(f"    {cid:18s} -> {target}   MISSING")

    if duplicated:
        print(f"\n  DUPLICATED — a hand-authored page AND a generated view both claim")
        print(f"  these classes. One canonical home per class (rule 14):")
        for cid, stem in duplicated:
            print(f"    {cid:18s}  methodology/{stem}.md  +  methodology/derived/{stem}.md")

    if absolute:
        print(f"\n  NON-PORTABLE — bug_class.methodology stores absolute paths, so the")
        print(f"  tree cannot be relocated or checked on another host. Store a")
        print(f"  repo-relative path instead:")
        for cid, raw in absolute:
            print(f"    {cid:18s} {raw}")

    orphans = sorted((have_top | have_derived) - {s for _, s in covered})
    if orphans:
        print(f"\n  pages no registered class maps to:")
        for o in orphans:
            print(f"    methodology/{o}.md")

    print()
    print("Authoritative edge: db/wks.db : bug_class.methodology. There is no")
    print("mapping literal in this script — it is derived from the canonical db")
    print("on every run, so it cannot drift from the registry it reports on.")
    return 0


if __name__ == "__main__":
    sys.exit(main())