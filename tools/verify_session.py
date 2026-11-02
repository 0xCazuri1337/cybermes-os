"""SESSION VERIFICATION GATE.

Answers one question with evidence: is every piece of learning from this session
present in `domains/` (the primary repository) AND reflected in the skills?

Checks, each of which can FAIL and say so:
  V1  every promoted item's claim appears in its class DIGEST.md
  V2  every promoted item's claim appears in its class SKILL.md
  V3  every class with promoted items has a HUNT.md runbook
  V4  every SKILL.md links its HUNT.md
  V5  every class touched this session has a topics/ debrief or refuted record
  V6  no unresolvable conflicts are being papered over (conflict table state)
  V7  projections are IDEMPOTENT — a second refresh writes nothing

Run:  python tools/verify_session.py [--verbose]
Exit: 0 only if every check passes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(r"C:\Users\Administrator\.hermes\cyber")
sys.path.insert(0, str(ROOT))

# Classes this session changed are DERIVED FROM THE DB, not hand-listed.
#
# MEASURED: the first version carried a hand-written TOUCHED set that included
# `csrf`, `otp` and `dns_enum` — classes this session never actually added an
# item to. The gate then failed on classes that were never touched, which is the
# same failure family as asserting a number that was not re-derived: the
# checklist disagreed with reality. It now asks the db which classes gained
# items on the session date.
SESSION_DATE = "2026-10-04"

FAILS: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f"  -- {detail}" if detail else ""))
    if not ok:
        FAILS.append(name)


def norm(s: str) -> str:
    return " ".join((s or "").split())


def digest_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    from wks import domains as D, store
    con = store.open_db(create=False)
    db = sqlite3.connect(str(ROOT / "db" / "wks.db"))
    db.row_factory = sqlite3.Row

    classes = [r[0] for r in db.execute(
        "SELECT id FROM bug_class WHERE status!='retired' ORDER BY id")]

    touched = sorted({r["class_id"] for r in db.execute("""
        SELECT DISTINCT class_id FROM item
        WHERE status='active' AND created_at >= ? AND item_key NOT LIKE '%.auto.%'
    """, (SESSION_DATE,))})
    print(f"classes with new items on {SESSION_DATE}: {touched}")

    # ---- V1/V2: every promoted claim reaches DIGEST and SKILL -------------
    print("\nV1/V2  promoted items present in domain knowledge + skills")
    tot = miss_d = miss_s = unrouted = 0
    for cid in classes:
        rows = db.execute("""
            SELECT i.claim FROM item i JOIN quality q ON q.item_id=i.id
            WHERE i.class_id=? AND i.status='active'
              AND q.validation_state='high_confidence'""", (cid,)).fetchall()
        if not rows:
            continue
        tot += len(rows)
        try:
            dp = D.class_subdir(cid, "knowledge", con) / "DIGEST.md"
            sp = D.class_subdir(cid, "skills", con) / "SKILL.md"
        except KeyError:
            unrouted += 1
            continue
        dt = norm(dp.read_text(encoding="utf-8")) if dp.exists() else ""
        st = norm(sp.read_text(encoding="utf-8")) if sp.exists() else ""
        for r in rows:
            key = norm(r["claim"])[:60]
            if key and key not in dt:
                miss_d += 1
                if args.verbose:
                    print(f"        DIGEST missing: {cid} :: {key[:60]}")
            if key and key not in st:
                miss_s += 1
                if args.verbose:
                    print(f"        SKILL  missing: {cid} :: {key[:60]}")
    check(f"V1 all {tot} promoted claims present in their DIGEST", miss_d == 0,
          f"{miss_d} missing")
    check(f"V2 all {tot} promoted claims present in their SKILL", miss_s == 0,
          f"{miss_s} missing")
    check("V2b every class routes to a domain folder", unrouted == 0,
          f"{unrouted} unroutable")

    # ---- V3/V4: hunt runbooks exist and are linked ------------------------
    print("\nV3/V4  derived hunt procedures live in domains/ and are linked")
    no_hunt, no_link = [], []
    for cid in classes:
        n = db.execute("""
            SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id
            WHERE i.class_id=? AND i.status='active'
              AND q.validation_state='high_confidence'""", (cid,)).fetchone()["n"]
        if not n:
            continue
        try:
            sdir = D.class_subdir(cid, "skills", con)
        except KeyError:
            continue
        h = sdir / "HUNT.md"
        s = sdir / "SKILL.md"
        if not h.exists():
            no_hunt.append(cid)
        if s.exists() and "HUNT.md" not in s.read_text(encoding="utf-8"):
            no_link.append(cid)
    check("V3 every classed-with-evidence has a HUNT.md runbook", not no_hunt,
          f"missing: {no_hunt[:6]}")
    check("V4 every SKILL.md links its HUNT.md", not no_link,
          f"unlinked: {no_link[:6]}")

    # ---- V5: this session's classes carry a written record ----------------
    print("\nV5  this session's classes carry a domain-side record")
    missing_record = []
    for cid in touched:
        # NOTE: `topics/` is NOT a registered class subdirectory — domains.py
        # raises deliberately ("Add it to CLASS_SUBDIRS deliberately"). The
        # session notes therefore belong in `knowledge/`, which is canonical.
        # This check reads knowledge/, not topics/.
        try:
            kdir = D.class_subdir(cid, "knowledge", con)
        except KeyError:
            missing_record.append(f"{cid}(unroutable)")
            continue
        notes = sorted(p.name for p in kdir.glob("*.md")) if kdir.exists() else []
        session_notes = [n for n in notes
                         if n.startswith("session-") or n.startswith("refuted-")]
        if not session_notes:
            missing_record.append(cid)
    check("V5 every session-touched class has a topics/ note", not missing_record,
          f"no record: {missing_record}")

    # ---- V6: conflicts surfaced, not guessed ------------------------------
    print("\nV6  contradictions surfaced rather than silently resolved")
    open_c = db.execute("SELECT count(*) n FROM conflict WHERE status='open'").fetchone()["n"]
    unresolved = db.execute("""
        SELECT count(*) n FROM conflict
        WHERE status='open' AND (resolution IS NULL OR trim(resolution)='')
    """).fetchone()["n"]
    check("V6 no conflict left open without a recorded resolution", unresolved == 0,
          f"{unresolved} unresolved of {open_c} open")

    # ---- V7: projections are idempotent ----------------------------------
    print("\nV7  projections are idempotent (a refresh writes nothing)")
    before = {p: digest_of(p) for p in
              list(ROOT.glob("domains/**/DIGEST.md")) +
              list(ROOT.glob("domains/**/SKILL.md")) +
              list(ROOT.glob("domains/**/HUNT.md"))}
    r = subprocess.run([sys.executable, "-m", "wks.cli", "skills-sync", "--apply"],
                       capture_output=True, text=True, cwd=str(ROOT))
    after = {p: digest_of(p) for p in before if p.exists()}
    changed = [p.name for p, h in before.items() if after.get(p) != h]
    check("V7 re-running the projection changed nothing", not changed,
          f"{r.stdout.strip()[:60]} | changed: {changed[:4]}")
    r2 = subprocess.run([sys.executable, "tools/write_hunt_docs.py"],
                        capture_output=True, text=True, cwd=str(ROOT))
    check("V7b re-running the hunt writer changed nothing",
          "written/updated: 0" in r2.stdout, r2.stdout.strip()[:70])

    db.close()
    con.close()
    print()
    if FAILS:
        print(f"SESSION VERIFICATION FAILED ({len(FAILS)}): {FAILS}")
        return 1
    print("SESSION VERIFICATION PASSED - every item and update is in domains/ "
          "and reflected in the skills.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())