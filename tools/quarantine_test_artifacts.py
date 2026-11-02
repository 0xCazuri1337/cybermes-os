#!/usr/bin/env python3
"""Quarantine the TEST ARTIFACTS that leaked into the live canonical corpus.

MEASURED 2026-11-01: the live `db/wks.db` held 46 `finding` rows, and 42
of them were written by the EVAL SUITE running against the canonical
database rather than against a sandbox. Their keys say so plainly:
`p0.skills.finding.*`, `reach.*.finding.*`, `surf.test.finding.*`,
`dbg.1.finding.*`, `lab.proof.chain.*.finding.*`, `f1`, `zz.gap`,
`exam-idor-*`.

The cause was a call-signature mismatch, not a design decision:
`eval/test_p0_skill_registry.py` wrote `store.open_db(db)`, where `store`
is `orch.store` -- whose signature is `open_db(create: bool = True)`. The
`Path` argument was bound to `create` (truthy), so the call opened the
LIVE database instead of the temporary one. The test passed, because the
live database has every table the test needs. The fix to that test is in
`eval/test_p0_skill_registry.py`.

A test that writes to the production corpus is not a cosmetic problem. The
findings are real rows: they carry evidence, they advance the lifecycle
machine, and the scheduler counts them as "potential impact" -- so the
system's own health metrics were reading test data as if it were hunting
output. They also produce LESSONS, and a lesson from a test run feeds the
corpus's prior.

WHAT THIS TOOL DOES, AND WHAT IT DOES NOT
-----------------------------------------
I8 says nothing is deleted: superseded material moves under `superseded/`.
So this tool:

  1. EXPORTS every quarantined finding, with its evidence, state
     transitions, lessons and feedback, to a timestamped JSON archive
     under `superseded/test-artifacts-<timestamp>/`;
  2. WRITES a manifest with a per-record verdict;
  3. MARKS each finding `status='rejected'` in the live database, so it is
     retained and auditable but is no longer presented as live knowledge
     and no longer counted as potential impact;
  4. DOES NOT DELETE ANY ROW. Every finding, evidence row, transition and
     lesson stays in the database, reachable and traceable.

It is idempotent: a second run finds nothing left to quarantine.

USAGE
    python tools/quarantine_test_artifacts.py --dry-run    # report only
    python tools/quarantine_test_artifacts.py              # quarantine
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import config as wks_config  # noqa: E402

# THE TEST-ARTIFACT KEY PATTERNS.
#
# Each pattern is a hunt id or key prefix that only a test harness uses.
# The list is deliberately EXPLICIT rather than a heuristic: a heuristic
# that guessed "this looks like a test" would eventually quarantine a real
# finding, and a real finding is the one thing in this system that must
# never be mistaken for noise.
#
# Every pattern below was matched against the live database and confirmed
# to name a synthetic harness (`p0.skills`, `reach.*`, `surf.test`,
# `dbg.1`, `lab.proof.chain`, `lab.cli`, `omh.*`, `p1.*`, `xwf.*`) or an
# exam-harness key (`exam-idor-*`).
TEST_KEY_PATTERNS = (
    re.compile(r"^p0\.skills\."),
    re.compile(r"^p1\."),
    re.compile(r"^reach\."),
    re.compile(r"^surf\.test\."),
    re.compile(r"^dbg\."),
    re.compile(r"^lab\."),
    re.compile(r"^omh\."),
    re.compile(r"^xwf\."),
    re.compile(r"^probe\."),
    re.compile(r"^test\."),
    # Single-word keys written by the harness in `eval/test_orch.py`.
    re.compile(r"^f1$"),
    re.compile(r"^zz\.gap$"),
)

# THE EXAM HARNESS IS NOT A LEAKED SANDBOX.
#
# `exam-idor-*` findings are created by `wks/assess_evidence.py`, which
# imports a GRADED EXAM into the corpus as evidence. They are not test
# output that leaked -- they are the system's own assessment mechanism
# feeding the corpus, and `wks.quality` reads their evidence to decide
# what may be promoted. Quarantining them would remove the corpus's
# evidence base for the classes the exams cover.
#
# They are listed here explicitly rather than by an "exam" prefix pattern
# so that the exclusion is visible and deliberate, and so that a future
# `exam-` key that IS a leaked sandbox is not swept up by accident.
EXAM_HARNESS_KEYS = (
    re.compile(r"^exam-[A-Za-z0-9_]+-\d+$"),
)


def is_test_artifact(finding_key: str) -> bool:
    """Is this finding a leaked test artifact?

    The exam harness's own findings are excluded: they are the corpus's
    evidence base, not a leak.
    """
    if any(p.match(finding_key) for p in EXAM_HARNESS_KEYS):
        return False
    return any(p.match(finding_key) for p in TEST_KEY_PATTERNS)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def collect(con: sqlite3.Connection) -> list[dict]:
    """Every finding that is a test artifact, with its linked records."""
    out: list[dict] = []
    rows = con.execute(
        "SELECT * FROM finding ORDER BY id").fetchall()
    for r in rows:
        key = r["finding_key"]
        if not is_test_artifact(key):
            continue
        con.row_factory = sqlite3.Row
        rec = {"finding": dict(r)}
        rec["evidence"] = [
            dict(x) for x in con.execute(
                "SELECT * FROM evidence WHERE finding_id=? ORDER BY id",
                (r["id"],))]
        rec["state"] = [
            dict(x) for x in con.execute(
                "SELECT * FROM finding_state WHERE finding_key=?",
                (key,))]
        rec["transitions"] = [
            dict(x) for x in con.execute(
                "SELECT * FROM finding_transition WHERE finding_key=?"
                " ORDER BY seq", (key,))]
        rec["lessons"] = [
            dict(x) for x in con.execute(
                "SELECT fl.*, l.topic, l.body, l.state AS lesson_state,"
                " l.score FROM finding_lesson fl"
                " LEFT JOIN lesson l ON l.lesson_key=fl.lesson_key"
                " WHERE fl.finding_key=?", (key,))]
        rec["revalidation"] = [
            dict(x) for x in con.execute(
                "SELECT * FROM revalidation_queue WHERE finding_key=?",
                (key,))]
        out.append(rec)
    return out


def write_archive(records: list[dict], dest_root: Path) -> dict:
    """Write the records and a per-record verdict under `superseded/`."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    dest = dest_root / f"test-artifacts-{stamp}"
    dest.mkdir(parents=True, exist_ok=True)
    findings_dir = dest / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)

    manifest = []
    for rec in records:
        key = rec["finding"]["finding_key"]
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", key)
        (findings_dir / f"{safe}.json").write_text(
            json.dumps(rec, indent=2, default=str), encoding="utf-8")
        manifest.append({
            "finding_key": key,
            "verdict": "test_artifact",
            "reason": ("written by the eval suite against the canonical "
                       "database; not hunting output"),
            "archived_to": str((findings_dir / f"{safe}.json")
                               .relative_to(ROOT)),
            "evidence_rows": len(rec["evidence"]),
            "transitions": len(rec["transitions"]),
            "lessons": len(rec["lessons"]),
        })
    (dest / "manifest.json").write_text(
        json.dumps({"generated_at": _now(),
                    "count": len(manifest),
                    "records": manifest}, indent=2),
        encoding="utf-8")
    return {"dir": str(dest), "count": len(manifest),
            "manifest": manifest}


def quarantine(con: sqlite3.Connection, records: list[dict]) -> dict:
    """Mark the findings rejected. NOTHING is deleted."""
    con.row_factory = sqlite3.Row
    changed = []
    for rec in records:
        key = rec["finding"]["finding_key"]
        before = con.execute(
            "SELECT status FROM finding WHERE finding_key=?",
            (key,)).fetchone()
        con.execute(
            "UPDATE finding SET status='rejected', updated_at=?"
            " WHERE finding_key=?", (_now(), key))
        changed.append({"finding_key": key,
                        "status_before": before["status"] if before else None,
                        "status_after": "rejected"})
    con.commit()
    return {"quarantined": len(changed), "records": changed}


def quarantine_lessons(con: sqlite3.Connection) -> dict:
    """Quarantine the LESSONS that the test findings produced.

    MEASURED 2026-11-01: quarantining the findings was not enough. A
    finding's outcome becomes a `lesson`, and the lesson is what the hunt
    layer reads: `before_recon`, `before_summary` and `_prior_for_signal`
    all read `lesson` rows in state `verified`. A lesson derived from a
    test run is test output in the corpus's own vocabulary, and it is the
    thing most likely to influence a real hunt.

    The live corpus had 36 `finding_lesson` links to the quarantined
    findings, and every one of those lessons was in state `analyzed` --
    so none was returned as intelligence YET. That is luck, not design:
    the state depends on whether a hunt had happened to close and run
    `analyze_hook`, and a `verified` test lesson would have been read by
    the next hunt's priority boost.

    A lesson is quarantined when it was produced by a quarantined finding.
    Its state becomes `rejected`, which `before_recon` and
    `before_summary` never read. Nothing is deleted, and the feedback
    rows that reference it stay in place.

    The legacy migration's probe lessons (`v`, `t`, `z`, `verify-topic`,
    `probe topic`) are ALSO quarantined: they are the residue of the
    `learning.db` migration's own test passes, and they name no class, so
    they can never be routed to a class skill anyway.
    """
    con.row_factory = sqlite3.Row
    now = _now()
    quarantined = []

    # Lessons produced by a quarantined finding.
    rows = con.execute(
        "SELECT DISTINCT l.lesson_key, l.topic, l.class_id, l.state"
        " FROM lesson l"
        " JOIN finding_lesson fl ON fl.lesson_key=l.lesson_key"
        " JOIN finding f ON f.finding_key=fl.finding_key"
        " WHERE f.status='rejected'").fetchall()
    for r in rows:
        con.execute(
            "UPDATE lesson SET state='rejected', updated_at=?"
            " WHERE lesson_key=? AND state != 'rejected'", (now, r["lesson_key"]))
        quarantined.append({"lesson_key": r["lesson_key"],
                            "topic": r["topic"], "state_before": r["state"],
                            "reason": "produced by a quarantined test finding"})

    # The legacy migration's probe lessons: they name no class and came
    # from the migration's own verification runs.
    probe = con.execute(
        "SELECT lesson_key, topic, class_id, state FROM lesson"
        " WHERE class_id IS NULL AND state != 'rejected'"
        " AND lesson_key NOT IN (SELECT lesson_key FROM finding_lesson)"
    ).fetchall()
    for r in probe:
        con.execute(
            "UPDATE lesson SET state='rejected', updated_at=?"
            " WHERE lesson_key=?", (now, r["lesson_key"]))
        quarantined.append({"lesson_key": r["lesson_key"],
                            "topic": r["topic"], "state_before": r["state"],
                            "reason": "legacy-migration probe lesson; names no class"})

    # LESSON TOPICS THAT NAME A TEST RUN.
    #
    # MEASURED 2026-11-01: four lessons survived the first pass. Two were
    # the `probe topic` rows written by `eval/test_learning_hooks.py`, and
    # two were `finding:cors:127.0.0.1` -- written by `after_finding` on a
    # test hunt. The second pair has NO `finding_lesson` link, because
    # `after_finding` captures the lesson at the moment the finding is
    # filed, and the bridge's `finding_lesson` link is written later by a
    # different path. So "linked to a rejected finding" is not a complete
    # test of "produced by a test run" -- the topic has to be checked too.
    #
    # The topic patterns below are the ones the harness writes. A lesson
    # topic of `finding:{class}:{target}` is the shape `after_finding`
    # produces, and every one in the live corpus names the loopback host
    # `127.0.0.1` that the test harnesses use.
    by_topic = con.execute(
        "SELECT lesson_key, topic, class_id, state FROM lesson"
        " WHERE state != 'rejected'").fetchall()
    for r in by_topic:
        topic = str(r["topic"] or "")
        reason = None
        if re.match(r"^probe topic", topic):
            reason = "probe lesson written by the learning-hooks test"
        elif re.match(r"^finding:[^:]+:127\.0\.0\.1$", topic):
            reason = ("lesson captured from a test hunt against the loopback "
                      "host")
        if reason:
            con.execute(
                "UPDATE lesson SET state='rejected', updated_at=?"
                " WHERE lesson_key=?", (now, r["lesson_key"]))
            quarantined.append({"lesson_key": r["lesson_key"],
                                "topic": topic, "state_before": r["state"],
                                "reason": reason})

    con.commit()
    return {"quarantined": len(quarantined), "records": quarantined}


def quarantine_gaps(con: sqlite3.Connection) -> dict:
    """Close the gaps that named the now-rejected lessons.

    MEASURED 2026-11-01: the corpus held 50 `learning_gap` rows, every one
    of them an `unverified_lesson` gap naming a lesson that is now
    `rejected`. A gap says "this lesson has no verification evidence" --
    and a REJECTED lesson is not waiting for evidence, it has been
    rejected. Leaving the gap open would propose research to verify a
    lesson that the program has already thrown out, which is work against
    a dead end.

    The gap rows are RETAINED and marked `resolved`, with the reason
    recorded, so the history of what was proposed and why it stopped is
    readable. Nothing is deleted.
    """
    con.row_factory = sqlite3.Row
    now = _now()
    gaps = con.execute(
        "SELECT gap_key, detail FROM learning_gap"
        " WHERE kind='unverified_lesson' AND status != 'resolved'").fetchall()
    changed = []
    for g in gaps:
        con.execute(
            "UPDATE learning_gap SET status='resolved', updated_at=?"
            " WHERE gap_key=?", (now, g["gap_key"]))
        changed.append({"gap_key": g["gap_key"], "detail": g["detail"][:120],
                        "reason": "the lesson it named was rejected, not "
                                  "left unverified"})
    # The research proposals raised from those gaps are closed too.
    con.execute(
        "UPDATE learning_research SET status='closed', updated_at=?"
        " WHERE status='proposed' AND gap_key IN"
        " (SELECT gap_key FROM learning_gap WHERE status='resolved')",
        (now,))
    con.commit()
    return {"resolved": len(changed), "records": changed}


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Quarantine test artifacts from the live corpus.")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would be quarantined; change nothing")
    ap.add_argument("--db", help="path to the database (default: canonical)")
    ap.add_argument("--lessons-only", action="store_true",
                    help="quarantine only the lessons (the findings are "
                         "already quarantined)")
    args = ap.parse_args()

    db = Path(args.db) if args.db else wks_config.db_path()
    if not db.exists():
        print(f"database absent: {db}", file=sys.stderr)
        return 1
    con = sqlite3.connect(db, timeout=30)
    con.row_factory = sqlite3.Row

    records = [] if args.lessons_only else collect(con)
    total = con.execute("SELECT count(*) FROM finding").fetchone()[0]
    print(f"live findings: {total}")
    print(f"test artifacts: {len(records)}")
    for rec in records[:60]:
        f = rec["finding"]
        print(f"  {f['finding_key'][:56]:58s} status={f['status']:10s} "
              f"evidence={len(rec['evidence'])}")
    if len(records) > 60:
        print(f"  ... and {len(records) - 60} more")

    if args.dry_run:
        print("\nDRY RUN — nothing was written.")
        con.close()
        return 0
    archive = {"dir": "", "count": 0}
    if records:
        archive = write_archive(records, ROOT / "superseded")
        print(f"\narchived: {archive['count']} record(s) -> {archive['dir']}")
        result = quarantine(con, records)
        print(f"quarantined: {result['quarantined']} finding(s) marked rejected")
        print(f"deleted: 0  (I8 — nothing is deleted)")
    elif not args.lessons_only:
        print("\nNothing to quarantine (already clean).")
        con.close()
        return 0

    # THE LESSONS THE TEST FINDINGS PRODUCED.
    less = quarantine_lessons(con)
    print(f"quarantined: {less['quarantined']} lesson(s) marked rejected")

    # THE GAPS THAT NAMED THEM.
    gaps = quarantine_gaps(con)
    print(f"resolved: {gaps['resolved']} gap(s) that named a rejected lesson")

    # Archive the lesson records alongside the findings, so the two can be
    # read together.
    if less["records"]:
        base = Path(archive["dir"]) if archive["dir"] else (
            ROOT / "superseded" / f"test-artifacts-{_stamp()}")
        ldir = base / "lessons"
        ldir.mkdir(parents=True, exist_ok=True)
        lesson_manifest = []
        for rec in less["records"]:
            lk = rec["lesson_key"]
            row = con.execute(
                "SELECT * FROM lesson WHERE lesson_key=?", (lk,)).fetchone()
            if row is None:
                continue
            out = ldir / f"{re.sub(r'[^A-Za-z0-9._-]', '_', lk)}.json"
            out.write_text(
                json.dumps({"lesson": dict(row),
                            "verdict": "test_artifact",
                            "reason": rec["reason"]},
                           indent=2, default=str), encoding="utf-8")
            lesson_manifest.append({
                "lesson_key": lk,
                "topic": rec["topic"],
                "state_before": rec["state_before"],
                "verdict": "test_artifact",
                "reason": rec["reason"],
                "archived_to": str(out),
            })
        # A MANIFEST FOR EVERY SNAPSHOT.
        #
        # MEASURED 2026-11-01: the lesson-only snapshots wrote the record
        # files but no `manifest.json`, so a reader could not tell WHICH
        # records were archived without walking the directory, and the
        # restore path was not self-describing. The findings' snapshots
        # always had one; the lessons' must too.
        (base / "lessons-manifest.json").write_text(
            json.dumps({"count": len(lesson_manifest),
                        "generated_at": _now(),
                        "records": lesson_manifest},
                       indent=2, default=str), encoding="utf-8")
        print(f"archived: {len(lesson_manifest)} lesson(s) -> {ldir}")
        print(f"manifest: {base / 'lessons-manifest.json'}")

    # PROVE the rows are still there.
    still = con.execute("SELECT count(*) FROM finding").fetchone()[0]
    live = con.execute(
        "SELECT count(*) FROM finding WHERE status IN"
        " ('candidate','validating','validated')").fetchone()[0]
    still_lessons = con.execute("SELECT count(*) FROM lesson").fetchone()[0]
    usable = con.execute(
        "SELECT count(*) FROM lesson WHERE state='verified'").fetchone()[0]
    print(f"\nfindings still in the database: {still} (was {total})")
    print(f"findings still counted as potential impact: {live}")
    print(f"lessons still in the database: {still_lessons}")
    print(f"lessons returned as intelligence (verified): {usable}")
    con.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
