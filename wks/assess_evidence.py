"""Close the assessment -> evidence loop.

The audit's finding: 62 skills, 1 mastery record, and an `evidence` table with
13 purpose-built columns (request_raw, response_raw, payload, sha256,
provenance) holding ZERO rows. A graded exam produced a verdict and nothing
else; the corpus could not see that a solver had actually solved an IDOR lab.

This imports graded exam results into `evidence` and `finding`, subject to the
rules the mastery layer already enforces -- because an evidence import that
ignores them would be a back door around the anti-fabrication gate:

  * a `finding` row is created ONLY for a verdict of PASS;
  * a DISQUALIFIED exam contributes NOTHING (its own guard exists because a
    disqualified run once closed a gate);
  * `evidence.sha256` is computed over the solver report's bytes, so tampering
    after the fact is detectable;
  * `provenance` records the GRADE.json path, the solver report path and size,
    and the verdict -- so a reader can re-derive the import;
  * NO mastery gate is opened here. `wks.mastery.record` stays the only writer
    of gates, and it re-validates. This module makes evidence *visible*; it
    does not make anything pass.

Idempotent: re-running updates the same rows rather than duplicating them.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wks import config, store

EXAMS = config.ROOT / "eval" / "exams"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def scan() -> list[dict[str, Any]]:
    """Every exam directory, with everything needed to judge admissibility."""
    out: list[dict[str, Any]] = []
    if not EXAMS.is_dir():
        return out
    for d in sorted(EXAMS.iterdir()):
        if not d.is_dir():
            continue
        grade_p = d / "GRADE.json"
        report_p = d / "SOLVER_REPORT.md"
        gt_p = d / "ground_truth.json"
        disq_p = d / "DISQUALIFIED.json"
        rec: dict[str, Any] = {
            "exam_id": d.name,
            "dir": str(d),
            "has_grade": grade_p.exists(),
            "has_report": report_p.exists(),
            "report_bytes": report_p.stat().st_size if report_p.exists() else 0,
            "has_ground_truth": gt_p.exists(),
            "disqualified": disq_p.exists(),
            "disqualify_reasons": [],
            "verdict": None,
            "class_id": None,
        }
        if disq_p.exists():
            try:
                rec["disqualify_reasons"] = json.loads(
                    disq_p.read_text(encoding="utf-8")).get("reasons", [])
            except (OSError, ValueError):
                rec["disqualify_reasons"] = ["unreadable DISQUALIFIED.json"]
        if gt_p.exists():
            try:
                rec["class_id"] = json.loads(
                    gt_p.read_text(encoding="utf-8")).get("class_id")
            except (OSError, ValueError):
                pass
        if grade_p.exists():
            try:
                g = json.loads(grade_p.read_text(encoding="utf-8"))
                rec["verdict"] = g.get("verdict")
                rec["class_id"] = rec["class_id"] or g.get("class_id")
                rec["score"] = g.get("score")
            except (OSError, ValueError) as e:
                rec["verdict"] = f"UNREADABLE: {e}"
        out.append(rec)
    return out


def admissibility(e: dict[str, Any]) -> tuple[bool, str]:
    """May this exam contribute evidence at all? Mirrors mastery._validate_evidence.

    Deliberately the SAME bar, including the 400-byte floor and the requirement
    of a real solver report -- otherwise a hand-written fixture would import
    evidence and the exam gate would look earned without a solver ever running.
    """
    if e["disqualified"]:
        return False, f"DISQUALIFIED: {e['disqualify_reasons'][:1]}"
    if not e["has_grade"]:
        return False, "no GRADE.json"
    if e["verdict"] is None:
        return False, "grade carries no verdict"
    if e["verdict"] != "PASS":
        return False, f"verdict={e['verdict']} (only PASS is evidence of capability)"
    if not e["has_report"]:
        return False, "PASS with no SOLVER_REPORT.md is not evidence"
    if e["report_bytes"] < 400:
        return False, f"SOLVER_REPORT.md is {e['report_bytes']}B (<400B stub)"
    return True, "admissible"


def evidence_admissibility(
    provenance: str | None,
    *,
    exams: dict[str, dict[str, Any]] | None = None,
) -> tuple[bool, str]:
    """May this evidence row's PROVENANCE support an evidence claim?

    An evidence row records where it came from in its `provenance` column.
    Two kinds of provenance exist in practice:

      * HTTP captures -- a raw request/response, recorded as free text
        ("curl GET http://..."). These are NOT exam-backed, and this
        function reports them as `not_exam_backed` rather than judging
        them: a live capture is evidence on its own terms.
      * Exam-backed imports -- a JSON document written by
        `wks.assess_evidence.import_all`, naming the exam's GRADE.json,
        its SOLVER_REPORT.md and the verdict.

    The function is deliberately STRICT about the exam-backed case, because
    that is where the bar matters: an evidence row may only close a gate
    if the exam it names actually PASSED, is not disqualified, and has a
    real solver report.

    PATH HANDLING. The recorded paths are produced on whichever platform ran
    the exam, so a Windows run records
    "C:\\Users\\...\\eval\\exams\\idor-5150\\GRADE.json" and a POSIX run
    records "/mnt/c/.../idor-5150/GRADE.json". `os.path.dirname` on POSIX
    does not split a backslash path, so a Windows path parsed on POSIX
    yields an EMPTY exam id -- which reads as "exam not found" and, before
    this function existed, made every row unjudgeable. Both separators are
    normalised here, because a path written by one platform must be
    readable by another.

    Returns `(ok, reason)`. The reason names the specific failure.
    """
    prov = (provenance or "").strip()
    if not prov:
        return False, "no provenance recorded"

    # Is this exam-backed provenance, or a live HTTP capture?
    #
    # MEASURED 2026-11-01: the first version decided this with a TEXTUAL
    # test -- `if "grade" not in prov`. That is wrong in both directions:
    # a malformed string that happens to contain the word "grade" was
    # parsed as exam-backed, and a JSON document that merely MENTIONED
    # "grade" was judged as one; while a provenance document that named no
    # exam at all but did not contain the word was waved through as a live
    # capture. The test is now STRUCTURAL: parse first, then ask what the
    # parsed document IS.
    try:
        parsed = json.loads(prov)
    except (ValueError, TypeError):
        parsed = None

    if parsed is None:
        # Not JSON at all. This is a free-text capture ("curl GET http://…")
        # -- legitimate evidence, not governed by the exam bar.
        if prov.startswith("{") or prov.startswith("["):
            return False, ("provenance looks like a JSON document but is not "
                           f"parseable: {prov[:120]!r}")
        return True, "not exam-backed (live capture)"

    if not isinstance(parsed, dict):
        return False, (f"provenance is not a JSON object "
                       f"(got {type(parsed).__name__})")

    # A JSON object IS an exam-backed provenance document -- it is the
    # shape `import_all` writes. It must therefore name an exam and carry
    # a verdict. There is no third kind.
    meta = parsed
    verdict = meta.get("verdict")
    if verdict != "PASS":
        return False, (f"exam verdict is {verdict!r} "
                       "(only PASS is evidence of capability)")

    grade_path = _normalise_path(meta.get("grade") or "")
    exam_id = Path(grade_path).parent.name if grade_path else ""
    if not exam_id:
        return False, "provenance names no exam (no grade path)"

    if exams is None:
        exams = {e["exam_id"]: e for e in scan()}
    exam = exams.get(exam_id)
    if exam is None:
        # The exam directory is gone, but the row records what was
        # measured at import time. Judge the RECORD.
        report = _normalise_path(meta.get("report") or "")
        has_report = bool(report) and Path(report).exists()
        exam = {"exam_id": exam_id,
                "verdict": verdict,
                "has_grade": bool(meta.get("grade")),
                "has_report": has_report,
                "report_bytes": (Path(report).stat().st_size
                                 if has_report else 0),
                "disqualified": False,
                "disqualify_reasons": []}
    ok, why = admissibility(exam)
    if not ok:
        return False, f"exam {exam_id}: {why}"
    return True, f"exam {exam_id}: PASS and admissible"


def _normalise_path(path: str) -> str:
    """A path that can be split by `pathlib` on ANY platform.

    A Windows path uses backslashes; `Path` on POSIX treats a backslash as
    an ordinary character, so "C:\\a\\b" is one filename whose parent is
    ".". Replacing the separator makes the path parseable everywhere.
    """
    return (path or "").replace("\\", "/")


def import_all(con: sqlite3.Connection, *, apply: bool = False) -> dict[str, Any]:
    scanned = scan()
    rows: list[dict[str, Any]] = []
    for e in scanned:
        ok, why = admissibility(e)
        rec = {**e, "admissible": ok, "reason": why}
        if ok:
            gp = Path(e["dir"]) / "GRADE.json"
            rp = Path(e["dir"]) / "SOLVER_REPORT.md"
            g = json.loads(gp.read_text(encoding="utf-8"))
            report_text = rp.read_text(encoding="utf-8", errors="replace")
            rec["finding"] = {
                "finding_key": f"exam-{e['exam_id']}",
                "title": (g.get("finding_titles") or [f"graded exam {e['exam_id']}"])[0]
                          if isinstance(g.get("finding_titles"), list)
                          and g["finding_titles"] else f"graded exam {e['exam_id']}",
                "class_id": e["class_id"],
                "status": "validated",
                "severity": "info",
                "validation_json": json.dumps(
                    {"source": "exam", "exam_id": e["exam_id"],
                     "verdict": g.get("verdict"), "score": g.get("score")},
                    sort_keys=True),
                "validator_run": "eval/grade_exam.py",
                "report_path": str(rp),
            }
            rec["evidence"] = {
                "exam_id": e["exam_id"], "class_id": e["class_id"],
                "kind": "repro",
                "target": e["exam_id"],
                "endpoint": None,
                "sha256": _sha(report_text),
                "provenance": json.dumps(
                    {"grade": str(gp), "report": str(rp),
                     "report_bytes": e["report_bytes"], "verdict": g.get("verdict"),
                     "score": g.get("score"),
                     "imported_by": "wks.assess_evidence"},
                    sort_keys=True),
                "request_raw": None,
                "response_raw": report_text[:20000],
            }
        rows.append(rec)

    written = {"findings": 0, "evidence": 0}
    if apply:
        # `finding` and `evidence` are ORCHESTRATION tables, and this
        # function writes them directly. MEASURED 2026-11-01: the raw
        # INSERTs carried no sanction, so on a connection with the
        # ownership authorizer installed they failed with "not
        # authorized" -- the exam-to-evidence import was broken at
        # runtime while its own dry-run (which writes nothing) reported
        # success.
        #
        # The crossing is now declared: `owner_write(con, ORCH)` lifts the
        # restriction for the duration of the sanctioned write and
        # restores it afterwards, so every OTHER write on this connection
        # is still refused. The crossing is greppable at the call site.
        from wks import ownership as _own
        with _own.owner_write(con, _own.ORCH):
            for rec in rows:
                if not rec["admissible"]:
                    continue
                f = rec["finding"]
                con.execute(
                    """INSERT INTO finding (finding_key,title,class_id,status,severity,
                           validation_json,validator_run,report_path,provenance,
                           created_at,updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT(finding_key) DO UPDATE SET
                           title=excluded.title, class_id=excluded.class_id,
                           status=excluded.status, validation_json=excluded.validation_json,
                           validator_run=excluded.validator_run,
                           report_path=excluded.report_path,
                           provenance=excluded.provenance, updated_at=excluded.updated_at""",
                    (f["finding_key"], f["title"], f["class_id"], f["status"],
                     f["severity"], f["validation_json"], f["validator_run"],
                     f["report_path"], "EXAM_FIXTURE", _now(), _now()))
                written["findings"] += 1
                fid = con.execute("SELECT id FROM finding WHERE finding_key=?",
                                  (f["finding_key"],)).fetchone()["id"]
                ev = rec["evidence"]
                con.execute(
                    """INSERT INTO evidence (task_key,finding_id,kind,target,
                           endpoint,sha256,provenance,response_raw,class_id,exam_id,captured_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)
                       ON CONFLICT DO NOTHING""",
                    (f"exam.{rec['exam_id']}", fid, ev["kind"], ev["target"],
                     ev["endpoint"], ev["sha256"], ev["provenance"], ev["response_raw"],
                     ev["class_id"], ev["exam_id"], _now()))
                written["evidence"] += 1
            # The class link is an UPDATE on `evidence`, which is also an
            # ORCHESTRATION table -- so it belongs inside the same
            # sanctioned crossing. MEASURED 2026-11-01: it sat outside
            # the block and would have been refused.
            for rec in rows:
                if not rec["admissible"] or not rec["class_id"]:
                    continue
                con.execute(
                    """UPDATE evidence SET class_id=?
                       WHERE exam_id=? AND (class_id IS NULL OR class_id='')""",
                    (rec["class_id"], rec["exam_id"]))
            con.commit()

    return {
        "exams_scanned": len(scanned),
        "admissible": [r["exam_id"] for r in rows if r["admissible"]],
        "excluded": [{"exam_id": r["exam_id"], "reason": r["reason"]}
                     for r in rows if not r["admissible"]],
        "written": written,
        "note": ("imports evidence and a validated finding. It opens NO mastery "
                 "gate: wks.mastery.record remains the only writer of gates and "
                 "re-validates from the same files."),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wks.assess_evidence")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    con = store.open_db(create=a.apply)
    out = import_all(con, apply=a.apply)
    con.close()
    if a.json:
        print(json.dumps(out, indent=1, default=str))
        return 0
    print(f"exams scanned : {out['exams_scanned']}")
    print(f"admissible    : {out['admissible']}")
    print("excluded:")
    for e in out["excluded"]:
        print(f"  {e['exam_id']:12} {e['reason']}")
    if a.apply:
        print(f"written       : {out['written']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())