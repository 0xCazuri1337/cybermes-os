"""Grade a black-box exam against hidden ground truth.

A solver's report is a self-report. It says "I found an IDOR"; that carries the
same evidentiary weight as a child claiming it ingested 20 items -- none. This
module re-derives the verdict from the LAB, not from the prose:

  * detection  -- did the report name the mechanism the lab actually plants?
  * evidence   -- is there a reproduction the lab can confirm?
  * no-FP      -- did the report AVOID the trap the lab deliberately planted?
  * no-halluc  -- does it assert findings the lab cannot support?

That last one is the important one. A report that invents a response is
distinguishable from a report that misreads one, and only one of them is
dangerous to learn from.

MEASURED FAILURE OF THE FIRST VERSION OF THIS FILE, kept because it is the
lesson: a whole markdown report can arrive as ONE line (soft-wrapped source with
collapsed newlines), so any line-based "is this a finding title" heuristic
matches the entire document and flags everything -- including a 178-line report
that found the bug correctly and rejected ten hypotheses rigorously. Parse the
report into SECTIONS and FINDINGS structurally. A grader that punishes a
correct report is worse than no grader, and the only way to find out is to grade
a known-good report and watch it fail.

    python eval/grade_exam.py eval/exams/idor-9091
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Vocabulary that counts as naming the mechanism. Product names are deliberately
# absent: recognition means recognising the mechanism, not guessing the label.
CONCEPT_MARKERS: dict[str, tuple[str, ...]] = {
    "idor": ("idor", "bola", "insecure direct object reference",
             "object level authorization", "object-level authorization",
             "horizontal privilege", "another user's", "other user's",
             "not the owner", "ownership check"),
    # Markers must NAME the mechanism, not describe a symptom. "any
    # authenticated user can ..." and "role check" are core IDOR vocabulary and
    # flagged a correct IDOR finding title as a function-level-authz claim.
    "authz": ("bfla", "function level authorization", "function-level authorization",
              "missing function level", "admin endpoint", "administrative endpoint",
              "any user may invoke", "no role enforcement"),
    "xss": ("xss", "cross site scripting", "cross-site scripting", "unencoded",
            "not escaped", "html injection", "script injection"),
    "sqli": ("sqli", "sql injection", "order by", "injected expression",
             "case when", "query structure"),
    "mass_assign": ("mass assignment", "mass-assignment", "over-posting",
                    "role field", "privilege field", "extra field",
                    "unlisted field", "property level"),
    "csrf": ("csrf", "cross site request forgery", "cross-site request forgery",
             "anti-csrf", "no token", "missing token", "origin"),
    "ssrf": ("ssrf", "server-side request forgery", "server side request forgery",
             "loopback", "127.0.0.1", "internal service", "fetches url"),
    "path_traversal": ("path traversal", "directory traversal", "lfi",
                       "file inclusion", "resolved outside", "escape the directory"),
}

FINDINGS_HEAD = re.compile(r"findings?\b", re.I)
STOP_HEAD = re.compile(
    r"(hypoth|reject|ruled|not\s+tested|could\s+not|limit|recommend|remedi|"
    r"conclusion|appendix|summary)", re.I)
FINDING_ITEM = re.compile(
    r"^\s*(?:#{1,6}\s*)?(?:\d+[.)]\s*)?(?:\*\*)?(?:finding|issue|vuln|"
    r"bug|high|med|low|critical)\b", re.I)


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower())


def parse_sections(raw: str) -> list[tuple[str, str]]:
    """Split a report into (heading, body) pairs, robust to a single-line doc.

    Markdown soft-wrapping can leave a whole report on one line, so headings are
    recovered from `#` markers first and only then split on newlines. The result
    is always a list of sections, never one giant blob."""
    txt = raw.replace("\r\n", "\n")
    marks: list[tuple[int, str]] = [(m.start(), m.group(1).strip())
                                    for m in re.finditer(r"^#{1,6}[ \t]*(.+?)[ \t]*$",
                                                         txt, re.M)]
    if not marks:
        marks = [(m.start(), m.group(1).strip())
                 for m in re.finditer(r"\*\*([^*\n]{3,80})\*\*", txt)]
    marks.sort()
    clean: list[tuple[int, str]] = []
    for pos, head in marks:
        if clean and pos < clean[-1][0] + len(clean[-1][1]) + 8:
            continue
        clean.append((pos, head))
    if not clean:
        return [("", txt)]
    return [(head, txt[pos:(clean[i + 1][0] if i + 1 < len(clean) else len(txt))])
            for i, (pos, head) in enumerate(clean)]


def findings_text(raw: str) -> tuple[str, str]:
    """Return (findings_text, everything_else)."""
    fparts: list[str] = []
    other: list[str] = []
    active: str | None = None
    for head, body in parse_sections(raw):
        if FINDINGS_HEAD.search(head):
            active = "f"
        elif STOP_HEAD.search(head):
            active = None
        (fparts if active == "f" else other).append(body)
    return ("\n".join(fparts), "\n".join(other))


def finding_titles(findings: str) -> list[str]:
    """Text that TITLES a finding, not text that explains one."""
    titles: list[str] = []
    for ln in findings.split("\n"):
        t = ln.strip()
        if FINDING_ITEM.match(t):
            titles.append(re.sub(r"^#+\s*|\*+", "", t)[:140])
            continue
        m = re.match(r"^\*\*([^*\n]{6,120})\*\*", t)
        if m and any(w in m.group(1).lower() for w in
                     ("idor", "bola", "xss", "sqli", "csrf", "ssrf", "traversal",
                      "authz", "mass", "injection", "vuln")):
            titles.append(m.group(1))
    return titles


def grade(exam_dir: Path) -> dict[str, Any]:
    card = json.loads((exam_dir / "card.json").read_text(encoding="utf-8"))
    truth = json.loads((exam_dir / "ground_truth.json").read_text(encoding="utf-8"))
    rp = exam_dir / "SOLVER_REPORT.md"
    if not rp.exists():
        return {"verdict": "NO_REPORT", "detail": "solver wrote no report",
                "exam": card.get("exam_id") or exam_dir.name}
    raw = rp.read_text(encoding="utf-8")
    report = _norm(raw)

    cid = truth["class_id"]
    markers = CONCEPT_MARKERS.get(cid, (cid,))
    named = [m for m in markers if m in report]

    findings, _rest = findings_text(raw)
    f_norm = _norm(findings)
    titles = finding_titles(findings)

    repro = _repro_quality(report)
    trap = _trap_claimed(f_norm, truth)
    fabricated = _fabricated_citations(report, truth, cid, titles)
    contaminated = contamination(report, truth)

    score = {
        "detected": bool(named),
        "evidence_present": repro["has_request_and_response"],
        "trap_correctly_ignored": not trap,
        "no_fabricated_evidence": not fabricated,
        "exam_not_contaminated": not contaminated,
    }
    passed = all(score.values())
    return {
        "verdict": "PASS" if passed else "FAIL",
        "class_id": cid,
        "matched_markers": named,
        "finding_titles": titles,
        "score": score,
        "repro": repro,
        "trap_claimed": trap,
        "fabricated_citations": fabricated,
        "contamination": contaminated,
        "notes": _notes(score, trap, fabricated, contaminated),
        "exam": card.get("exam_id") or exam_dir.name,
    }


def _repro_quality(report: str) -> dict[str, Any]:
    has_method = bool(re.search(r"\b(get|post|put|patch|delete)\b", report))
    has_path = bool(re.search(r"/[a-z0-9_\-]+/[a-z0-9_\-]+", report))
    has_status = bool(re.search(r"\b(200|201|204|301|302|400|401|403|404|405|500)\b", report))
    has_body = bool(re.search(r"(owner|amount|ref|balance|admin|alice|carol|bob|records)", report))
    return {"has_method": has_method, "has_path": has_path, "has_status": has_status,
            "has_body": has_body,
            "has_request_and_response": has_method and has_path and has_status and has_body}


def _trap_claimed(f_norm: str, truth: dict[str, Any]) -> list[str]:
    """A trap counts as REPORTED only when it is titled as a finding.

    Judging the whole document flagged the strongest reports seen: one wrote
    "no password exists by design" in its REJECTED section and was marked as
    having fallen for the trap."""
    claims: list[str] = []
    trap_excerpt = _norm(str(truth.get("trap_probe", {}).get("excerpt", "")))
    if trap_excerpt and len(trap_excerpt) > 20:
        head = " ".join(trap_excerpt.split()[:6])
        if head and head in f_norm:
            claims.append("trap observation reported as a finding")
    if "false positive" in f_norm:
        claims.append("report labels its own finding section a false positive")
    return claims


def _fabricated_citations(report: str, truth: dict[str, Any], planted: str,
                          titles: list[str]) -> list[str]:
    known = " ".join(str(truth.get(k, {}).get("excerpt", "")) for k in
                     ("vuln_probe", "patched_probe", "renamed_probe", "trap_probe"))
    known += " " + str(truth.get("vuln_probe", {}).get("expected", ""))
    bad: list[str] = []
    for q in re.findall(r'"([^"]{12,160})"', report):
        qn = _norm(q)
        if qn and qn not in _norm(known) and re.match(r"^\s*[\{\[].*[\}\]]\s*$", q):
            bad.append(f"invented response body: {q[:70]}")
    title_text = _norm(" ".join(titles))
    for other, markers in CONCEPT_MARKERS.items():
        if other == planted:
            continue
        for m in markers:
            if m in title_text:
                bad.append(f"asserted {other!r} as a finding title; this lab plants "
                           f"{planted!r} only")
                break
    return sorted(set(bad))


def contamination(report: str, truth: dict[str, Any]) -> list[str]:
    """Evidence that the solver had access to the GENERATOR, not the app.

    MEASURED, TWICE, and the first attempt at this function was wrong:

    1. A solver read `eval/labforge.py` to learn the object-id format, then
       solved the lab. A lab sharing a filesystem with its solver is not
       automatically a black box.
    2. v1 flagged any ground-truth *vocabulary* ("insecure direct object
       reference", "object level authorization") and failed TWO PERFECT reports
       that simply named the bug correctly. Naming the mechanism is the whole
       point; it is not evidence of cheating.

    So only SOURCE-LEVEL references count: paths and symbols that exist in the
    generator and are served by no endpoint. Vocabulary is never a signal."""
    signals: list[str] = []
    for term in ("labforge", "self_validate", "ground_truth", "vuln_probe",
                 "patched_install", "patched_probe", "renamed_probe",
                 "trap_probe", "ground truth", "injection_id", "BY_ID",
                 "ctx.py", "run_exam", "grade_exam"):
        if term in report:
            signals.append(f"report references lab internals ({term})")
    return signals


def _notes(score: dict, trap: list, fab: list, contam: list | None = None) -> list:
    n = []
    if not score["detected"]:
        n.append("the mechanism was never named: recognition failure, not a knowledge gap")
    if not score["evidence_present"]:
        n.append("no request/response reproduction: a suspicion is not a finding")
    if trap:
        n.append(f"reported a planted trap as a vulnerability: {trap}")
    if fab:
        n.append(f"unsupported claims: {fab[:2]} -- do not learn from this report")
    if contam:
        n.append(f"EXAM CONTAMINATED: {contam[:2]} -- the solver had access to the "
                 f"generator, so this run measures nothing about black-box skill")
    if not n:
        n.append("clean: mechanism named, reproduction present, trap rejected, "
                 "no invented evidence")
    return n


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="grade_exam")
    ap.add_argument("exam_dir")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    res = grade(Path(a.exam_dir))
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"verdict: {res['verdict']}  class={res.get('class_id')}")
        for t in res.get("finding_titles", []):
            print(f"  finding: {t[:90]}")
        for k, v in res.get("score", {}).items():
            print(f"  [{'x' if v else ' '}] {k}")
        for note in res.get("notes", []):
            print(f"  - {note}")
    return 0 if res["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
