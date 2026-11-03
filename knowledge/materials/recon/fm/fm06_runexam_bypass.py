"""FM test: does eval/run_exam.py grade_and_record() -- the documented way an
exam closes a gate -- enforce the SAME guards as mastery.record_gate()?

Answered by executing the real function in a THROWAWAY tree with a
DISQUALIFIED exam whose GRADE.json says PASS. If the gate closes, the exam
path bypasses _refuse_disqualified entirely.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

SB = Path(open(sys.argv[1]).read().strip())
EVAL = Path(sys.argv[2])
os.environ["WKS_ROOT"] = str(SB)
sys.path.insert(0, str(SB))
sys.path.insert(0, str(EVAL.parent))

from wks import mastery  # noqa: E402

assert Path(str(mastery.config.root())) == SB, "refusing: wrong root"

print("=" * 74)
print("FM-06  DOES THE EXAM PATH (run_exam.grade_and_record) ENFORCE THE GUARDS?")
print("=" * 74)

work = Path(tempfile.mkdtemp(prefix="fm_runexam_"))
exam = work / "idor-9999"
exam.mkdir(parents=True, exist_ok=True)

# A lab that plants IDOR, a solver report that would PASS, a clean grade,
# AND a DISQUALIFIED marker -- the exact combination mastery._refuse_disqualified
# exists to reject.
(exam / "card.json").write_text(json.dumps({
    "target": "http://127.0.0.1:9999",
    "credentials": {"alice": "user", "bob": "user"},
    "how_to_auth": "POST /login user=<name>",
    "mission": "Find real, demonstrable vulnerabilities.",
    "exam_id": "idor-9999",
}), encoding="utf-8")
(exam / "ground_truth.json").write_text(json.dumps({
    "class_id": "idor", "injection_id": "idor",
    "vuln_probe": {"excerpt": '{"ref": "A-1003", "owner": "carol"}',
                   "expected": "HTTP 200 whose body names another owner"},
    "trap_probe": {"excerpt": "the listing is owner-scoped", "why_not_a_vuln": "x"},
}), encoding="utf-8")
(exam / "SOLVER_REPORT.md").write_text(
    "# Findings\n\n"
    "### FINDING 1 — Insecure Direct Object Reference (IDOR) on the item route\n"
    "Any authenticated user can read another user's policy record: there is no "
    "ownership check on the item route, only on the collection route.\n\n"
    "```http\nPOST /login HTTP/1.1\nHost: 127.0.0.1:9999\nuser=bob\n```\n"
    "```http\nHTTP/1.1 200 OK\n\n{\"ref\": \"A-1003\", \"owner\": \"carol\", "
    "\"amount\": 7777}\n```\n\n"
    "The record named above belongs to alice, not bob. Login was attempted with "
    "POST /login user=bob; the cookie returned authenticated bob successfully "
    "with status 200. The requested path /rest/workspace/A-1003 returned "
    "status 200 and the body above.\n"
    + "detail " * 60, encoding="utf-8")
(exam / "DISQUALIFIED.json").write_text(json.dumps({
    "reasons": ["solver read eval/labforge.py; the run measures nothing about skill"],
}), encoding="utf-8")

print()
print("STAGE 1 -- the guard itself, called directly (control):")
try:
    mastery.record_gate("fm_probe_b", "black_box", exam / "GRADE.json", root=SB)
    print("  record_gate CLOSED it  <-- guard is broken")
except SystemExit as e:
    print(f"  record_gate REFUSED: {e}")
except FileNotFoundError:
    print("  (GRADE.json not yet written; guard needs it) -- writing grade next")

print()
print("STAGE 2 -- the documented exam path, run_exam.grade_and_record():")
import importlib.util  # noqa: E402
spec = importlib.util.spec_from_file_location("run_exam_mod", EVAL / "run_exam.py")
mod = importlib.util.module_from_spec(spec)
try:
    spec.loader.exec_module(mod)
except Exception as e:
    print(f"  could not import run_exam: {type(e).__name__}: {e}")
    raise SystemExit(0)

rc = mod.grade_and_record(exam, "black_box")
rec = mastery.load("idor")
print()
print(f"  grade_and_record returned {rc}")
print(f"  mastery/idor.json now: closed={rec.closed()} state={rec.derive_state()}")
print(f"  idor gates on disk: {sorted((json.loads((SB/'mastery'/'idor.json').read_text())['gates']).keys()) if (SB/'mastery'/'idor.json').exists() else '<no idor.json in sandbox>'}")
print()
if "black_box" in [g for g in rec.closed()]:
    print("  RESULT: THE EXAM PATH CLOSED A GATE INSIDE A DISQUALIFIED EXAM.")
    print("          _refuse_disqualified never ran on this path.")
else:
    print("  RESULT: the exam path refused (guard held).")