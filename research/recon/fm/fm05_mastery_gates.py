"""FM test: can the 12 mastery gates be closed by artifacts that prove less
than the gate's own name claims?

Runs in a THROWAWAY tree (WKS_ROOT from argv). Never touches the canonical
mastery/ directory or the canonical db.
"""
import json
import os
import sys
import tempfile
from pathlib import Path

SB = Path(open(sys.argv[1]).read().strip())
os.environ["WKS_ROOT"] = str(SB)
sys.path.insert(0, str(SB))

from wks import mastery  # noqa: E402

assert Path(config_root := str(mastery.config.root())) == SB, \
    f"refusing: root={mastery.config.root()} != {SB}"

print("=" * 74)
print("FM-05  CAN 12 MASTERY GATES BE CLOSED BY NON-PROOF ARTIFACTS?")
print("=" * 74)
print(f"sandbox: {SB}")
print()
print("_validate_evidence enforces ONLY for gate in EXAM_GATES =", mastery.EXAM_GATES)
print("-> the other", len(mastery.GATE_IDS) - len(mastery.EXAM_GATES),
      "gates have NO content requirement at all beyond os.path.exists()")
print()

work = Path(tempfile.mkdtemp(prefix="fm_ev_"))
CID = "fm_probe_class"


def attempt(gate, artifact_name, content, note):
    p = work / artifact_name
    p.parent.mkdir(parents=True, exist_ok=True)
    if content is not None:
        p.write_text(content, encoding="utf-8")
    try:
        rec = mastery.record_gate(CID, gate, p, root=SB)
        print(f"  [CLOSED] {gate:17} evidence={artifact_name:16} "
              f"-> {len(rec.closed())}/{len(mastery.GATE_IDS)} "
              f"state={rec.derive_state()}")
        print(f"           ({note})")
        return True
    except SystemExit as e:
        print(f"  [REFUSED] {gate:17} {e}")
        return False


print("--- A. the ten NON-exam gates: does artifact CONTENT matter at all? ---")
attempts = [
    # (gate, filename, content, why this proves nothing)
    ("explain", "explain.md", "TODO",
     "gate requires a mechanism chain: attacker input -> parser -> normalisation "
     "-> validation -> trust decision -> internal operation -> observable result, "
     "with the exact invariant that fails. Content is the single word TODO."),
    ("recognize", "signals.txt", "x",
     "gate requires a signal list justifying investigation. Content is 'x'."),
    ("hypothesize", "hypo.txt", "",
     "gate requires a falsifiable hypothesis set keyed to the observed signal. "
     "Content is ZERO BYTES."),
    ("interpret", "interp.md", "see later",
     "gate requires result -> meaning -> next action. Content is a forward reference."),
    ("reject_fp", "fp.md", "no false positives observed",
     "gate requires a false-positive rejection log with the disproof test for "
     "each. Content asserts there were none -- zero disproof tests."),
    ("generalize", "gen.md", "see also chain.md",
     "gate requires a variant map covering common, uncommon AND defensive "
     "variants. Content is a pointer to a nonexistent file."),
    ("test", "test.md", "try it",
     "gate requires an ordered test plan with expected information gain PER TEST. "
     "Two words."),
    ("chain", "chain.md", "chain.md",
     "gate requires prerequisites, transition, escalation and blocker. The file "
     "points at itself."),
    ("failure_analysis", "fa.md", "no mistakes were made",
     "gate requires expected vs actual vs wrong assumption vs next test. "
     "Content asserts there were no mistakes -- a perfect record is asserted, not earned."),
    ("validate", "validate.md", "validated",
     "gate requires an exploit request + response PAIR proving impact. "
     "Content is one word; no request, no response."),
]
closed = 0
for g, fn, content, why in attempts:
    if attempt(g, fn, content, why):
        closed += 1
    print()

print(f"NON-EXAM GATES CLOSED BY EMPTY/TRIVIAL ARTIFACTS: {closed}/10")

print()
print("--- B. the two EXAM gates: is _validate_evidence actually load-bearing? ---")
ex = work / "examdir"
ex.mkdir(parents=True, exist_ok=True)
(ex / "SOLVER_REPORT.md").write_text("x" * 500, encoding="utf-8")   # 500 bytes, no content check
(ex / "GRADE.json").write_text(json.dumps({
    "verdict": "PASS",
    "score": {"detected": True, "evidence_present": True},
}), encoding="utf-8")
attempt("black_box", "examdir/GRADE.json", None,
        "note: pre-written by this test")
attempt("transfer", "examdir/GRADE.json", None,
        "note: THE SAME ARTIFACT closes transfer as black_box -- nothing ties "
             "a transfer gate to a DIFFERENT architecture than the black_box run")

print()
print("--- C. the disqualification guard ---")
dq = work / "dqexam"
dq.mkdir(parents=True, exist_ok=True)
(dq / "SOLVER_REPORT.md").write_text("y" * 500, encoding="utf-8")
(dq / "GRADE.json").write_text(json.dumps({
    "verdict": "PASS", "score": {"detected": True}}), encoding="utf-8")
(dq / "DISQUALIFIED.json").write_text(json.dumps({"reasons": ["cheating"]}),
                                      encoding="utf-8")
# Non-exam gate inside a DISQUALIFIED exam dir -- does _refuse_disqualified fire?
p = dq / "SOLVER_REPORT.md"
attempt("failure_analysis", "dqexam/SOLVER_REPORT.md", None,
        "non-exam gate with evidence inside a DISQUALIFIED exam")

print()
print("--- D. run_exam.py's OWN path bypasses record_gate entirely ---")
src = (SB / "eval" / "run_exam.py").read_text(encoding="utf-8") if (SB / "eval" / "run_exam.py").exists() else ""
if not src:
    src = Path(os.environ["FM_EVAL_SRC"]).read_text(encoding="utf-8")
lines = src.splitlines()
for i, l in enumerate(lines, 1):
    if "mastery" in l:
        print(f"  eval/run_exam.py:{i}: {l.strip()}")
print()
print("  -> grade_and_record() assigns rec.gates[gate]={closed:True} directly")
print("     and calls mastery.save(rec). record_gate() -- and therefore")
print("     _validate_evidence AND _refuse_disqualified -- is NEVER called")
print("     on this path.")

print()
print("=" * 74)
rec = mastery.load(CID, root=SB)
print(f"FINAL: {CID} -> {len(rec.closed())}/{len(mastery.GATE_IDS)} gates, "
      f"state={rec.derive_state()}, score={rec.score()}")
print(f"closed gates: {rec.closed()}")
print("=" * 74)