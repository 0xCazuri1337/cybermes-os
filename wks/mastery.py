"""Mastery engine: the 12 gates from the brief, scored from evidence.

WKS measures knowledge quality. It does not measure capability. This module
adds the capability half, and it is deliberately separate from the corpus:
`mastery` never writes an item, never promotes a validation_state, and never
touches `quality.py`'s authority. A class can be MASTERED here while holding
zero items, and an item can be high_confidence there while the class is WEAK.
Neither direction is inferred from the other, because conflating them is how a
system convinces itself it is competent because it has notes.

Every gate is satisfied by a stored, re-checkable artifact. `score()` refuses to
award a gate whose evidence is missing, so the state machine cannot be talked
into MASTERED by writing a sentence in a markdown file.

    python -m wks.mastery gates idor
    python -m wks.mastery score idor
    python -m wks.mastery status
    python -m wks.mastery record <class> <gate> --evidence PATH
"""
from __future__ import annotations

import json
import re
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import config, store

MASTERY_DIR = "mastery"

# The twelve gates, verbatim from the brief §22, with the artifact that closes
# each one. A gate with no artifact type is a gate that cannot be closed.
GATES: list[tuple[str, str, str]] = [
    ("explain", "Explain from first principles",
     "mechanism note: attacker input -> parser -> normalisation -> validation -> "
     "trust decision -> internal operation -> observable result, with the exact "
     "invariant that fails"),
    ("recognize", "Identify relevant attack-surface signals",
     "signal list: which observations justify investigating this class"),
    ("hypothesize", "Generate useful hypotheses from incomplete evidence",
     "hypothesis set keyed to the observed signal, each falsifiable"),
    ("test", "Select efficient tests",
     "ordered test plan with expected information gain per test"),
    ("interpret", "Interpret ambiguous or unexpected results",
     "interpretation table: result -> meaning -> next action"),
    ("validate", "Prove the vulnerability rather than suspecting it",
     "validation record: exploit request + response pair proving impact"),
    ("reject_fp", "Correctly reject misleading cases",
     "false-positive rejection log with the disproof test for each"),
    ("generalize", "Recognise meaningful variants",
     "variant map covering common, uncommon and defensive variants"),
    ("black_box", "Solve an unseen black-box case",
     "black-box exam result: class UNSEEN at start, vulnerability found with evidence"),
    ("transfer", "Solve the same class in a different architecture",
     "transfer exam result in a differently-named/shaped target"),
    ("chain", "Reason about chains and chain blockers",
     "chain model with prerequisites, transition, escalation and blocker"),
    ("failure_analysis", "Diagnose own mistakes and close the gaps",
     "failure analysis: expected vs actual vs wrong assumption vs next test"),
]

STATES = ["UNSEEN", "RESEARCHING", "MODELING", "PRACTICING", "WEAK",
          "REPAIRING", "VALIDATING", "TRANSFER_TESTING", "MASTERED",
          "NEEDS_REVIEW"]

GATE_IDS = [g[0] for g in GATES]


def dir_for(root: Path | None = None) -> Path:
    d = (root or config.root()) / MASTERY_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d


@dataclass
class Record:
    class_id: str
    gates: dict[str, dict[str, Any]]
    state: str = "UNSEEN"
    history: list[dict[str, Any]] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.history is None:
            self.history = []

    def closed(self) -> list[str]:
        return [g for g in GATE_IDS if self.gates.get(g, {}).get("closed")]

    def score(self) -> float:
        return round(len(self.closed()) / len(GATE_IDS), 3)

    def derive_state(self) -> str:
        """State is DERIVED from gate evidence, never asserted by hand."""
        done = set(self.closed())
        if len(done) == len(GATE_IDS):
            return "MASTERED"
        for advanced in ("transfer", "black_box", "validate"):
            if advanced in done:
                return "TRANSFER_TESTING" if "transfer" not in done else "VALIDATING"
        if "reject_fp" in done or "interpret" in done:
            return "PRACTICING"
        if "recognize" in done or "hypothesize" in done:
            return "MODELING"
        if "explain" in done:
            return "RESEARCHING"
        if not done:
            return "UNSEEN"
        return "PRACTICING"


def path_for(class_id: str, root: Path | None = None) -> Path:
    return dir_for(root) / f"{class_id}.json"


def load(class_id: str, root: Path | None = None) -> Record:
    p = path_for(class_id, root)
    if not p.exists():
        return Record(class_id, {})
    d = json.loads(p.read_text(encoding="utf-8"))
    return Record(d["class_id"], d.get("gates", {}), d.get("state", "UNSEEN"),
                  d.get("history", []))


def save(rec: Record, root: Path | None = None) -> Path:
    rec.state = rec.derive_state()
    rec.history.append({"at": datetime.now(timezone.utc).isoformat(),
                        "state": rec.state, "closed": len(rec.closed())})
    p = path_for(rec.class_id, root)
    p.write_text(json.dumps({
        "class_id": rec.class_id, "state": rec.state, "gates": rec.gates,
        "closed": len(rec.closed()), "total": len(GATE_IDS),
        "score": rec.score(), "history": rec.history[-40:],
    }, indent=2), encoding="utf-8")
    return p


# Gates closed by an exam may only cite a graded verdict. `card.json` is a real
# file that proves nothing, and accepting it let an unearned `transfer` gate
# through during development.
EXAM_GATES = {"black_box", "transfer"}

# MEASURED (recon mastery cycle): before this table, 10 of 12 gates accepted a
# 4-byte file containing "TODO" and `hypothesize` accepted a zero-byte file,
# so the engine could report MASTERED on nothing. Floors are set per gate from
# what each artifact IS, and are intentionally low -- they reject placeholders,
# not brevity. An honest 300-byte mechanism note passes; a 300-byte TODO does
# not (the placeholder check below catches the second case).
MIN_GATE_BYTES_DEFAULT = 120
MIN_GATE_BYTES: dict[str, int] = {
    # narrative artefacts
    "explain": 200,            # mechanism note: input -> ... -> observable
    "recognize": 150,          # signal list
    "hypothesize": 200,        # hypothesis set, each falsifiable
    "test": 200,               # ordered plan + expected information gain
    "interpret": 200,          # result -> meaning -> next action table
    "reject_fp": 150,          # rejection log with a disproof each
    "generalize": 200,         # variant map
    "failure_analysis": 250,   # expected vs actual vs wrong assumption
    # structured artefacts: JSON/tables carry more punctuation, so a slightly
    # higher floor still admits a genuinely small one
    "validate": 200,
    "chain": 250,
    # exam gates are validated separately and more strictly (GRADE.json +
    # SOLVER_REPORT.md >= 400 bytes); these floors are a floor, not the test.
    "black_box": 120,
    "transfer": 120,
}

# A short file that is nothing but a placeholder marker, however long it is.
_PLACEHOLDER_WORDS = {"todo", "tbd", "fixme", "xxx", "wip", "lorem",
                      "ipsum", "placeholder", "stub", "coming", "soon"}

_PLACEHOLDER_STARTS = {
    "todo", "tbd", "fixme", "xxx", "n/a", "na", "placeholder", "stub",
    "lorem ipsum", "coming soon", "wip", ".", "..",
}


def _validate_evidence(gate: str, ev: Path) -> None:
    if not ev.exists():
        raise SystemExit(f"evidence {ev} does not exist -- a gate with no "
                         "artifact cannot be closed")
    # MEASURED (recon mastery cycle): before this guard, 10 of the 12 gates
    # accepted a 4-byte file whose entire content was the word "TODO", and
    # `hypothesize` accepted a ZERO-BYTE file. Existence is not evidence. A
    # gate that closes on an empty file is a gate that cannot fail, so the
    # mastery engine could report MASTERED (12/12) without one piece of
    # reasoning ever recorded -- the exact "fake mastery" this system exists to
    # prevent.
    #
    # The floors are deliberately LOW. They reject placeholders and stubs; they
    # do not grade quality, which is the assessment's job and which a size
    # floor cannot do. A floor set too high would refuse an honest terse note
    # and teach the operator to pad artifacts -- worse than the defect.
    floor = MIN_GATE_BYTES.get(gate, MIN_GATE_BYTES_DEFAULT)
    size = ev.stat().st_size
    if size < floor:
        raise SystemExit(
            f"evidence {ev.name} is {size} bytes; gate {gate!r} requires >= "
            f"{floor}. A placeholder is not evidence -- write the artifact the "
            f"gate names, or the gate stays open.")

    # Padding must not defeat the check. The first version of this guard only
    # inspected files UNDER 400 bytes, so `"TODO\n" + "x" * 400` closed a gate
    # unimpeded -- caught by eval/test_mastery_gates.py, which tests the padded
    # case explicitly. A file with this few distinct words contains no
    # reasoning regardless of its length.
    text = ev.read_bytes().decode("utf-8", "replace")
    stripped = text.strip()
    words = {w.lower() for w in re.findall(r"[a-zA-Z]{2,}", stripped)}
    if not words:
        raise SystemExit(
            f"evidence {ev.name} contains no words at all; that is not a "
            f"{gate!r} artifact")
    if words <= _PLACEHOLDER_WORDS:
        raise SystemExit(
            f"evidence {ev.name} is {size} bytes but uses only {sorted(words)}"
            f" -- padding a placeholder does not make one")
    # Repetition is the real signal, not vocabulary. `"TODO\n" + "x" * 400`
    # yields ONE 400-character "word", so a vocabulary-subset test passes it
    # happily (measured: caught only by adding this check). A real artifact has
    # many distinct words; padding has almost none. Count 3-letter+ tokens so a
    # long identifier still counts as the few words it is.
    tokens = [w.lower() for w in re.findall(r"[a-zA-Z]{3,}", stripped)]
    if tokens and len(set(tokens)) <= 2:
        raise SystemExit(
            f"evidence {ev.name} is {size} bytes but has only "
            f"{len(set(tokens))} distinct word(s) ({sorted(set(tokens))[:3]}) "
            f"-- padding a placeholder does not make one")
    head = stripped[:64].lower()
    if head in _PLACEHOLDER_STARTS:
        raise SystemExit(
            f"evidence {ev.name} opens with {head[:40]!r}; that is a "
            f"placeholder, not a {gate!r} artifact")

    if gate in EXAM_GATES:
        if ev.name != "GRADE.json":
            raise SystemExit(
                f"gate {gate!r} may only be closed by a graded exam verdict "
                f"(GRADE.json); {ev.name} is not one")
        import json as _json
        try:
            g = _json.loads(ev.read_text(encoding="utf-8"))
        except Exception as e:
            raise SystemExit(f"{ev} is not readable JSON: {e}")
        if g.get("verdict") != "PASS":
            raise SystemExit(
                f"{ev} records verdict={g.get('verdict')!r}; a failing exam may "
                f"not close a gate")
        for k, v in (g.get("score") or {}).items():
            if not v:
                raise SystemExit(f"{ev} is not a clean pass: {k} failed")
        # The grade must be backed by an actual solver report, not by a fixture
        # the operator wrote to test the grader. A hand-authored report passes
        # every check, so it closed a `black_box` gate that no solver ever
        # earned.
        exam_dir = ev.parent
        rp = exam_dir / "SOLVER_REPORT.md"
        if not rp.exists():
            raise SystemExit(
                f"{exam_dir.name} has no SOLVER_REPORT.md; a grade without a "
                f"solver report is not evidence of anything")
        if rp.stat().st_size < 400:
            raise SystemExit(
                f"{rp} is {rp.stat().st_size} bytes -- too short to be a real "
                f"solver report; refusing to treat a stub as an exam")


def _refuse_disqualified(ev: Path) -> None:
    """Any gate, from any directory, refuses evidence inside a disqualified exam.

    This check lives in record_gate rather than in the exam branch: it was
    originally scoped to EXAM_GATES, and a `chain` gate then closed on a
    NO_REPORT grade inside a DISQUALIFIED exam because the guard never ran."""
    dq = ev.parent / "DISQUALIFIED.json"
    if dq.exists():
        import json as _json
        try:
            reasons = _json.loads(dq.read_text(encoding="utf-8")).get("reasons", [])
        except Exception:
            reasons = []
        raise SystemExit(
            f"{ev.parent.name} is DISQUALIFIED"
            + (f": {reasons[0]}" if reasons else "")
            + " -- a disqualified run may never close a gate")


def record_gate(class_id: str, gate: str, evidence: Path | str, root: Path | None = None) -> Record:
    if gate not in GATE_IDS:
        raise SystemExit(f"unknown gate {gate!r}; valid: {', '.join(GATE_IDS)}")
    ev = Path(evidence)
    if not ev.exists():
        raise SystemExit(f"evidence {ev} does not exist -- a gate with no "
                         f"artifact cannot be closed")
    _refuse_disqualified(ev)
    _validate_evidence(gate, ev)
    rec = load(class_id, root)
    rec.gates[gate] = {
        "closed": True,
        "evidence": str(ev),
        "bytes": ev.stat().st_size,
        "at": datetime.now(timezone.utc).isoformat(),
    }
    save(rec, root)
    return rec


def gate_defs() -> list[dict[str, str]]:
    return [{"gate": g, "definition": d, "artifact_required": a} for g, d, a in GATES]


def status(root: Path | None = None) -> dict[str, Any]:
    rows = []
    for p in sorted(dir_for(root).glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        rows.append({"class_id": d["class_id"], "state": d["state"],
                     "closed": d["closed"], "total": d["total"],
                     "score": d["score"],
                     "missing": [g for g in GATE_IDS
                                 if not d.get("gates", {}).get(g, {}).get("closed")]})
    return {"gates": len(GATE_IDS), "classes": len(rows), "rows": rows}


def cmd_gates(args) -> int:
    for g in gate_defs():
        print(f"{g['gate']:18} {g['definition']}")
        print(f"{'':18} requires: {g['artifact_required'][:88]}")
    return 0


def cmd_score(args) -> int:
    rec = load(args.class_id)
    done = set(rec.closed())
    print(f"{args.class_id}: {rec.score():.0%}  state={rec.derive_state()}")
    for gid, defn, art in GATES:
        mark = "x" if gid in done else " "
        print(f"  [{mark}] {gid:18} {defn}")
    return 0


def cmd_status(args) -> int:
    print(json.dumps(status(), indent=2))
    return 0


def cmd_record(args) -> int:
    rec = record_gate(args.class_id, args.gate, args.evidence)
    print(f"{args.class_id}: gate {args.gate} closed -> "
          f"{len(rec.closed())}/{len(GATE_IDS)} state={rec.derive_state()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="wks.mastery")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("gates").set_defaults(fn=cmd_gates)
    s = sub.add_parser("status"); s.set_defaults(fn=cmd_status)
    sc = sub.add_parser("score"); sc.add_argument("class_id"); sc.set_defaults(fn=cmd_score)
    r = sub.add_parser("record")
    r.add_argument("class_id"); r.add_argument("gate"); r.add_argument("--evidence", required=True)
    r.set_defaults(fn=cmd_record)

    a = ap.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())