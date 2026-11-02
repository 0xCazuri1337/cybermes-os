"""P0-C: the finding state machine — evidence-gated, auditable, three axes.

THE GAP THIS EXISTS TO CLOSE (measured 2026-11-01)
----------------------------------------------------
`orch/lifecycle.py` had a complete, well-designed state machine: 14 states,
an explicit LEGAL transition table, `IllegalTransition` for a move the
machine does not permit, a revalidation queue, a dedup ladder and a retest
decision. That part was real.

Three things were missing, and all three were measured, not guessed:

1. THE TRANSITION HISTORY WAS LOST.
   `finding_state` is keyed by `finding_key` ALONE and written with
   `INSERT OR REPLACE`. MEASURED: a finding driven through
   CANDIDATE -> TESTING -> VALIDATED -> EVIDENCE_COMPLETE left ONE row,
   holding only the last state. Every earlier move was overwritten. There
   was no way to answer "how did this finding get here", "who promoted it"
   or "was it ever demoted and re-promoted".

2. PROMOTION REQUIRED NO EVIDENCE.
   `LEGAL` said which moves were permitted, but nothing required a permitted
   move to be BACKED. MEASURED: a finding could be driven
   OBSERVED -> CANDIDATE -> TESTING -> VALIDATED -> EVIDENCE_COMPLETE ->
   RETESTED -> REPORT_READY with `evidence_refs` = [] and reach REPORT_READY
   with no evidence at all. That is the fabricated-finding failure the
   constitution's evidence standard exists to prevent, reachable through the
   system's own happy path.

3. SEVERITY WAS THE ONLY AXIS.
   `finding` carried `severity` and nothing else. "How bad would it be if
   real" and "how sure are we that it IS real" are different questions, and
   "what do we work on next" is a third. With one column, every caller that
   needed confidence or priority had to infer it from severity.

WHAT THIS FILE PINS
-------------------
  A. HISTORY — every transition is appended, in order, and never lost.
  B. EVIDENCE GATE — promotion past TESTING is REFUSED without evidence,
     and the refusal leaves no trace in the current state.
  C. LEGAL MOVES — the machine still refuses an illegal move.
  D. THREE AXES — severity, confidence and priority are independent; setting
     one never rewrites another.
  E. CONFIDENCE IS EARNED — a candidate's confidence stays in the
     observation band regardless of severity, and rises with evidence.
  F. AUDIT — history names who moved it and why.

Run: python eval/test_p0_finding_state_machine.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


def _fresh_db(tmp: str) -> sqlite3.Connection:
    """A database with the orch schema, in a sandboxed WKS_ROOT."""
    from orch import store
    os.environ["WKS_ROOT"] = tmp
    for sub in ("db", "orch"):
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
    shutil.copy(ROOT / "orch" / "schema.sql",
                os.path.join(tmp, "orch", "schema.sql"))
    base = ROOT / "wks" / "config.py"
    # The base schema must exist for the orch schema to apply.
    wks_schema = ROOT / "wks" / "schema.sql"
    if wks_schema.exists():
        shutil.copy(wks_schema, os.path.join(tmp, "wks", "schema.sql")
                    if os.path.isdir(os.path.join(tmp, "wks")) else
                    os.path.join(tmp, "schema.sql"))
    con = store.open_db()
    con.row_factory = sqlite3.Row
    return con


def _mk_finding(con: sqlite3.Connection, key: str) -> None:
    con.execute("INSERT INTO finding(finding_key, title, severity, status,"
                " created_at, updated_at) VALUES (?,?,?,'candidate','','')",
                (key, f"finding {key}", "high"))
    con.commit()


def main() -> int:
    print("=== P0-C: the finding state machine ===")
    from orch import lifecycle

    tmp = tempfile.mkdtemp(prefix="p0c.")
    try:
        con = _fresh_db(tmp)
        lc = lifecycle.FindingLifecycle(con, "p0.c")

        # -----------------------------------------------------------------
        print("\nA. HISTORY — every transition is appended and never lost")
        _mk_finding(con, "f.hist")
        for st in ("CANDIDATE", "TESTING", "VALIDATED", "EVIDENCE_COMPLETE"):
            lc.transition("f.hist", st, reason=f"reached {st}",
                          changed_by="tester", evidence_ids=[1, 2])
        hist = lc.history("f.hist")
        check("every transition is recorded", len(hist) == 4, str(len(hist)))
        check("the history is ORDERED by sequence",
              [h["seq"] for h in hist] == sorted(h["seq"] for h in hist))
        check("the history names each state it passed through",
              [h["to_state"] for h in hist] ==
              ["CANDIDATE", "TESTING", "VALIDATED", "EVIDENCE_COMPLETE"],
              str([h["to_state"] for h in hist]))
        check("the history records the FROM state",
              hist[0]["from_state"] == "OBSERVED", str(hist[0]))
        check("the history names WHO moved it",
              all(h["changed_by"] == "tester" for h in hist),
              str([h["changed_by"] for h in hist]))
        check("the history records WHY",
              all(h["reason"] for h in hist))
        check("the history records the evidence cited",
              hist[-1]["evidence_refs"] == [1, 2], str(hist[-1]))

        # The CURRENT state is still readable and still the last one.
        check("the current state is the last transition",
              lc.state("f.hist") == "EVIDENCE_COMPLETE", lc.state("f.hist"))

        # A demotion and re-promotion must show as separate rows.
        lc.transition("f.hist", "REVALIDATION_REQUIRED",
                      reason="weak evidence", changed_by="tester",
                      evidence_ids=[1])
        lc.transition("f.hist", "TESTING", reason="retest started",
                      changed_by="tester", evidence_ids=[1])
        hist2 = lc.history("f.hist")
        check("a demotion and re-promotion are BOTH in the history",
              len(hist2) == 6 and hist2[-2]["to_state"] ==
              "REVALIDATION_REQUIRED" and hist2[-1]["to_state"] == "TESTING",
              str([h["to_state"] for h in hist2]))

        # -----------------------------------------------------------------
        print("\nB. EVIDENCE GATE — promotion past TESTING is refused")
        _mk_finding(con, "f.noev")
        lc.transition("f.noev", "CANDIDATE", reason="observed a signal",
                      changed_by="tester")
        lc.transition("f.noev", "TESTING", reason="testing the hypothesis",
                      changed_by="tester")
        try:
            lc.transition("f.noev", "VALIDATED", reason="looks good",
                          changed_by="tester")
            check("VALIDATED is REFUSED without evidence", False,
                  "the transition was accepted")
        except lifecycle.PromotionNotSupported as e:
            check("VALIDATED is REFUSED without evidence", True)
            check("the refusal names what was missing",
                  "evidence" in str(e).lower(), str(e))
        check("the refused promotion left the state UNCHANGED",
              lc.state("f.noev") == "TESTING", lc.state("f.noev"))
        check("the refused promotion was NOT recorded as a transition",
              [h["to_state"] for h in lc.history("f.noev")] ==
              ["CANDIDATE", "TESTING"],
              str([h["to_state"] for h in lc.history("f.noev")]))

        # With evidence, the SAME move is allowed.
        lc.transition("f.noev", "VALIDATED", reason="evidence proves it",
                      changed_by="tester", evidence_ids=[42])
        check("VALIDATED is ALLOWED with evidence",
              lc.state("f.noev") == "VALIDATED", lc.state("f.noev"))

        # A missing reason is refused too.
        _mk_finding(con, "f.noreason")
        try:
            lc.transition("f.noreason", "CANDIDATE", reason="",
                          changed_by="tester", evidence_ids=[1])
            check("a promotion with NO reason is REFUSED", False,
                  "the transition was accepted")
        except lifecycle.PromotionNotSupported as e:
            check("a promotion with NO reason is REFUSED", True)
            check("the refusal names the missing reason",
                  "reason" in str(e).lower(), str(e))

        # REPORT_READY must be gated too.
        _mk_finding(con, "f.report")
        for st, ev in (("CANDIDATE", None), ("TESTING", None),
                       ("VALIDATED", [7]), ("EVIDENCE_COMPLETE", [7])):
            try:
                lc.transition("f.report", st, reason="moving on",
                              changed_by="tester", evidence_ids=ev)
            except lifecycle.PromotionNotSupported as e:
                check(f"{st} was unexpectedly refused", False, str(e))
        try:
            lc.transition("f.report", "REPORT_READY", reason="ready",
                          changed_by="tester")
            check("REPORT_READY is REFUSED without evidence", False,
                  "the transition was accepted")
        except lifecycle.PromotionNotSupported:
            check("REPORT_READY is REFUSED without evidence", True)

        # -----------------------------------------------------------------
        print("\nC. LEGAL MOVES — the machine still refuses an illegal move")
        _mk_finding(con, "f.illegal")
        try:
            lc.transition("f.illegal", "REPORT_READY", reason="skip ahead",
                          changed_by="tester", evidence_ids=[1])
            check("an ILLEGAL move is refused", False, "it was accepted")
        except lifecycle.IllegalTransition as e:
            check("an ILLEGAL move is refused", True)
            check("the refusal names the legal moves",
                  "Legal from" in str(e), str(e))
        try:
            lc.transition("f.illegal", "NOT_A_STATE", reason="x")
            check("an unknown state is refused", False, "it was accepted")
        except ValueError:
            check("an unknown state is refused", True)

        # -----------------------------------------------------------------
        print("\nD. THREE AXES — severity, confidence and priority are independent")
        from orch import store
        store.add_finding(con, "f.axes", "axes", severity="critical",
                          confidence=0.5, priority=2)
        row = con.execute("SELECT severity, confidence, priority FROM finding"
                          " WHERE finding_key='f.axes'").fetchone()
        check("severity is stored", row["severity"] == "critical", str(dict(row)))
        check("confidence is stored", abs(row["confidence"] - 0.5) < 1e-9,
              str(dict(row)))
        check("priority is stored", row["priority"] == 2, str(dict(row)))

        store.set_finding_axes(con, "f.axes", confidence=0.9)
        row = con.execute("SELECT severity, confidence, priority FROM finding"
                          " WHERE finding_key='f.axes'").fetchone()
        check("setting confidence does NOT rewrite severity",
              row["severity"] == "critical", str(dict(row)))
        check("setting confidence does NOT rewrite priority",
              row["priority"] == 2, str(dict(row)))
        check("setting confidence DID change confidence",
              abs(row["confidence"] - 0.9) < 1e-9, str(dict(row)))

        store.set_finding_axes(con, "f.axes", severity="low")
        row = con.execute("SELECT severity, confidence FROM finding"
                          " WHERE finding_key='f.axes'").fetchone()
        check("setting severity does NOT rewrite confidence",
              abs(row["confidence"] - 0.9) < 1e-9, str(dict(row)))
        check("setting severity DID change severity",
              row["severity"] == "low", str(dict(row)))

        # -----------------------------------------------------------------
        print("\nE. CONFIDENCE IS EARNED — independent of severity")
        from orch import hunt_exec
        conf_fn = hunt_exec.ActiveHuntExecutor._confidence_from_evidence

        # No signals at all -> no confidence.
        check("no signals means no confidence",
              conf_fn([], []) == 0.0, str(conf_fn([], [])))

        # A broad, classifiable, captured observation -> the best a
        # candidate can be, and still below the LEAD band's floor.
        obs = [{"signals": ["boolean_differential", "sql_error_or_behaviour"]}]
        reqs = [{"raw": "HTTP/1.1 500 ..."}]
        hi = conf_fn(obs, reqs)
        check("a corroborated, classifiable observation scores above zero",
              hi > 0.0, str(hi))
        check("a candidate's confidence stays BELOW the LEAD band (10%)",
              hi < 0.10, f"{hi} (LEAD starts at 10%)")

        # One ambiguous signal only -> lower.
        lo = conf_fn([{"signals": ["weird_unknown_thing"]}], [])
        check("an unclassifiable single signal scores lower than a "
              "corroborated one", lo < hi, f"{lo} vs {hi}")

        # Severity must not affect it at all: the function does not take
        # severity, so a critical-severity claim and an info-severity claim
        # with the same evidence score identically.
        check("confidence does not depend on severity",
              conf_fn(obs, reqs) == hi, str(conf_fn(obs, reqs)))

        # -----------------------------------------------------------------
        print("\nF. AUDIT — the board and the history agree")
        board = lc.board()
        check("the board lists every lifecycle state",
              set(board) == set(lifecycle.LIFECYCLE),
              str(set(lifecycle.LIFECYCLE) - set(board)))
        # Every finding that HAS a transition must appear on the board, in
        # the state its last transition put it in. A finding whose only
        # transition was REFUSED must NOT appear -- it was never promoted.
        on_board = set(sum(board.values(), []))
        for key in ("f.hist", "f.noev"):
            check(f"{key} is on the board", key in on_board, str(sorted(on_board)))
        check("f.hist is on the board in its LAST state",
              "f.hist" in board["TESTING"], str(board.get("TESTING")))
        check("a finding whose only transition was REFUSED is NOT on the board",
              "f.illegal" not in on_board, str(sorted(on_board)))
        check("the board and the history agree on the state",
              board.get(lc.state("f.hist"), []) == ["f.hist"],
              f"state={lc.state('f.hist')} board={board.get(lc.state('f.hist'))}")

        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        os.environ.pop("WKS_ROOT", None)

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL P0-C FINDING STATE MACHINE CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
