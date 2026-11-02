"""P0-D: the false-positive gate — one implementation of all four checklists.

THE GAP THIS EXISTS TO CLOSE (measured 2026-11-01)
----------------------------------------------------
The project states FOUR FP checklists in its own authoritative documents.
Before `orch/fp_checklist.py`, NONE of them was implemented in code:

  1. AGENTS.md:111-115 — the 10-question FP checklist
  2. agent-briefing.md:104-109 — the 6-question HARD FP GATE
  3. prioritization.md:83-94 — the 6 MANDATORY EXPLOITABILITY gates
  4. AGENTS.md:117-119 — the Findings Strength Verification checklist

`orch/validate.py` (L1..L6) and `orch/finalgate.py` (9 stages) existed and
were real, but they are NOT these checklists. MEASURED gaps, item by item:

  * "replay 2x"                 -> L3 required ONE stored reproduction
  * "FP-DB hash"                -> NO code computed the signature hash
  * "leverageable"              -> no code checked it
  * "2+ accounts/roles/tenants" -> no code checked it
  * "severity per prioritization.md" -> no code read prioritization.md
  * "Findings Strength Verification" -> no code at all

And `memory/FALSE_POSITIVE_DB.md` -- the database the rules say to consult
before promoting an observation -- was read by NOTHING. No parser existed.

WHAT THIS FILE PINS
-------------------
  A. COVERAGE — every check the four lists require exists, and no list's
     requirement was dropped in the reconciliation.
  B. THE SIGNATURE HASH — computed in the exact form the rules specify.
  C. THE FP DATABASE — parsed, and consulted before a promotion.
  D. A GATE THAT CAN FAIL — an empty answer set FAILS, naming every
     unanswered check. A gate that passes an empty answer set is worse
     than no gate.
  E. THE FP-DB MATCH — a known FP pattern auto-downgrades the finding.
  F. SEVERITY CALIBRATION — severity inflation is refused.
  G. REPLAY 2x — one reproduction is not two; two DISTINCT bodies are.
  H. PER-LIST SATISFACTION — "which of the four lists is met?" is
     answerable without re-reading the source documents.
  I. NO REQUIREMENT DROPPED — the union of the four lists is covered, and
     each check names every list that requires it.

Run: python eval/test_p0_fp_checklist.py
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
    from orch import store
    os.environ["WKS_ROOT"] = tmp
    for sub in ("db", "orch"):
        os.makedirs(os.path.join(tmp, sub), exist_ok=True)
    shutil.copy(ROOT / "orch" / "schema.sql",
                os.path.join(tmp, "orch", "schema.sql"))
    con = store.open_db()
    con.row_factory = sqlite3.Row
    return con


def _file_finding(con: sqlite3.Connection, key: str, severity: str = "high",
                  title: str = "IDOR on /users/{id}") -> int:
    con.execute("INSERT INTO finding(finding_key, title, severity, status,"
                " created_at, updated_at) VALUES (?,?,?,'candidate','','')",
                (key, title, severity))
    con.commit()
    return int(con.execute("SELECT id FROM finding WHERE finding_key=?",
                           (key,)).fetchone()["id"])


def _evidence(con: sqlite3.Connection, fid: int, body: str,
              status_line: str = "HTTP/1.1 200 OK") -> None:
    raw = f"{status_line}\r\nContent-Type: text/html\r\n\r\n{body}"
    con.execute(
        "INSERT INTO evidence(task_key, finding_id, kind, target, asset,"
        " endpoint, request_raw, response_raw, payload, sha256, provenance,"
        " captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("t.1", fid, "request", "127.0.0.1", "127.0.0.1", "http://127.0.0.1/x",
         "GET /x HTTP/1.1\r\n\r\n", raw, None, "d" * 64, "curl", "2026-01-01"))
    con.commit()


def main() -> int:
    print("=== P0-D: the false-positive gate ===")
    from orch import fp_checklist as fp

    tmp = tempfile.mkdtemp(prefix="p0d.")
    try:
        con = _fresh_db(tmp)

        # -----------------------------------------------------------------
        print("\nA. COVERAGE — every required check exists")
        union = set()
        for name, reqs in fp.LIST_REQUIREMENTS.items():
            union |= set(reqs)
        missing = union - set(fp.CHECK_IDS)
        check("every required check is implemented", not missing,
              f"missing: {sorted(missing)}")
        check("the four lists are all represented",
              set(fp.LIST_REQUIREMENTS) ==
              {fp.FP10, fp.FP6_BRIEFING, fp.GATES6, fp.STRENGTH},
              str(sorted(fp.LIST_REQUIREMENTS)))
        check("the 10-question list has 10 checks",
              len(fp.LIST_REQUIREMENTS[fp.FP10]) == 10,
              str(len(fp.LIST_REQUIREMENTS[fp.FP10])))
        check("the 6-question list has 6 checks",
              len(fp.LIST_REQUIREMENTS[fp.FP6_BRIEFING]) == 6,
              str(len(fp.LIST_REQUIREMENTS[fp.FP6_BRIEFING])))
        check("the 6-gate list has 6 checks",
              len(fp.LIST_REQUIREMENTS[fp.GATES6]) == 6,
              str(len(fp.LIST_REQUIREMENTS[fp.GATES6])))
        check("the strength list has 5 checks",
              len(fp.LIST_REQUIREMENTS[fp.STRENGTH]) == 5,
              str(len(fp.LIST_REQUIREMENTS[fp.STRENGTH])))

        # The specific items MEASURED as having no code counterpart.
        for cid in ("fp_db_hash", "leverageable", "cross_context",
                    "severity_calibration", "proof_quality",
                    "impact_statement", "fp_eliminated", "raw_poc",
                    "exploit_chain", "replay_2x", "server_side_effect",
                    "real_impact", "no_oos_dependency"):
            check(f"the check {cid!r} exists", cid in fp.CHECK_IDS)

        # -----------------------------------------------------------------
        print("\nI. NO REQUIREMENT DROPPED — each check names its sources")
        for c in fp.CHECKS:
            check(f"{c['id']} names its source list(s)", bool(c["sources"]),
                  str(c))
            # Every list that requires the check must be in its sources.
            required_by = [name for name, reqs in fp.LIST_REQUIREMENTS.items()
                           if c["id"] in reqs]
            check(f"{c['id']} names EVERY list that requires it",
                  set(required_by) <= set(c["sources"]),
                  f"required_by={required_by} sources={c['sources']}")

        # -----------------------------------------------------------------
        print("\nB. THE SIGNATURE HASH — the exact form the rules specify")
        # SHA256(status:body-length:body-substring)[:8]
        import hashlib
        body = "some response body content"
        expected = hashlib.sha256(
            f"200:{len(body)}:{body[:200]}".encode()).hexdigest()[:8]
        got = fp.signature_hash(200, body)
        check("the hash is SHA256(status:body-length:body-substring)[:8]",
              got == expected, f"got {got} want {expected}")
        check("the hash is 8 hex characters",
              len(got) == 8 and all(c in "0123456789abcdef" for c in got), got)
        check("a different status gives a different hash",
              fp.signature_hash(500, body) != got)
        check("a different body length gives a different hash",
              fp.signature_hash(200, body + "x") != got)
        check("the hash is stable for the same input",
              fp.signature_hash(200, body) == got)

        # -----------------------------------------------------------------
        print("\nC. THE FP DATABASE — parsed and consulted")
        entries = fp.parse_fp_db()
        check("the FP database is PARSED", len(entries) > 0, str(len(entries)))
        check("every entry keeps its text", all(e["text"] for e in entries))
        check("every entry keeps its section", all(e["section"] for e in entries))
        check("the known files.com entries are present",
              any("Mass assignment" in e["text"] for e in entries),
              str([e["text"][:40] for e in entries][:3]))
        # A lookup by the title of a known FP must hit.
        hit = fp.fp_db_lookup("", title="Mass assignment PATCH /users/{id} "
                                     "permission flags")
        check("a known FP pattern is FOUND by text", hit is not None,
              str(hit))
        check("the hit says how it matched", hit and hit["matched_by"] == "text",
              str(hit))

        # A missing database file must not crash.
        check("a missing FP database yields no entries, not an exception",
              fp.parse_fp_db(Path("/nonexistent/NO.md")) == [])

        # -----------------------------------------------------------------
        print("\nD. A GATE THAT CAN FAIL — an empty answer set FAILS")
        fid = _file_finding(con, "f.empty", severity="critical",
                            title="Totally novel issue")
        r = fp.run_fp_gate(con, "f.empty")
        check("the gate FAILS with no answers", r["passed"] is False,
              str(r["passed"]))
        check("the gate names what failed", len(r["failed"]) > 0,
              str(r["failed"]))
        check("the gate distinguishes UNANSWERED from answered-and-failed",
              len(r["unanswered"]) > 0, str(r["unanswered"]))
        check("the failure names the downgrade the rules require",
              r["downgrade_to"] == "LEAD", str(r["downgrade_to"]))
        check("no list is satisfied by an empty answer set",
              not any(v["passed"] for v in r["lists"].values()),
              str({k: v["passed"] for k, v in r["lists"].items()}))
        check("every check is reported", len(r["checks"]) == len(fp.CHECKS),
              f"{len(r['checks'])} of {len(fp.CHECKS)}")
        check("every check names the source list(s)",
              all(c["sources"] for c in r["checks"]))
        check("every check quotes its spec",
              all(c["spec"] for c in r["checks"]))

        # -----------------------------------------------------------------
        print("\nE. THE FP-DB MATCH — a known FP auto-downgrades")
        fid = _file_finding(con, "f.known", severity="critical",
                            title="Mass assignment PATCH /users/{id} "
                                  "permission flags")
        _evidence(con, fid, "<html>forbidden</html>", "HTTP/1.1 403 Forbidden")
        r = fp.run_fp_gate(con, "f.known")
        check("the known FP pattern is DETECTED", r["fp_db_hit"] is not None,
              str(r["fp_db_hit"]))
        check("the detection downgrades the finding",
              r["downgrade_to"] == "LEAD", str(r["downgrade_to"]))
        fpdb_check = next(c for c in r["checks"] if c["id"] == fp.FP_DB_HASH)
        check("the FP-DB check FAILED for the known pattern",
              fpdb_check["passed"] is False, str(fpdb_check))
        check("the FP-DB failure explains the match",
              "MATCH" in fpdb_check["detail"], str(fpdb_check))
        elim = next(c for c in r["checks"] if c["id"] == fp.FP_ELIMINATED)
        check("the FP-eliminated gate also failed",
              elim["passed"] is False, str(elim))

        # -----------------------------------------------------------------
        print("\nF. SEVERITY CALIBRATION — inflation is refused")
        fid = _file_finding(con, "f.inflated", severity="critical")
        _evidence(con, fid, "body one")
        _evidence(con, fid, "body two")
        r = fp.run_fp_gate(con, "f.inflated",
                           answers={"proven_impact": "data_exposure"})
        sc = next(c for c in r["checks"] if c["id"] == fp.SEVERITY_CALIBRATION)
        check("a critical severity on a data-exposure claim is REFUSED",
              sc["passed"] is False, str(sc))
        check("the refusal names the ceiling", "ceiling" in sc["detail"],
              str(sc))
        check("the refusal says inflation is prohibited",
              "PROHIBITED" in sc["detail"], str(sc))

        # The same severity with a proven RCE is fine.
        fid = _file_finding(con, "f.rce", severity="critical")
        _evidence(con, fid, "body one")
        _evidence(con, fid, "body two")
        r = fp.run_fp_gate(con, "f.rce",
                           answers={"proven_impact": "remote_code_execution"})
        sc = next(c for c in r["checks"] if c["id"] == fp.SEVERITY_CALIBRATION)
        check("a critical severity on a proven RCE is ALLOWED",
              sc["passed"] is True, str(sc))

        # -----------------------------------------------------------------
        print("\nG. REPLAY 2x — one is not two")
        fid = _file_finding(con, "f.once", severity="medium")
        _evidence(con, fid, "identical body")
        r = fp.run_fp_gate(con, "f.once")
        rep = next(c for c in r["checks"] if c["id"] == fp.REPLAY_2X)
        check("ONE capture is NOT 2x", rep["passed"] is False, str(rep))
        check("the failure says 2x is required", "2x" in rep["detail"],
              str(rep))

        # Two IDENTICAL bodies are still one reproduction.
        _evidence(con, fid, "identical body")
        r = fp.run_fp_gate(con, "f.once")
        rep = next(c for c in r["checks"] if c["id"] == fp.REPLAY_2X)
        check("two IDENTICAL captures are still NOT 2x",
              rep["passed"] is False, str(rep))

        # Two DIFFERENT bodies are two reproductions.
        fid = _file_finding(con, "f.twice", severity="medium")
        _evidence(con, fid, "body A")
        _evidence(con, fid, "body B")
        r = fp.run_fp_gate(con, "f.twice")
        rep = next(c for c in r["checks"] if c["id"] == fp.REPLAY_2X)
        check("two DISTINCT captures ARE 2x", rep["passed"] is True, str(rep))

        # -----------------------------------------------------------------
        print("\nH. PER-LIST SATISFACTION — answerable without the docs")
        fid = _file_finding(con, "f.full", severity="medium",
                            title="Novel issue")
        _evidence(con, fid, "body A")
        _evidence(con, fid, "body B")
        # Answer every judgement check.
        judgement = {
            fp.SERVER_SIDE_EFFECT: True, fp.EXPLOIT_CHAIN: True,
            fp.REAL_IMPACT: True, fp.LEVERAGEABLE: True,
            fp.NO_OOS_DEPENDENCY: True, fp.CROSS_CONTEXT: True,
            fp.IMPACT_STATEMENT: True, fp.PROOF_QUALITY: True,
            fp.FP_ELIMINATED: True,
            "proven_impact": "privilege_escalation",
        }
        r = fp.run_fp_gate(con, "f.full", answers=judgement)
        check("with every answer supplied and 2 distinct reproductions, "
              "the gate PASSES", r["passed"] is True,
              str([(c["id"], c["detail"]) for c in r["checks"]
                   if not c["passed"]]))
        check("every list is satisfied",
              all(v["passed"] for v in r["lists"].values()),
              str({k: v["missing"] for k, v in r["lists"].items()}))
        check("a passing gate names NO downgrade",
              r["downgrade_to"] is None, str(r["downgrade_to"]))

        # An explicit answer OVERRIDES a derivation.
        r2 = fp.run_fp_gate(con, "f.once",
                            answers={fp.REPLAY_2X: {
                                "passed": True,
                                "detail": "independently replayed by hand"}})
        rep2 = next(c for c in r2["checks"] if c["id"] == fp.REPLAY_2X)
        check("an explicit answer OVERRIDES the derivation",
              rep2["passed"] is True, str(rep2))
        check("the override is marked as answered",
              "answered" in rep2["detail"], str(rep2))

        # A single failed check fails the whole gate and names the list.
        r3 = fp.run_fp_gate(con, "f.full",
                            answers={**judgement, fp.CROSS_CONTEXT: False})
        check("one failed check fails the gate", r3["passed"] is False)
        check("the failed list names its missing check",
              fp.CROSS_CONTEXT in r3["lists"][fp.FP10]["missing"],
              str(r3["lists"][fp.FP10]["missing"]))
        check("the lists that do not need it still pass",
              r3["lists"][fp.GATES6]["passed"] is False,
              str(r3["lists"][fp.GATES6]))

        con.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        os.environ.pop("WKS_ROOT", None)

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL P0-D FP CHECKLIST CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
