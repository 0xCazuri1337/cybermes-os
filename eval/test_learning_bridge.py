"""Integration test for the hunt-outcome -> learning bridge.

MEASURED CONTEXT: the learning engine had all five hooks, and the hunt layer
had a complete finding lifecycle with a real final gate — and NOTHING
connected them. No module under `orch/`, `wks/` or `scripts/` imported
`learning_engine`. A confirmed finding produced no lesson; a program's
"duplicate" verdict produced no feedback.

These tests drive the bridge end-to-end against a scratch database, so they
prove the connection exists rather than that a function imports.
"""
from __future__ import annotations

import json
import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0
_CURRENT: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        _CURRENT.append(f"{label}  ({detail})")
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))


class LearningBridgeTests(unittest.TestCase):
    def setUp(self):
        _CURRENT.clear()
        self.tmp = tempfile.mkdtemp(prefix="bridge_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

        from wks import config as wks_config
        schema = Path(wks_config.SCHEMA_PATH).read_text(encoding="utf-8")
        self.db = Path(self.tmp) / "wks.db"
        con = sqlite3.connect(str(self.db))
        con.row_factory = sqlite3.Row
        con.executescript(schema)
        con.commit()
        con.close()

        orch_schema = (ROOT / "orch" / "schema.sql").read_text(encoding="utf-8")
        con = sqlite3.connect(str(self.db))
        con.row_factory = sqlite3.Row
        con.executescript(orch_schema)
        con.commit()

        from learning_engine import engine as le
        le.ensure_schema(con)
        self.le = le
        self.con = con

        # `finding_state` belongs to the lifecycle module, not orch/schema.sql.
        from orch import lifecycle as lifecycle_mod
        lifecycle_mod._ensure(con)

        from orch import learning_bridge
        self.bridge = learning_bridge

        # A finding with evidence, and one without.
        from orch import store as orch_store
        self.orch_store = orch_store
        # THE SCENARIO THIS FILE MODELS IS A PRODUCTION HUNT.
        #
        # MEASURED 2026-11-01: these fixtures used `example.test`, a
        # RESERVED TEST DOMAIN, so `add_finding` classified them
        # EVAL_TEST -- and a lesson from an EVAL_TEST finding can never be
        # verified, so the assertions below ("a confirmed finding with
        # evidence is VERIFIED", "before_recon now returns the lesson")
        # could not hold.
        #
        # MEASURED 2026-11-02: the fix for that was to ASSERT
        # `provenance="PRODUCTION_HUNT"` with no authorization anywhere --
        # which `add_finding` now correctly DOWNGRADES to UNKNOWN, because
        # an explicit origin is a claim and a receipt is the proof. So the
        # assertion no longer works, and it must not: the whole point is
        # that a claim alone cannot make production experience.
        #
        # The scenario is now created the way the runtime creates one: a
        # hunt with a VALIDATED AUTHORIZATION RECEIPT that names the
        # target. The receipt -- not the fixture's assertion -- is what
        # makes the origin production.
        #
        # The provenance gate is not weakened. It is exercised in
        # `eval/test_p2_provenance.py`, which proves that a finding with
        # no receipt cannot produce a verified lesson.
        self.HUNT_ID = "bridge.hunt"
        self.AUTH_REF = "BRIDGE-PROGRAM-SCOPE"
        from wks import ownership as _ownership
        with _ownership.owner_write(con, _ownership.ORCH):
            con.execute(
                "INSERT OR REPLACE INTO hunt_authorization(auth_id, hunt_id,"
                " program, target, kind, authorization_ref,"
                " offensive_allowed, validated, validated_at, created_at,"
                " context_json, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("auth." + self.HUNT_ID, self.HUNT_ID, "bridge-program",
                 "example.test", "bugbounty", self.AUTH_REF, 1, 1,
                 "2026-01-01T00:00:00+00:00",
                 "2026-01-01T00:00:00+00:00", "{}", "test fixture receipt"))
            con.commit()
        orch_store.add_finding(
            con, "f.confirmed", "IDOR on /api/users/{id}",
            target="example.test", endpoint="/api/users/42",
            class_id="idor", severity="high", hypothesis="cross-user read",
            hunt_id=self.HUNT_ID)
        orch_store.add_finding(
            con, "f.bare", "SQLi on /search", target="example.test",
            endpoint="/search", class_id="sqli", severity="medium",
            hunt_id=self.HUNT_ID)
        fid = con.execute(
            "SELECT id FROM finding WHERE finding_key='f.confirmed'").fetchone()["id"]
        # `add_evidence` computes the sha256 itself from the blob — it is a
        # content hash of the captured artifact, not a caller-supplied value.
        orch_store.add_evidence(
            con, "request", finding_id=fid, target="example.test",
            endpoint="/api/users/42", request_raw="GET /api/users/42",
            response_raw="HTTP/1.1 200 ...")
        orch_store.add_evidence(
            con, "response", finding_id=fid, target="example.test",
            endpoint="/api/users/42", response_raw="HTTP/1.1 200 ... other user")

    def tearDown(self):
        self.con.close()
        if _CURRENT:
            self.fail("rule violations:\n  - " + "\n  - ".join(_CURRENT))

    # ------------------------------------------------------------------
    def test_a_confirmed_finding_becomes_a_lesson(self):
        print("\nB1  A CONFIRMED FINDING BECOMES A LESSON")
        r = self.bridge.record_hunt_outcome(
            self.con, "f.confirmed", lifecycle_state="VALIDATED")
        check("the outcome is recorded", r["ok"], str(r))
        check("the outcome is reported as confirmed",
              r["outcome"] == "confirmed", str(r))
        n = self.con.execute(
            "SELECT count(*) n FROM lesson WHERE topic LIKE 'outcome:idor:%'"
        ).fetchone()["n"]
        check("a lesson row exists in the canonical database", n == 1, f"n={n}")

    def test_a_confirmed_finding_with_evidence_is_VERIFIED(self):
        print("\nB2  A CONFIRMED FINDING WITH EVIDENCE IS VERIFIED")
        r = self.bridge.record_hunt_outcome(
            self.con, "f.confirmed", lifecycle_state="VALIDATED")
        check("the lesson is verified", r["verified"], str(r))
        check("the lesson is promotable", r["promotable"], str(r))
        state = self.con.execute(
            "SELECT state FROM lesson WHERE lesson_key=?",
            (r["lesson_key"],)).fetchone()["state"]
        check("the lesson state is 'verified'", state == "verified", state)

        # And it is now retrievable as intelligence.
        br = self.le.before_recon(self.con, "example.test")
        topics = [l["topic"] for l in br["lessons"]]
        check("before_recon now returns the lesson",
              any("outcome:idor" in t for t in topics), str(topics))

    def test_a_confirmed_finding_WITHOUT_evidence_is_not_promoted(self):
        print("\nB3  A CONFIRMED FINDING WITHOUT EVIDENCE IS NOT PROMOTED")
        r = self.bridge.record_hunt_outcome(
            self.con, "f.bare", lifecycle_state="VALIDATED")
        check("the outcome is still recorded", r["ok"], str(r))
        check("the lesson is NOT verified", not r["verified"], str(r))
        check("the lesson is NOT promotable", not r["promotable"], str(r))
        state = self.con.execute(
            "SELECT state FROM lesson WHERE lesson_key=?",
            (r["lesson_key"],)).fetchone()["state"]
        check("the lesson state is 'captured', not 'verified'",
              state == "captured", state)
        check("the reason names the missing evidence",
              "evidence" in r.get("reason", "").lower(), str(r))

    def test_a_false_positive_is_never_promoted(self):
        print("\nB4  A FALSE POSITIVE IS NEVER PROMOTED")
        r = self.bridge.record_hunt_outcome(
            self.con, "f.bare", lifecycle_state="FALSE_POSITIVE",
            notes="the response was expected behaviour")
        check("the outcome is recorded", r["ok"], str(r))
        check("the outcome is reported as rejected",
              r["outcome"] == "rejected", str(r))
        check("the lesson is NOT promotable", not r["promotable"], str(r))
        state = self.con.execute(
            "SELECT state FROM lesson WHERE lesson_key=?",
            (r["lesson_key"],)).fetchone()["state"]
        check("the lesson state is 'rejected'", state == "rejected", state)
        check("the score was pushed down",
              r["score"] < 0.2, str(r))

        # And it must not appear as intelligence.
        br = self.le.before_recon(self.con, "example.test")
        check("a rejected lesson is not returned as intelligence",
              not any("outcome:sqli" in l["topic"] for l in br["lessons"]),
              str([l["topic"] for l in br["lessons"]]))

    def test_recording_twice_is_idempotent(self):
        print("\nB5  RECORDING THE SAME OUTCOME TWICE IS IDEMPOTENT")
        first = self.bridge.record_hunt_outcome(
            self.con, "f.confirmed", lifecycle_state="VALIDATED")
        second = self.bridge.record_hunt_outcome(
            self.con, "f.confirmed", lifecycle_state="VALIDATED")
        check("both calls succeed", first["ok"] and second["ok"])
        check("both calls use the SAME lesson key",
              first["lesson_key"] == second["lesson_key"],
              f"{first['lesson_key']} != {second['lesson_key']}")
        n = self.con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("there is exactly ONE lesson row", n == 1, f"n={n}")

    def test_triage_feedback_recalibrates_the_lesson(self):
        print("\nB6  TRIAGE FEEDBACK RECALIBRATES THE LESSON")
        self.bridge.record_hunt_outcome(
            self.con, "f.confirmed", lifecycle_state="VALIDATED")
        before = self.con.execute(
            "SELECT score FROM lesson WHERE topic LIKE 'outcome:idor:%'"
        ).fetchone()["score"]

        r = self.bridge.record_triage_feedback(
            self.con, "f.confirmed", feedback_type="duplicate",
            notes="the program already has this issue")
        check("the feedback is accepted", r["ok"], str(r))
        check("the score moved down", r["score"] < before,
              f"{before} -> {r['score']}")
        n = self.con.execute(
            "SELECT count(*) n FROM lesson_feedback").fetchone()["n"]
        check("the feedback is persisted", n == 1, f"n={n}")

        bad = self.bridge.record_triage_feedback(
            self.con, "f.confirmed", feedback_type="whatever")
        check("an unknown feedback type is refused", not bad["ok"], str(bad))

    def test_triage_feedback_without_a_lesson_is_refused(self):
        print("\nB7  TRIAGE FEEDBACK WITHOUT A LESSON IS REFUSED")
        r = self.bridge.record_triage_feedback(
            self.con, "f.bare", feedback_type="accepted")
        check("the feedback is refused", not r["ok"], str(r))
        check("the refusal says to record the outcome first",
              "outcome" in r.get("reason", "").lower(), str(r))

    def test_sync_reconciles_findings_resolved_before_the_bridge(self):
        print("\nB8  SYNC RECONCILES EARLIERLY-RESOLVED FINDINGS")
        # A finding that reached a terminal state with no bridge involvement.
        self.con.execute(
            "INSERT INTO finding_state(finding_key,lifecycle,changed_by,"
            "reason,at) VALUES ('f.bare','VALIDATED','test','sync',?)",
            ("2026-01-01T00:00:00Z",))
        self.con.commit()

        r = self.bridge.sync_finding_outcomes(self.con)
        check("the sync succeeds", r["ok"], str(r))
        check("the earlier finding was recorded", r["recorded"] >= 1, str(r))
        n = self.con.execute(
            "SELECT count(*) n FROM lesson WHERE topic LIKE 'outcome:sqli:%'"
        ).fetchone()["n"]
        check("a lesson now exists for it", n == 1, f"n={n}")

        # And it is idempotent.
        r2 = self.bridge.sync_finding_outcomes(self.con)
        n2 = self.con.execute(
            "SELECT count(*) n FROM lesson WHERE topic LIKE 'outcome:sqli:%'"
        ).fetchone()["n"]
        check("a repeat sync creates no second lesson", n2 == n,
              f"{n} -> {n2}")

    def test_an_unknown_finding_is_refused_not_invented(self):
        print("\nB9  AN UNKNOWN FINDING IS REFUSED, NOT INVENTED")
        r = self.bridge.record_hunt_outcome(self.con, "f.does-not-exist")
        check("the outcome is refused", not r["ok"], str(r))
        n = self.con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("no lesson was created", n == 0, f"n={n}")

    def test_the_bridge_writes_only_learning_tables(self):
        print("\nB10  THE BRIDGE WRITES ONLY LEARNING TABLES")
        before = self._table_snapshots()
        self.bridge.record_hunt_outcome(
            self.con, "f.confirmed", lifecycle_state="VALIDATED")
        after = self._table_snapshots()
        changed = {t for t in after if before.get(t) != after[t]}
        check("only learning tables changed",
              changed <= {"lesson", "lesson_feedback", "learning_gap",
                          "learning_research"},
              str(changed))

    def _table_snapshots(self) -> dict[str, int]:
        snap: dict[str, int] = {}
        for t in ("item", "source", "bug_class", "quality", "finding",
                  "evidence", "agent_run", "event", "task",
                  "lesson", "lesson_feedback", "learning_gap"):
            try:
                snap[t] = self.con.execute(
                    f"SELECT count(*) n FROM {t}").fetchone()["n"]
            except sqlite3.OperationalError:
                snap[t] = -1
        return snap


if __name__ == "__main__":
    unittest.main(verbosity=2)
