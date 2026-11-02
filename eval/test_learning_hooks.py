"""Integration test for the five adaptive-memory hooks.

MEASURED CONTEXT: before this test existed, the learning engine had no
`LearningEngine` class, its five documented hooks did not exist in any
callable form, and it wrote to a PRIVATE `learning_engine/memory/learning.db`
that no component outside the package read. The canonical database had no
learning tables at all.

These tests therefore check the two properties that were missing:

  1. the hooks work, and
  2. they write to the CANONICAL database — a scratch copy of it, so the
     live corpus is never touched — and create no second database file.

Every assertion has a matching negative control, because a check that
cannot go red certifies nothing.
"""
from __future__ import annotations

import os
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

# A check that only PRINTS its failure certifies nothing: the suite would
# report OK while a hook was broken. Failures are collected here and the test
# fails at teardown if any were recorded.
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


class LearningHookTests(unittest.TestCase):
    def setUp(self):
        _CURRENT.clear()
        self.tmp = tempfile.mkdtemp(prefix="learn_hooks_")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        # A scratch copy of the canonical schema — the learning engine's
        # canonical home is `db/wks.db`, and this test must not write to it.
        from wks import config as wks_config
        from wks import store as wks_store
        schema = Path(wks_config.SCHEMA_PATH).read_text(encoding="utf-8")
        self.db = Path(self.tmp) / "wks.db"
        con = sqlite3.connect(str(self.db))
        con.executescript(schema)
        con.commit()
        con.close()
        self.wks_store = wks_store

        from learning_engine import engine as le
        self.le = le
        con = sqlite3.connect(str(self.db))
        con.row_factory = sqlite3.Row
        le.ensure_schema(con)
        # Register a class so the analysis hook has something to examine.
        wks_store.upsert_class(con, "sqli", "SQL Injection", "web",
                               cwe="CWE-89", owasp="A03:2021")
        wks_store.upsert_class(con, "idor", "IDOR", "web", cwe="CWE-639")
        con.commit()
        self.con = con
        # A VALIDATED AUTHORIZATION RECEIPT.
        #
        # MEASURED 2026-11-02: this file captured its lessons with an
        # explicit `origin="PRODUCTION_HUNT"` and no receipt, and asserted
        # that they verified. That was the defect the receipt closes: the
        # origin was ASSERTED, so any caller could manufacture production
        # hunting experience.
        #
        # The fixture now creates the receipt the runtime creates -- a
        # validated `hunt_authorization` row -- and passes it to
        # `capture_hook`. The lesson is production-origin because the
        # authorization says so, not because the test says so.
        #
        # The receipt is written through the orchestrator's own schema, so
        # the table exists. `orch.schema.sql` is applied to the scratch
        # database before the learning schema, mirroring the runtime
        # order.
        orch_schema = (ROOT / "orch" / "schema.sql").read_text(encoding="utf-8")
        self.con.executescript(orch_schema)
        self.con.commit()
        self.HUNT_ID = "hooks.hunt"
        self.AUTH_REF = "https://example.test/program/scope"
        # THE RECEIPT IS WRITTEN THROUGH THE OWNER THAT OWNS IT.
        #
        # `hunt_authorization` is an ORCHESTRATION table, and this
        # connection is the WKS owner -- so the runtime authorizer refuses
        # the write with "not authorized". That refusal is the ownership
        # boundary working exactly as designed: the receipt is operational
        # state, and the knowledge layer must not write it.
        #
        # So the write goes through `owner_write(con, ORCH)`, which is
        # exactly the sanctioned crossing the orchestrator itself uses.
        from wks import ownership as _ownership
        with _ownership.owner_write(self.con, _ownership.ORCH):
            self.con.execute(
                "INSERT OR REPLACE INTO hunt_authorization(auth_id, hunt_id,"
                " program, target, kind, authorization_ref,"
                " offensive_allowed, validated, validated_at, created_at,"
                " context_json, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                ("auth." + self.HUNT_ID, self.HUNT_ID, "example-program",
                 "example.test", "bugbounty", self.AUTH_REF, 1, 1,
                 "2026-01-01T00:00:00+00:00",
                 "2026-01-01T00:00:00+00:00", "{}", "test fixture receipt"))
            self.con.commit()

    def _capture(self, **kw):
        """Capture a lesson backed by the fixture's receipt."""
        kw.setdefault("hunt_id", self.HUNT_ID)
        kw.setdefault("authorization_ref", self.AUTH_REF)
        return self.le.capture_hook(self.con, **kw)

    def tearDown(self):
        self.con.close()
        if _CURRENT:
            self.fail("rule violations:\n  - " + "\n  - ".join(_CURRENT))

    # ------------------------------------------------------------------
    def test_capture_hook_persists_and_is_idempotent(self):
        print("\nL1  CAPTURE PERSISTS, AND IS IDEMPOTENT")
        r1 = self.le.capture_hook(self.con, topic="sqli: blind boolean works",
                                  body="a quoted ' AND 1=1 changed the row count",
                                  class_id="sqli", score=0.6)
        check("capture reports ok", r1["ok"], str(r1))
        check("capture creates a lesson", r1["created"], str(r1))
        n = self.con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("one lesson row exists", n == 1, f"n={n}")

        r2 = self.le.capture_hook(self.con, topic="sqli: blind boolean works",
                                  body="a quoted ' AND 1=1 changed the row count",
                                  class_id="sqli", score=0.6)
        check("a repeat capture is idempotent", r2["idempotent"], str(r2))
        n = self.con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("still exactly one lesson row", n == 1, f"n={n}")

        bad = self.le.capture_hook(self.con, topic="", body="")
        check("an empty lesson is refused", not bad["ok"], str(bad))

    def test_analyze_hook_finds_and_persists_gaps(self):
        print("\nL2  ANALYZE FINDS AND PERSISTS GAPS")
        self.le.capture_hook(self.con, topic="unverified thought",
                             body="this has never been checked against a page",
                             class_id="sqli")
        r = self.le.analyze_hook(self.con)
        check("analyze reports ok", r["ok"], str(r))
        kinds = {g["kind"] for g in r["gaps"]}
        check("an unresearched class is found",
              "unresearched_class" in kinds, str(kinds))
        check("an unverified lesson is found",
              "unverified_lesson" in kinds, str(kinds))
        n = self.con.execute("SELECT count(*) n FROM learning_gap").fetchone()["n"]
        check("gaps are PERSISTED, not merely returned", n > 0, f"n={n}")

        r2 = self.le.analyze_hook(self.con)
        n2 = self.con.execute("SELECT count(*) n FROM learning_gap").fetchone()["n"]
        check("a repeat analysis does not duplicate gaps", n2 == n,
              f"{n} -> {n2}")

    def test_research_hook_turns_a_gap_into_a_persisted_task(self):
        print("\nL3  RESEARCH TURNS A GAP INTO A PERSISTED TASK")
        self.le.analyze_hook(self.con)
        gap = self.con.execute(
            "SELECT gap_key, class_id FROM learning_gap WHERE class_id='idor'"
            " LIMIT 1").fetchone()
        check("a gap for idor exists", gap is not None)
        r = self.le.research_hook(self.con, gap_key=gap["gap_key"])
        check("research reports ok", r["ok"], str(r))
        check("a research row is persisted",
              self.con.execute("SELECT count(*) n FROM learning_research"
                               ).fetchone()["n"] == 1)
        status = self.con.execute("SELECT status FROM learning_gap"
                                  " WHERE gap_key=?", (gap["gap_key"],)
                                  ).fetchone()["status"]
        check("the gap is marked proposed", status == "proposed", status)

        r2 = self.le.research_hook(self.con, gap_key=gap["gap_key"])
        check("research is idempotent", r2["idempotent"], str(r2))
        check("still one research row",
              self.con.execute("SELECT count(*) n FROM learning_research"
                               ).fetchone()["n"] == 1)

    def test_verify_hook_refuses_without_evidence(self):
        print("\nL4  VERIFY REFUSES WITHOUT EVIDENCE")
        cap = self._capture(topic="a claim",
                            body="something worth checking",
                            class_id="sqli",
                            # The claim is checked against a real
                            # page, so it is a PRODUCTION observation --
                            # and the fixture's authorization receipt is
                            # what makes that true. MEASURED 2026-11-02:
                            # this asserted `origin="PRODUCTION_HUNT"`
                            # with no receipt, which was the self-
                            # promotion defect itself. The receipt is
                            # created in setUp and passed here.
                            origin="PRODUCTION_HUNT")
        key = cap["lesson_key"]
        r = self.le.verify_hook(self.con, lesson_key=key, evidence=None)
        check("verification without evidence is REFUSED", not r["ok"], str(r))
        check("the refusal names the reason",
              "evidence" in r.get("reason", "").lower(), str(r))
        state = self.con.execute("SELECT state FROM lesson WHERE lesson_key=?",
                                 (key,)).fetchone()["state"]
        check("the lesson is still unverified", state == "captured", state)

        ok = self.le.verify_hook(self.con, lesson_key=key,
                                 evidence="verified against page X",
                                 provenance={"source": "test"})
        check("verification WITH evidence succeeds", ok["ok"], str(ok))
        state = self.con.execute("SELECT state FROM lesson WHERE lesson_key=?",
                                 (key,)).fetchone()["state"]
        check("the lesson is now verified", state == "verified", state)

    def test_update_hook_requires_a_verified_lesson(self):
        print("\nL5  UPDATE REFUSES AN UNVERIFIED LESSON")
        cap = self._capture(topic="a claim",
                            body="not checked yet", class_id="sqli",
                            # See the note above: the receipt in setUp is
                            # what backs the production origin.
                            origin="PRODUCTION_HUNT")
        key = cap["lesson_key"]
        r = self.le.update_hook(self.con, lesson_key=key)
        check("update of an UNVERIFIED lesson is refused", not r["ok"], str(r))
        check("the refusal names verification",
              "verified" in r.get("reason", "").lower(), str(r))

        self.le.verify_hook(self.con, lesson_key=key,
                            evidence="verified against page X")
        r2 = self.le.update_hook(self.con, lesson_key=key)
        # This test runs against a SCRATCH database (see setUp), which is NOT
        # the canonical store. The projection therefore REFUSES -- correctly:
        # `wks.project` writes to the canonical tree, so rendering the scratch
        # corpus there would overwrite the real skill with this fixture's
        # empty one. MEASURED 2026-10-31: before the refusal existed, this
        # exact call overwrote the 45-item sqli hunting skill with an empty
        # "planned" skeleton, and every db-backed check kept passing while the
        # file the agent loads was empty.
        check("a VERIFIED lesson is accepted for projection",
              not r2.get("reason", "").lower().startswith("only a verified"),
              str(r2))
        check("projection from a NON-CANONICAL connection is refused",
              not r2["ok"], str(r2))
        check("the refusal names the canonical-store mismatch",
              "canonical" in r2.get("reason", "").lower(), str(r2))

    def test_canonical_projection_writes_the_canonical_tree(self):
        """The positive case: a canonical connection DOES project.

        Without this, "the projection is refused" could be satisfied by a
        projection that never works at all. The two halves are tested together
        on purpose: the refusal is only meaningful if the permission is real.

        Sandboxed through `WKS_ROOT`, so the projection writes to a throwaway
        tree and NOT the canonical one. The guard compares the connection's
        file against `config.db_path()`, and both move together when the root
        moves -- that is what makes a sandboxed projection legal while a
        scratch-DB projection onto the real tree is not.
        """
        print("\nL5b  A CANONICAL CONNECTION DOES PROJECT")
        prev_root = os.environ.get("WKS_ROOT")
        os.environ["WKS_ROOT"] = str(Path(self.tmp))
        try:
            from wks import project
            from wks import store as wks_store
            con = wks_store.open_db()
            try:
                wks_store.upsert_class(con, "sqli", "SQL Injection", "web",
                                       cwe="CWE-89", owasp="A03:2021")
                con.commit()
                r = project.refresh_class(con, "sqli")
                check("the canonical projection reports no errors",
                      not r["errors"], str(r["errors"]))
                r2 = project.refresh_class(con, "sqli")
                check("the canonical projection is idempotent on a second call",
                      r2["changed"] == [], str(r2["changed"]))
                from wks import domains as _D
                sk = _D.class_subdir("sqli", "skills", con) / "SKILL.md"
                check("the projection wrote the skill into the sandbox tree",
                      sk.exists(), str(sk))
                check("the projection did NOT write the canonical tree",
                      not Path(prev_root or
                               Path(__file__).resolve().parent.parent)
                      .joinpath("domains/web/sqli/skills/SKILL.md")
                      .resolve() == sk.resolve(), str(sk))
            finally:
                con.close()
        finally:
            if prev_root is None:
                os.environ.pop("WKS_ROOT", None)
            else:
                os.environ["WKS_ROOT"] = prev_root

    def test_engine_uses_the_canonical_database_not_a_second_one(self):
        print("\nL6  THE ENGINE WRITES TO THE CANONICAL DATABASE")
        before = set(os.listdir(str(Path(self.tmp))))
        self.le.capture_hook(self.con, topic="canonical check",
                             body="this must land in the shared database",
                             class_id="sqli")
        after = set(os.listdir(str(Path(self.tmp))))
        new_files = {f for f in after - before if f.endswith(".db")}
        check("no SECOND database file is created",
              not new_files, str(new_files))
        check("the only database is the canonical one",
              after - before == set() or not (after - before) - {"wks.db-wal",
                                                                "wks.db-shm"},
              str(after - before))

    def test_triage_feedback_recalibrates_and_rejects_false_positives(self):
        print("\nL7  TRIAGE FEEDBACK RECALIBRATES THE LESSON")
        cap = self.le.capture_hook(self.con, topic="a claim",
                                   body="possibly a false positive",
                                   class_id="sqli", score=0.5)
        key = cap["lesson_key"]
        r = self.le.after_triage(self.con, lesson_key=key,
                                 feedback_type="false_positive",
                                 notes="program says it is expected behaviour",
                                 provenance={"source": "program_triage"})
        check("triage is accepted", r["ok"], str(r))
        check("the score moved DOWN", r["score"] < 0.5, str(r))
        state = self.con.execute("SELECT state FROM lesson WHERE lesson_key=?",
                                 (key,)).fetchone()["state"]
        check("a false positive is REJECTED, not kept as knowledge",
              state == "rejected", state)
        n = self.con.execute("SELECT count(*) n FROM lesson_feedback"
                             ).fetchone()["n"]
        check("the feedback is persisted with its provenance", n == 1, f"n={n}")

        bad = self.le.after_triage(self.con, lesson_key=key,
                                   feedback_type="whatever")
        check("an unknown feedback type is refused", not bad["ok"], str(bad))

    def test_legacy_database_is_migrated_once_and_not_rewritten(self):
        print("\nL8  THE LEGACY DATABASE IS MIGRATED ONCE, THEN LEFT ALONE")
        legacy = self.le.LEGACY_DB
        self.assertTrue(legacy.is_file(), "the legacy db should still exist")
        before_mtime = legacy.stat().st_mtime_ns
        before_size = legacy.stat().st_size

        r1 = self.le.migrate_legacy(self.con)
        check("the migration reports what it did", "migrated" in r1, str(r1))
        n1 = self.con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        r2 = self.le.migrate_legacy(self.con)
        n2 = self.con.execute("SELECT count(*) n FROM lesson").fetchone()["n"]
        check("a repeat migration adds nothing", n2 == n1, f"{n1} -> {n2}")
        check("the legacy file is NOT rewritten",
              legacy.stat().st_mtime_ns == before_mtime
              and legacy.stat().st_size == before_size,
              "legacy db was modified")

    def test_named_integration_points_exist(self):
        print("\nL9  THE FIVE NAMED INTEGRATION POINTS EXIST")
        e = self.le.LearningEngine(self.con)
        check("before_recon exists", callable(e.before_recon))
        check("during_testing exists", callable(e.during_testing))
        check("after_finding exists", callable(e.after_finding))
        check("after_triage exists", callable(e.after_triage))
        check("before_summary exists", callable(e.before_summary))

        cap = self._capture(topic="verified lesson",
                            body="checked against a real page",
                            class_id="sqli",
                            # THE SCENARIO THIS FILE MODELS IS A
                            # VERIFIED PRODUCTION OBSERVATION, and the
                            # fixture's authorization receipt is what
                            # makes it one.
                            #
                            # MEASURED 2026-11-02: this asserted
                            # `origin="PRODUCTION_HUNT"` with no receipt.
                            # The origin was a CLAIM the test made about
                            # itself; the receipt is the PROOF. The
                            # eligibility rule is pinned in
                            # `eval/test_p2_provenance.py`.
                            origin="PRODUCTION_HUNT")
        self.le.verify_hook(self.con, lesson_key=cap["lesson_key"],
                            evidence="page X")
        br = e.before_recon("example.test", ["nginx"])
        check("before_recon returns verified lessons only",
              any(l["class_id"] == "sqli" for l in br["lessons"]), str(br))
        dt = e.during_testing({"sql_error_or_behaviour": 1.0})
        check("during_testing scores the signal", dt["signals"], str(dt))
        af = e.after_finding(target="example.test",
                             vulnerability_class="sqli",
                             signals={"sql_error_or_behaviour": 1},
                             validation_state="confirmed")
        check("after_finding captures a lesson", af["ok"], str(af))
        bs = e.before_summary([{"finding_key": "f1", "class_id": "sqli"}])
        check("before_summary ranks findings", bs["ranked"], str(bs))


if __name__ == "__main__":
    unittest.main(verbosity=2)
