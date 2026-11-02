"""A TEST FINDING MUST NEVER BECOME HUNTING EXPERIENCE.

MEASURED 2026-11-01: the test suite wrote 44 findings and 51 lessons into
the LIVE canonical database. The quarantine marked those records so a human
could see them, but the SYSTEM had no field that said where a record came
from, so every query that asked "how much impact is on the table" or "what
does the corpus already know" counted the test output as real work:

  * `orch/scheduler.py` counted every `candidate`/`validating` finding as
    unvalidated impact. Its stop condition could not be reached.
  * `orch/hunting.py` computed the hunt's value from the same set, so a
    hunt's value was dominated by contamination.
  * `learning_engine.before_recon` returned every `verified` lesson to the
    next hunt. A test lesson became class-level experience that steered a
    real hunt's attack model.
  * `learning_engine.verify_hook` refused a lesson with no EVIDENCE, but
    accepted one from any origin. Evidence proves a claim; it says nothing
    about where the claim came from.

This test proves the structural property that closes the class of defect:
A FINDING'S ORIGIN IS INHERITED BY ITS LESSON, AND AN INELIGIBLE ORIGIN
CANNOT BE VERIFIED, PROMOTED, OR RETURNED AS INTELLIGENCE.

It runs against a disposable scratch database, so it never touches the
canonical corpus.
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


def _lesson_origin(con: sqlite3.Connection, lesson_key: str) -> str:
    row = con.execute(
        "SELECT origin FROM lesson WHERE lesson_key=?", (lesson_key,)).fetchone()
    return row["origin"] if row else "<missing>"


def _lesson_state(con: sqlite3.Connection, lesson_key: str) -> str:
    row = con.execute(
        "SELECT state FROM lesson WHERE lesson_key=?", (lesson_key,)).fetchone()
    return row["state"] if row else "<missing>"


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        _CURRENT.clear()
        self.tmp = tempfile.mkdtemp(prefix="provenance_")
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

        from orch import lifecycle as lifecycle_mod
        lifecycle_mod._ensure(con)

        from orch import store as orch_store
        from orch import learning_bridge as bridge_mod
        self.store = orch_store
        self.bridge = bridge_mod

        self.prov = __import__("orch.provenance", fromlist=["provenance"])

    # ------------------------------------------------------------------
    # P1: THE SCHEMA HAS THE FIELDS, AND A LEGACY DATABASE IS MIGRATED
    # ------------------------------------------------------------------
    def test_p1_the_eligibility_columns_exist_and_default_fail_closed(self):
        print("\nP1  THE ELIGIBILITY COLUMNS EXIST AND DEFAULT FAIL-CLOSED")

        fcols = {r["name"] for r in self.con.execute(
            "PRAGMA table_info(finding)")}
        check("finding has a provenance column", "provenance" in fcols,
              str(sorted(fcols)))
        lcols = {r["name"] for r in self.con.execute(
            "PRAGMA table_info(lesson)")}
        check("lesson has an origin column", "origin" in lcols,
              str(sorted(lcols)))
        check("lesson ALSO keeps its provenance descriptor blob",
              "provenance" in lcols, str(sorted(lcols)))

        # The descriptor and the eligibility are DIFFERENT columns. If a
        # caller wrote the descriptor into the eligibility column, the
        # descriptor would be lost and every lesson would read UNKNOWN.
        self.con.execute(
            "INSERT INTO lesson(lesson_key, topic, body, score, state,"
            " provenance, origin, created_at, updated_at)"
            " VALUES ('k.desc','t','b',0.5,'captured',?,?,?,?)",
            (json.dumps({"source": "a.test"}), self.prov.EVAL_TEST,
             "2026-11-01T00:00:00", "2026-11-01T00:00:00"))
        self.con.commit()
        blob = self.con.execute(
            "SELECT provenance FROM lesson WHERE lesson_key='k.desc'"
        ).fetchone()["provenance"]
        check("the descriptor blob survives the eligibility write",
              "a.test" in str(blob), str(blob))

    def test_p2_a_legacy_database_is_migrated_on_open(self):
        print("\nP2  A LEGACY DATABASE IS MIGRATED ON OPEN")

        legacy = Path(self.tmp) / "legacy.db"
        con = sqlite3.connect(str(legacy))
        con.row_factory = sqlite3.Row
        # The REAL legacy shape of `finding`: the columns the live
        # database had before `provenance` was added, minus `confidence`
        # and `priority` (added by an earlier migration) so this test
        # exercises BOTH migrations on a genuinely old table.
        #
        # MEASURED 2026-11-01: the first version of this test used a
        # four-column `finding` table, and `open_db` failed with "no such
        # column: dedup_group" -- because `orch/schema.sql` creates an
        # index on `finding(dedup_group)` and the table already existed
        # without it. A migration test must use the shape that actually
        # occurs, not a convenient one.
        con.execute(
            "CREATE TABLE finding (id INTEGER PRIMARY KEY, finding_key TEXT,"
            " title TEXT, target TEXT, asset TEXT, endpoint TEXT,"
            " class_id TEXT, hypothesis TEXT, severity TEXT, status TEXT,"
            " validation_json TEXT, dedup_group TEXT, canonical_id INTEGER,"
            " validator_run TEXT, report_path TEXT, created_at TEXT,"
            " updated_at TEXT)")
        con.execute(
            "INSERT INTO finding(finding_key,title,status,created_at,updated_at)"
            " VALUES ('legacy.1','old','candidate','x','x')")
        con.execute(
            "CREATE TABLE lesson (lesson_key TEXT PRIMARY KEY, topic TEXT,"
            " body TEXT, score REAL, state TEXT, provenance TEXT,"
            " evidence TEXT, created_at TEXT, updated_at TEXT)")
        con.execute(
            "INSERT INTO lesson(lesson_key,topic,body,score,state,provenance,"
            " evidence,created_at,updated_at)"
            " VALUES ('legacy.l','t','b',0.5,'captured','{}',NULL,'x','x')")
        con.commit()
        con.close()

        # `open_db` resolves the canonical path, so point the config at
        # the legacy file for the duration of the open.
        from wks import config as wks_config
        from orch import store as orch_store
        original = wks_config.db_path
        try:
            wks_config.db_path = lambda: legacy
            orch_store.db_path = lambda: legacy
            con = orch_store.open_db(create=True)
            fcols = {r["name"] for r in con.execute(
                "PRAGMA table_info(finding)")}
            lcols = {r["name"] for r in con.execute(
                "PRAGMA table_info(lesson)")}
            check("the legacy finding table gained `provenance`",
                  "provenance" in fcols, str(sorted(fcols)))
            check("the legacy lesson table gained `origin`",
                  "origin" in lcols, str(sorted(lcols)))
            v = con.execute(
                "SELECT provenance FROM finding WHERE finding_key='legacy.1'"
            ).fetchone()["provenance"]
            check("the pre-existing finding defaults to UNKNOWN, not to a "
                  "guess", v == self.prov.UNKNOWN, repr(v))
            o = con.execute(
                "SELECT origin FROM lesson WHERE lesson_key='legacy.l'"
            ).fetchone()["origin"]
            check("the pre-existing lesson defaults to UNKNOWN",
                  o == self.prov.UNKNOWN, repr(o))
            check("the legacy row itself was preserved",
                  con.execute("SELECT count(*) n FROM finding"
                              " WHERE finding_key='legacy.1'"
                              ).fetchone()["n"] == 1)
            con.close()
        finally:
            wks_config.db_path = original
            orch_store.db_path = original

    # ------------------------------------------------------------------
    # P3: THE BRIDGE INHERITS THE FINDING'S ORIGIN
    # ------------------------------------------------------------------
    def _add_finding(self, key: str, provenance: str, title: str = "t"):
        """File a finding with the given provenance.

        MEASURED 2026-11-02: this helper asserted `provenance` directly,
        with no authorization anywhere -- which is the self-declaration
        `add_finding` now correctly refuses. A production finding is
        therefore created the way the runtime creates one: a hunt with a
        VALIDATED AUTHORIZATION RECEIPT that names the target.
        """
        if provenance == self.prov.PRODUCTION_HUNT:
            hunt_id = "prov." + key
            self._receipt(hunt_id=hunt_id, target="app.prov.example")
            self.store.add_finding(self.con, key, title, target="app.prov.example",
                                   class_id="cors", severity="high",
                                   hunt_id=hunt_id)
        else:
            self.store.add_finding(self.con, key, title, target="127.0.0.1",
                                   class_id="cors", severity="high",
                                   provenance=provenance)
        return self.con.execute(
            "SELECT * FROM finding WHERE finding_key=?", (key,)).fetchone()

    def _receipt(self, *, hunt_id: str, target: str) -> dict:
        """Record a validated authorization receipt for a hunt."""
        from orch import authz as authz_mod
        from wks import ownership as _ownership
        ctx = authz_mod.AuthorizationContext(
            program="prov-program", target=target,
            in_scope_assets=[target],
            reporting_requirements={"format": "md"},
            authorization_ref="PROV-SCOPE", kind="bugbounty",
            allowed_actions=["recon", "probe"])
        with _ownership.owner_write(self.con, _ownership.ORCH):
            return ctx.validate_and_record(self.con, hunt_id=hunt_id)

    def test_p3_the_lesson_inherits_the_findings_origin(self):
        print("\nP3  THE LESSON INHERITS THE FINDING'S ORIGIN")

        self._add_finding("f.test", self.prov.EVAL_TEST)
        r = self.bridge.record_hunt_outcome(
            self.con, "f.test", lifecycle_state="TESTING")
        check("the outcome was recorded", r.get("ok"), str(r))
        lk = r.get("lesson_key")
        check("a lesson key was returned", bool(lk), str(r))
        if lk:
            check("the lesson's origin is EVAL_TEST, inherited from the "
                  "finding",
                  _lesson_origin(self.con, lk) == self.prov.EVAL_TEST,
                  _lesson_origin(self.con, lk))

    def test_p4_a_production_finding_produces_a_production_lesson(self):
        print("\nP4  A PRODUCTION FINDING PRODUCES A PRODUCTION LESSON")

        self._add_finding("f.prod", self.prov.PRODUCTION_HUNT)
        r = self.bridge.record_hunt_outcome(
            self.con, "f.prod", lifecycle_state="TESTING")
        lk = r.get("lesson_key")
        check("the outcome was recorded", r.get("ok"), str(r))
        if lk:
            check("the lesson's origin is PRODUCTION_HUNT",
                  _lesson_origin(self.con, lk) == self.prov.PRODUCTION_HUNT,
                  _lesson_origin(self.con, lk))

    def test_p4b_a_confirmed_test_finding_is_refused_the_lesson_but_recorded(self):
        print("\nP4b  A CONFIRMED TEST FINDING IS REFUSED THE LESSON, "
              "BUT RECORDED")

        # A CONFIRMED finding from a test run. This is the exact case
        # that contaminated the corpus: the finding was confirmed and
        # carried evidence, so the old code verified the lesson.
        self._add_finding("f.conf.test", self.prov.EVAL_TEST)
        # Attach evidence, so the refusal is not merely "no evidence".
        self.con.execute(
            "INSERT INTO evidence(finding_id, kind, target, asset, endpoint,"
            " sha256, captured_at) VALUES"
            " ((SELECT id FROM finding WHERE finding_key='f.conf.test'),"
            " 'request','http://127.0.0.1:1/','127.0.0.1','http://127.0.0.1:1/',"
            " 'abc','2026-11-01T00:00:00')")
        self.con.commit()

        r = self.bridge.record_hunt_outcome(
            self.con, "f.conf.test", lifecycle_state="VALIDATED")
        check("the outcome was recorded", r.get("ok"), str(r))
        lk = r.get("lesson_key")
        check("a lesson WAS created -- nothing is deleted",
              bool(lk), str(r))
        if not lk:
            return
        check("the lesson is NOT verified",
              r.get("verified") is False, str(r))
        check("the lesson is NOT promotable",
              r.get("promotable") is False, str(r))
        check("the lesson did not advance to verified",
              _lesson_state(self.con, lk) != "verified",
              _lesson_state(self.con, lk))
        check("the result names the origin that caused the refusal",
              r.get("origin") == self.prov.EVAL_TEST, str(r))
        check("the result names the refusal",
              r.get("outcome") == "ineligible_origin", str(r))

        # The link must record the refusal, not "confirmed".
        link = self.con.execute(
            "SELECT outcome FROM finding_lesson WHERE finding_key=?",
            ("f.conf.test",)).fetchone()
        check("the orchestration link records the refusal",
              link is not None and link["outcome"] == "ineligible_origin",
              str(dict(link) if link else None))

        # And the refusal must be RECORDED, not silently dropped.
        fb = self.con.execute(
            "SELECT count(*) n FROM lesson_feedback WHERE lesson_key=?",
            (lk,)).fetchone()["n"]
        check("the refusal is recorded as feedback", fb >= 1, f"n={fb}")

    def test_p4c_a_confirmed_production_finding_with_evidence_is_verified(self):
        print("\nP4c  A CONFIRMED PRODUCTION FINDING WITH EVIDENCE IS VERIFIED")

        self._add_finding("f.conf.prod", self.prov.PRODUCTION_HUNT)
        self.con.execute(
            "INSERT INTO evidence(finding_id, kind, target, asset, endpoint,"
            " sha256, captured_at) VALUES"
            " ((SELECT id FROM finding WHERE finding_key='f.conf.prod'),"
            " 'request','https://real.example/','real.example',"
            " 'https://real.example/','abc','2026-11-01T00:00:00')")
        self.con.commit()

        r = self.bridge.record_hunt_outcome(
            self.con, "f.conf.prod", lifecycle_state="VALIDATED")
        lk = r.get("lesson_key")
        check("the outcome was recorded", r.get("ok"), str(r))
        if lk:
            check("the lesson IS verified for a production finding",
                  _lesson_state(self.con, lk) == "verified",
                  _lesson_state(self.con, lk))
            link = self.con.execute(
                "SELECT outcome FROM finding_lesson WHERE finding_key=?",
                ("f.conf.prod",)).fetchone()
            check("the orchestration link records 'confirmed'",
                  link is not None and link["outcome"] == "confirmed",
                  str(dict(link) if link else None))

    # ------------------------------------------------------------------
    # P5: AN INELIGIBLE LESSON CANNOT BE VERIFIED
    #
    # THIS IS THE CORE ASSERTION. Before the fix, `verify_hook` refused
    # only a lesson with NO evidence. A lesson from a test run, given any
    # evidence, was promoted to `verified` -- and `verified` is what
    # `before_recon` returns as intelligence.
    # ------------------------------------------------------------------
    def test_p5_an_ineligible_lesson_cannot_be_verified(self):
        print("\nP5  AN INELIGIBLE LESSON CANNOT BE VERIFIED")

        for origin in (self.prov.EVAL_TEST, self.prov.EXAM_FIXTURE,
                       self.prov.UNKNOWN):
            key = f"k.{origin}"
            self.con.execute(
                "INSERT INTO lesson(lesson_key, topic, body, score, state,"
                " provenance, origin, evidence, created_at, updated_at)"
                " VALUES (?,'t','b',0.5,'captured','{}',?,NULL,?,?)",
                (key, origin, "2026-11-01T00:00:00", "2026-11-01T00:00:00"))
        self.con.commit()

        for origin in (self.prov.EVAL_TEST, self.prov.EXAM_FIXTURE,
                       self.prov.UNKNOWN):
            key = f"k.{origin}"
            r = self.le.verify_hook(self.con, lesson_key=key,
                                     evidence="some evidence")
            check(f"verification is REFUSED for origin {origin}",
                  not r.get("verified"), str(r))
            check(f"the lesson did not advance to verified for {origin}",
                  _lesson_state(self.con, key) != "verified",
                  _lesson_state(self.con, key))

    def test_p6_an_eligible_lesson_can_be_verified(self):
        print("\nP6  AN ELIGIBLE LESSON CAN BE VERIFIED")

        # AN ELIGIBLE LESSON WITH A RECEIPT.
        #
        # MEASURED 2026-11-02: this inserted a lesson with origin
        # PRODUCTION_HUNT and an empty descriptor -- no hunt, no
        # authorization. `verify_hook` now demands the receipt rather than
        # trusting the origin column, so the fixture names the hunt whose
        # receipt backs it.
        #
        # The lesson is created through `capture_hook`, which is the
        # path that enforces the receipt, so the fixture cannot assert an
        # origin the runtime would refuse.
        hunt_id = "prov.p6"
        self._receipt(hunt_id=hunt_id, target="app.prov.example")
        cap = self.le.capture_hook(
            self.con, topic="t", body="b", class_id="cors", score=0.5,
            origin=self.prov.PRODUCTION_HUNT, hunt_id=hunt_id,
            authorization_ref="PROV-SCOPE")
        key = cap["lesson_key"]
        r = self.le.verify_hook(self.con, lesson_key=key,
                                 evidence="some evidence")
        check("verification succeeds for a PRODUCTION_HUNT lesson",
              r.get("verified"), str(r))
        check("the lesson advanced to verified",
              _lesson_state(self.con, key) == "verified",
              _lesson_state(self.con, key))

    # ------------------------------------------------------------------
    # P7: THE RETRIEVAL PATH DOES NOT RETURN TEST EXPERIENCE
    # ------------------------------------------------------------------
    def test_p7_before_recon_does_not_return_ineligible_lessons(self):
        print("\nP7  BEFORE_RECON DOES NOT RETURN INELIGIBLE LESSONS")

        for origin, topic in (
                (self.prov.EVAL_TEST, "outcome:cors:127.0.0.1"),
                (self.prov.EXAM_FIXTURE, "outcome:cors:exam"),
                (self.prov.PRODUCTION_HUNT, "outcome:cors:real.example")):
            self.con.execute(
                "INSERT INTO lesson(lesson_key, topic, body, class_id, score,"
                " state, provenance, origin, evidence, created_at, updated_at)"
                " VALUES (?,?,'b','cors',0.9,'verified','{}',?,?,?,?)",
                (f"k.rec.{origin}", topic, origin, "evidence",
                 "2026-11-01T00:00:00", "2026-11-01T00:00:00"))
        self.con.commit()

        out = self.le.before_recon(self.con, "real.example")
        topics = [x["topic"] for x in out.get("lessons", [])]
        check("the production lesson IS returned",
              "outcome:cors:real.example" in topics, str(topics))
        check("the EVAL_TEST lesson is NOT returned",
              "outcome:cors:127.0.0.1" not in topics, str(topics))
        check("the EXAM_FIXTURE lesson is NOT returned",
              "outcome:cors:exam" not in topics, str(topics))
        check("the class list excludes the ineligible lessons",
              out.get("classes_with_verified_lessons") == ["cors"],
              str(out.get("classes_with_verified_lessons")))

    def test_p8_before_summary_ranks_only_eligible_lessons(self):
        print("\nP8  BEFORE_SUMMARY RANKS ONLY ELIGIBLE LESSONS")

        for origin, key in ((self.prov.EVAL_TEST, "k.sum.test"),
                            (self.prov.PRODUCTION_HUNT, "k.sum.prod")):
            self.con.execute(
                "INSERT INTO lesson(lesson_key, topic, body, class_id, score,"
                " state, provenance, origin, evidence, created_at, updated_at)"
                " VALUES (?,'t','b','cors',?, 'verified','{}',?,'e',?,?)",
                (key, 0.95 if origin == self.prov.EVAL_TEST else 0.2,
                 origin, "2026-11-01T00:00:00", "2026-11-01T00:00:00"))
        self.con.commit()

        out = self.le.before_summary(self.con, [
            {"finding_key": "f.a", "class_id": "cors"},
            {"finding_key": "f.b", "class_id": "cors"}])
        for r in out.get("ranked", []):
            check(f"{r['finding_key']} is ranked by the PRODUCTION lesson "
                  f"only (count=1, score=0.2)",
                  r.get("prior_lessons") == 1
                  and abs(float(r.get("learned_exploitability", 0)) - 0.2) < 1e-6,
                  str(r))

    def test_p9_prior_for_signal_counts_only_eligible_lessons(self):
        print("\nP9  PRIOR_FOR_SIGNAL COUNTS ONLY ELIGIBLE LESSONS")

        self.con.execute(
            "INSERT INTO lesson(lesson_key, topic, body, class_id, score,"
            " state, provenance, origin, evidence, created_at, updated_at)"
            " VALUES ('k.sig.test','t','cors signal body','cors',0.9,"
            " 'verified','{}',?,'e',?,?)",
            (self.prov.EVAL_TEST, "2026-11-01T00:00:00",
             "2026-11-01T00:00:00"))
        self.con.commit()
        n, avg = self.le._prior_for_signal(self.con, "cors")
        check("the EVAL_TEST lesson contributes no prior",
              n == 0, f"n={n} avg={avg}")

    # ------------------------------------------------------------------
    # P10: THE IMPACT CALCULATIONS IGNORE TEST OUTPUT
    # ------------------------------------------------------------------
    def test_p10_impact_counts_ignore_test_findings(self):
        print("\nP10  IMPACT COUNTS IGNORE TEST FINDINGS")

        self._add_finding("f.t1", self.prov.EVAL_TEST)
        self._add_finding("f.t2", self.prov.EXAM_FIXTURE)
        self._add_finding("f.p1", self.prov.PRODUCTION_HUNT)

        check("production impact counts only the production finding",
              self.store.production_impact_count(self.con) == 1,
              str(self.store.production_impact_count(self.con)))
        check("unvalidated production counts only the production finding",
              self.store.unvalidated_production_count(self.con) == 1,
              str(self.store.unvalidated_production_count(self.con)))
        check("the raw status query WOULD have counted all three",
              self.con.execute(
                  "SELECT count(*) n FROM finding WHERE status IN"
                  " ('candidate','validating')").fetchone()["n"] == 3)

    def test_p11_the_scheduler_stop_condition_ignores_test_findings(self):
        print("\nP11  THE SCHEDULER STOP CONDITION IGNORES TEST FINDINGS")

        from orch import scheduler as sched_mod
        from orch import dag as dag_mod

        # A candidate finding with TEST provenance is exactly what
        # contaminated the live corpus.
        self._add_finding("f.sched.test", self.prov.EVAL_TEST)
        self._add_finding("f.sched.exam", self.prov.EXAM_FIXTURE)

        # The scheduler's own stop condition, run against live state.
        # `has_useful_work` calls `dag.refresh_readiness` and
        # `priority.weakest_classes`, so the scratch database needs the
        # task/event tables the base schema provides -- it does.
        result = sched_mod.has_useful_work(self.con)
        check("the scheduler reports no unvalidated findings",
              result.get("unvalidated_findings") == 0,
              str(result))
        check("the scheduler does not treat test findings as unvalidated "
              "work",
              result.get("unvalidated_findings") != 2,
              str(result))

        # And the production finding DOES count.
        self._add_finding("f.sched.prod", self.prov.PRODUCTION_HUNT)
        result2 = sched_mod.has_useful_work(self.con)
        check("the scheduler counts the production finding",
              result2.get("unvalidated_findings") == 1,
              str(result2))

    # ------------------------------------------------------------------
    # P12: THE VOCABULARY IS ONE VOCABULARY
    #
    # The learning engine must not import the orchestrator -- they are two
    # owners of one database. So the vocabulary is deliberately duplicated
    # there, and this test asserts the two copies AGREE. If they drift,
    # one of them silently accepts an origin the other refuses.
    # ------------------------------------------------------------------
    def test_p12_the_two_vocabulary_copies_agree(self):
        print("\nP12  THE TWO VOCABULARY COPIES AGREE")

        for value in list(self.prov.ALL_PROVENANCE) + ["", "nonsense", None]:
            a = self.prov.normalise(value)
            b = self.le._normalise_origin(value)
            check(f"both copies normalise {value!r} to {a}",
                  a == b, f"provenance={a} engine={b}")

        # The engine's eligible set must match the provenance module's.
        engine_eligible = set(self.le._ELIGIBLE_ORIGINS)
        prov_eligible = {p for p in self.prov.ALL_PROVENANCE
                         if self.prov.eligible_as_lesson(p)}
        check("the engine's eligible origins match the orchestrator's",
              engine_eligible == prov_eligible,
              f"engine={sorted(engine_eligible)} "
              f"orch={sorted(prov_eligible)}")

    def test_p13_the_sql_clauses_use_the_right_column(self):
        print("\nP13  THE SQL CLAUSES USE THE RIGHT COLUMN")

        # `lesson.provenance` is the JSON descriptor. Comparing it with
        # a vocabulary word never matches, so a clause built on it
        # silently selected NOTHING.
        self.con.execute(
            "INSERT INTO lesson(lesson_key, topic, body, class_id, score,"
            " state, provenance, origin, evidence, created_at, updated_at)"
            " VALUES ('k.clause','t','b','cors',0.5,'verified','{}',?, 'e',?,?)",
            (self.prov.PRODUCTION_HUNT, "2026-11-01T00:00:00",
             "2026-11-01T00:00:00"))
        self.con.commit()
        n = self.con.execute(
            f"SELECT count(*) n FROM lesson WHERE"
            f" {self.prov.trusted_lesson_clause()}").fetchone()["n"]
        check("the trusted-lesson clause selects the production lesson",
              n == 1, f"n={n}")
        n2 = self.con.execute(
            f"SELECT count(*) n FROM lesson WHERE"
            f" {self.prov.promotable_clause()}").fetchone()["n"]
        check("the promotable clause selects the production lesson",
              n2 == 1, f"n={n2}")


if __name__ == "__main__":
    print(f"\n{'=' * 70}")
    print(f"PROVENANCE: {PASS} passed, {FAIL} failed")
    for f in _CURRENT:
        print(f"  FAILED: {f}")
    print(f"{'=' * 70}")
    unittest.main(verbosity=2, exit=False)
    sys.exit(1 if FAIL else 0)
