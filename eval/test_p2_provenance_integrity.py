"""THE ORIGIN OF A RECORD CANNOT BE SELF-DECLARED, AND CANNOT BE EDITED.

MEASURED 2026-11-02: the provenance column was derived from the context
that created a record and then ASSERTED. `classify_from_context` returned
PRODUCTION_HUNT for any hunt that had an id and a routable target, so a
caller that merely held a hunt id could claim production hunting impact
-- and nothing in the system recorded that the hunt was authorized at
all. The origin was the system making a claim about itself.

Three defects followed from that, and this file pins the closure of each:

  1. SELF-DECLARATION. `add_finding(provenance="PRODUCTION_HUNT")` and
     `capture_hook(origin="PRODUCTION_HUNT")` accepted the word. A
     production origin now requires a PERSISTED AUTHORIZATION RECEIPT --
     a validated `hunt_authorization` row naming the hunt and the target.
     The claim is downgraded to UNKNOWN without it, and the downgrade is
     reported rather than silent.

  2. DERIVATION WITHOUT PROOF. `classify_from_context` granted
     PRODUCTION_HUNT from a routable target alone. It now requires the
     receipt, and the receipt is consulted BEFORE the reserved-name
     heuristic, because a receipt names the target it covers while a
     reserved name is only a guess.

  3. UNAUDITED MUTATION. `set_provenance` was the sanctioned correction
     path, but nothing stopped a raw `UPDATE finding SET
     provenance='PRODUCTION_HUNT'`. The audit trail described the changes
     that went through the function; it did not prevent the ones that did
     not. The origin column is now guarded by a DATABASE TRIGGER: SQLite
     itself refuses the change unless a matching `provenance_correction`
     audit row exists.

Every check has a matching negative control, because a check that cannot
go red certifies nothing. It runs against a disposable scratch database,
so it never touches the canonical corpus.
"""
from __future__ import annotations

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
        print(f"  [FAIL] {label}" + (f"  ({detail})" if f"  ({detail})" else ""))


class ProvenanceIntegrityTests(unittest.TestCase):
    def setUp(self):
        _CURRENT.clear()
        self.tmp = tempfile.mkdtemp(prefix="prov_integrity_")
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
        from orch import authz as authz_mod
        from orch import learning_bridge as bridge_mod
        self.store = orch_store
        self.authz = authz_mod
        self.bridge = bridge_mod
        self.prov = __import__("orch.provenance", fromlist=["provenance"])

    def tearDown(self):
        self.con.close()
        if _CURRENT:
            self.fail("rule violations:\n  - " + "\n  - ".join(_CURRENT))

    # -- helpers ------------------------------------------------------
    def _production_context(self, *, target: str = "app.acme.test",
                            hunt_id: str = "integrity.hunt"):
        """A context whose authorization can be validated and recorded."""
        return self.authz.AuthorizationContext(
            program="integrity-program", target=target,
            in_scope_assets=[target],
            reporting_requirements={"format": "md"},
            authorization_ref="INTEGRITY-SCOPE", kind="bugbounty",
            allowed_actions=["recon", "probe"]), hunt_id

    def _receipt(self, *, target: str = "app.acme.test",
                 hunt_id: str = "integrity.hunt"):
        ctx, hid = self._production_context(target=target, hunt_id=hunt_id)
        verdict = ctx.validate_and_record(self.con, hunt_id=hid)
        return ctx, hid, verdict

    # ------------------------------------------------------------------
    # I1: A FINDING CANNOT ASSERT ITS OWN PRODUCTION ORIGIN
    # ------------------------------------------------------------------
    def test_i1_a_finding_cannot_assert_production_without_a_receipt(self):
        print("\nI1  A FINDING CANNOT ASSERT PRODUCTION WITHOUT A RECEIPT")
        self.store.add_finding(
            self.con, "f.asserted", "asserted production", target="app.acme.test",
            class_id="sqli", severity="high",
            provenance=self.prov.PRODUCTION_HUNT)
        origin = self.prov.provenance_of(self.con, "finding", "f.asserted")
        check("an asserted PRODUCTION_HUNT with no receipt is REFUSED",
              origin == self.prov.UNKNOWN, origin)
        check("a refused finding contributes ZERO impact",
              self.prov.production_impact_count(self.con) == 0,
              str(self.prov.production_impact_count(self.con)))

        # THE POSITIVE CONTROL: the same finding, with a receipt.
        ctx, hid, verdict = self._receipt()
        check("the receipt is validated", verdict.get("validated") is True,
              str(verdict)[:160])
        self.store.add_finding(
            self.con, "f.receipted", "receipt-backed production",
            target="app.acme.test", class_id="sqli", severity="high",
            hunt_id=hid)
        origin = self.prov.provenance_of(self.con, "finding", "f.receipted")
        check("the same finding WITH a receipt is PRODUCTION_HUNT",
              origin == self.prov.PRODUCTION_HUNT, origin)
        check("and it contributes impact",
              self.prov.production_impact_count(self.con) == 1,
              str(self.prov.production_impact_count(self.con)))

    # ------------------------------------------------------------------
    # I2: A LESSON CANNOT ASSERT ITS OWN PRODUCTION ORIGIN
    # ------------------------------------------------------------------
    def test_i2_a_lesson_cannot_assert_production_without_a_receipt(self):
        print("\nI2  A LESSON CANNOT ASSERT PRODUCTION WITHOUT A RECEIPT")
        r = self.le.capture_hook(
            self.con, topic="asserted lesson", body="claims production",
            class_id="sqli", origin=self.prov.PRODUCTION_HUNT)
        check("the capture is refused as production",
              r.get("origin") == self.prov.UNKNOWN, str(r))
        check("the downgrade is REPORTED, not silent",
              r.get("origin_downgraded") is True, str(r))
        # The lesson IS still recorded -- nothing is deleted -- but it is
        # recorded as what it is: an UNKNOWN claim, which can never become
        # hunting experience.
        origin = self.con.execute(
            "SELECT origin FROM lesson WHERE lesson_key=?",
            (r.get("lesson_key"),)).fetchone()["origin"]
        check("the lesson is recorded, but as UNKNOWN",
              origin == self.prov.UNKNOWN, origin)

        # THE POSITIVE CONTROL: the receipt makes the claim true.
        ctx, hid, _v = self._receipt()
        r2 = self.le.capture_hook(
            self.con, topic="receipted lesson", body="backed by a receipt",
            class_id="sqli", origin=self.prov.PRODUCTION_HUNT,
            hunt_id=hid, authorization_ref="INTEGRITY-SCOPE")
        check("the receipt-backed capture is PRODUCTION_HUNT",
              r2.get("origin") == self.prov.PRODUCTION_HUNT, str(r2))
        check("and it is NOT downgraded",
              r2.get("origin_downgraded") is False, str(r2))

    # ------------------------------------------------------------------
    # I3: A RECEIPT FOR A DIFFERENT TARGET DOES NOT BACK THE RECORD
    # ------------------------------------------------------------------
    def test_i3_a_receipt_for_another_target_does_not_back_the_record(self):
        print("\nI3  A RECEIPT FOR ANOTHER TARGET DOES NOT BACK THE RECORD")
        _ctx, hid, _v = self._receipt(target="app.acme.test")
        self.store.add_finding(
            self.con, "f.othertarget", "wrong target",
            target="other.acme.test", class_id="sqli", severity="high",
            hunt_id=hid)
        origin = self.prov.provenance_of(self.con, "finding", "f.othertarget")
        check("a receipt covering another target does NOT back this finding",
              origin != self.prov.PRODUCTION_HUNT, origin)

    # ------------------------------------------------------------------
    # I4: THE ORIGIN CANNOT BE CHANGED BY A RAW UPDATE
    # ------------------------------------------------------------------
    def test_i4_a_raw_update_cannot_change_the_origin(self):
        print("\nI4  A RAW UPDATE CANNOT CHANGE THE ORIGIN")
        _ctx, hid, _v = self._receipt()
        self.store.add_finding(
            self.con, "f.guard", "guarded", target="app.acme.test",
            class_id="sqli", severity="high", hunt_id=hid)
        before = self.prov.provenance_of(self.con, "finding", "f.guard")
        try:
            self.con.execute(
                "UPDATE finding SET provenance='EVAL_TEST'"
                " WHERE finding_key='f.guard'")
            self.con.commit()
            check("the raw UPDATE is REFUSED by the database", False,
                  "the UPDATE succeeded -- the trigger is not installed")
        except sqlite3.Error as exc:
            check("the raw UPDATE is REFUSED by the database", True, str(exc))
        self.con.rollback()
        after = self.prov.provenance_of(self.con, "finding", "f.guard")
        check("the origin is unchanged after the refused UPDATE",
              before == after, f"{before} -> {after}")

        # AND THE SAME FOR A LESSON.
        self.le.capture_hook(self.con, topic="guarded lesson",
                             body="b", class_id="sqli",
                             origin=self.prov.EVAL_TEST)
        lkey = self.con.execute(
            "SELECT lesson_key FROM lesson WHERE topic='guarded lesson'"
        ).fetchone()["lesson_key"]
        try:
            with __import__("wks.ownership", fromlist=["ownership"]).owner_write(
                    self.con, __import__(
                        "wks.ownership", fromlist=["ownership"]).WKS):
                self.con.execute(
                    "UPDATE lesson SET origin='PRODUCTION_HUNT'"
                    " WHERE lesson_key=?", (lkey,))
                self.con.commit()
            check("the raw lesson UPDATE is REFUSED by the database", False,
                  "the UPDATE succeeded -- the trigger is not installed")
        except sqlite3.Error as exc:
            check("the raw lesson UPDATE is REFUSED by the database", True,
                  str(exc))
        self.con.rollback()

    # ------------------------------------------------------------------
    # I5: THE SANCTIONED CORRECTION PATH STILL WORKS, AND IS AUDITED
    # ------------------------------------------------------------------
    def test_i5_the_correction_path_works_and_is_audited(self):
        print("\nI5  THE CORRECTION PATH WORKS AND IS AUDITED")
        _ctx, hid, _v = self._receipt()
        self.store.add_finding(
            self.con, "f.correct", "correctable", target="app.acme.test",
            class_id="sqli", severity="high", hunt_id=hid)
        ok = self.prov.set_provenance(
            self.con, "finding", "f.correct", self.prov.EVAL_TEST,
            reason="reclassified after review", corrected_by="integrity.test")
        check("the correction succeeds", ok is True, str(ok))
        origin = self.prov.provenance_of(self.con, "finding", "f.correct")
        check("the origin is now the corrected value",
              origin == self.prov.EVAL_TEST, origin)
        trail = self.prov.corrections(self.con, "finding", "f.correct")
        check("the correction is AUDITED", len(trail) == 1, str(len(trail)))
        if trail:
            row = trail[0]
            check("the audit names the old value",
                  row["old_provenance"] == self.prov.PRODUCTION_HUNT,
                  row["old_provenance"])
            check("the audit names the new value",
                  row["new_provenance"] == self.prov.EVAL_TEST,
                  row["new_provenance"])
            check("the audit names the reason",
                  "review" in (row["reason"] or ""), row["reason"])
            check("the audit names the corrector",
                  row["corrected_by"] == "integrity.test", row["corrected_by"])

        # A CORRECTION WITH NO REASON IS REFUSED: an origin change that
        # names no reason cannot be audited.
        try:
            self.prov.set_provenance(
                self.con, "finding", "f.correct", self.prov.PRODUCTION_HUNT,
                reason="   ", corrected_by="integrity.test")
            check("a correction with no reason is REFUSED", False,
                  "the correction succeeded")
        except ValueError as exc:
            check("a correction with no reason is REFUSED", True, str(exc))

    # ------------------------------------------------------------------
    # I6: A PROMOTION STILL NEEDS THE RECEIPT
    # ------------------------------------------------------------------
    def test_i6_a_promotion_through_the_correction_path_needs_a_receipt(self):
        print("\nI6  A PROMOTION THROUGH THE CORRECTION PATH NEEDS A RECEIPT")
        # A ROUTABLE TARGET, so the reserved-name heuristic cannot be the
        # thing under test: only the receipt is.
        self.store.add_finding(
            self.con, "f.promote", "to promote", target="app.acme.io",
            class_id="sqli", severity="high")
        origin = self.prov.provenance_of(self.con, "finding", "f.promote")
        check("the finding starts UNKNOWN", origin == self.prov.UNKNOWN, origin)
        try:
            self.prov.set_provenance(
                self.con, "finding", "f.promote", self.prov.PRODUCTION_HUNT,
                reason="attempted promotion", corrected_by="integrity.test")
            check("the promotion is REFUSED without a receipt", False,
                  "the promotion succeeded")
        except ValueError as exc:
            check("the promotion is REFUSED without a receipt", True, str(exc))
        after = self.prov.provenance_of(self.con, "finding", "f.promote")
        check("the origin is unchanged after the refused promotion",
              after == self.prov.UNKNOWN, after)

    # ------------------------------------------------------------------
    # I7: A HUNT WITH NO RECEIPT PRODUCES NO IMPACT, EVERYWHERE
    # ------------------------------------------------------------------
    def test_i7_every_consumer_excludes_an_unbacked_origin(self):
        print("\nI7  EVERY CONSUMER EXCLUDES AN UNBACKED ORIGIN")
        # A finding that CLAIMS production, with no receipt.
        self.store.add_finding(
            self.con, "f.unbacked", "unbacked", target="app.acme.test",
            class_id="sqli", severity="high",
            provenance=self.prov.PRODUCTION_HUNT)
        check("the scheduler counts ZERO unvalidated production work",
              self.prov.unvalidated_production_count(self.con) == 0,
              str(self.prov.unvalidated_production_count(self.con)))
        check("the hunt value counts ZERO production impact",
              self.prov.production_impact_count(self.con) == 0,
              str(self.prov.production_impact_count(self.con)))

        # A lesson that CLAIMS production, with no receipt.
        r = self.le.capture_hook(
            self.con, topic="unbacked lesson", body="b", class_id="sqli",
            origin=self.prov.PRODUCTION_HUNT)
        lkey = r.get("lesson_key")
        # Force it to `verified` so ONLY the origin can exclude it. If the
        # trusted query were checking only the state, this lesson would be
        # returned -- which is exactly the defect being closed.
        from wks import ownership as _own
        with _own.owner_write(self.con, _own.WKS):
            self.con.execute(
                "UPDATE lesson SET state='verified' WHERE lesson_key=?",
                (lkey,))
            self.con.commit()
        trusted = self.prov.trusted_lessons(self.con)
        check("an unbacked lesson is NOT returned as intelligence",
              all(x["lesson_key"] != lkey for x in trusted),
              str([x["lesson_key"] for x in trusted]))
        check("the trusted lesson set is EMPTY",
              len(trusted) == 0, str(len(trusted)))


    # ------------------------------------------------------------------
    # I8: THE SCHEMA IS SAFE ON AN EMPTY, LEGACY, AND PARTIALLY-MIGRATED
    #     DATABASE
    # ------------------------------------------------------------------
    def test_i8_the_schema_is_safe_on_every_database_state(self):
        print("\nI8  THE SCHEMA IS SAFE ON EVERY DATABASE STATE")

        from orch import store as orch_store
        from wks import config as wks_config

        # --- AN EMPTY DATABASE -------------------------------------
        fresh = Path(self.tmp) / "fresh.db"
        original = wks_config.db_path
        original_store = orch_store.db_path
        try:
            wks_config.db_path = lambda: fresh
            orch_store.db_path = lambda: fresh
            con = orch_store.open_db(create=True)
            self.le.ensure_schema(con)
            triggers = {r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger'")}
            check("a fresh database installs the finding guard",
                  "trg_finding_origin_immutable" in triggers,
                  str(sorted(triggers)))
            check("a fresh database installs the lesson guard",
                  "trg_lesson_origin_immutable" in triggers,
                  str(sorted(triggers)))
            con.close()
        finally:
            wks_config.db_path = original
            orch_store.db_path = original_store

        # --- A LEGACY DATABASE -------------------------------------
        # `finding` without `provenance`, `lesson` without `origin` and
        # without `class_id` -- the shape a pre-taxonomy database has.
        legacy = Path(self.tmp) / "legacy.db"
        con = sqlite3.connect(str(legacy))
        con.row_factory = sqlite3.Row
        con.execute(
            "CREATE TABLE finding (id INTEGER PRIMARY KEY, finding_key TEXT,"
            " title TEXT, target TEXT, asset TEXT, endpoint TEXT,"
            " class_id TEXT, hypothesis TEXT, severity TEXT, status TEXT,"
            " validation_json TEXT, dedup_group TEXT, canonical_id INTEGER,"
            " validator_run TEXT, report_path TEXT, created_at TEXT,"
            " updated_at TEXT)")
        con.execute(
            "INSERT INTO finding(finding_key,title,status,created_at,"
            "updated_at) VALUES ('legacy.1','old','candidate','x','x')")
        con.execute(
            "CREATE TABLE lesson (lesson_key TEXT PRIMARY KEY, topic TEXT,"
            " body TEXT, score REAL, state TEXT, provenance TEXT,"
            " evidence TEXT, created_at TEXT, updated_at TEXT)")
        con.execute(
            "INSERT INTO lesson(lesson_key,topic,body,score,state,provenance,"
            "evidence,created_at,updated_at)"
            " VALUES ('legacy.l','t','b',0.5,'captured','{}',NULL,'x','x')")
        con.commit()
        con.close()
        try:
            wks_config.db_path = lambda: legacy
            orch_store.db_path = lambda: legacy
            con = orch_store.open_db(create=True)
            self.le.ensure_schema(con)
            fcols = {r["name"] for r in con.execute(
                "PRAGMA table_info(finding)")}
            lcols = {r["name"] for r in con.execute(
                "PRAGMA table_info(lesson)")}
            check("the legacy finding gained `provenance`",
                  "provenance" in fcols, str(sorted(fcols)))
            check("the legacy lesson gained `origin`",
                  "origin" in lcols, str(sorted(lcols)))
            check("the legacy lesson gained `class_id`",
                  "class_id" in lcols, str(sorted(lcols)))
            check("the legacy records are PRESERVED, not deleted",
                  con.execute("SELECT count(*) n FROM finding"
                              ).fetchone()["n"] == 1
                  and con.execute("SELECT count(*) n FROM lesson"
                                  ).fetchone()["n"] == 1)
            check("the legacy finding defaults to UNKNOWN",
                  self.prov.provenance_of(con, "finding", "legacy.1")
                  == self.prov.UNKNOWN)
            check("the legacy lesson defaults to UNKNOWN",
                  self.prov.provenance_of(con, "lesson", "legacy.l",
                                          "lesson_key")
                  == self.prov.UNKNOWN)
            # THE GUARD IS LIVE ON THE MIGRATED DATABASE.
            try:
                con.execute("UPDATE finding SET provenance='PRODUCTION_HUNT'"
                            " WHERE finding_key='legacy.1'")
                con.commit()
                check("the guard is live on the migrated database", False,
                      "the raw UPDATE succeeded")
            except sqlite3.Error as exc:
                check("the guard is live on the migrated database", True,
                      str(exc))
            con.close()
        finally:
            wks_config.db_path = original
            orch_store.db_path = original_store

        # --- A PARTIALLY-MIGRATED DATABASE -------------------------
        # `finding` HAS `provenance` (and carries an UNBACKED
        # PRODUCTION_HUNT claim), `lesson` has no `origin`.
        partial = Path(self.tmp) / "partial.db"
        con = sqlite3.connect(str(partial))
        con.row_factory = sqlite3.Row
        con.execute(
            "CREATE TABLE finding (id INTEGER PRIMARY KEY, finding_key TEXT,"
            " title TEXT, target TEXT, asset TEXT, endpoint TEXT,"
            " class_id TEXT, hypothesis TEXT, severity TEXT, status TEXT,"
            " validation_json TEXT, dedup_group TEXT, canonical_id INTEGER,"
            " validator_run TEXT, report_path TEXT, hunt_id TEXT,"
            " provenance TEXT, created_at TEXT, updated_at TEXT)")
        con.execute(
            "INSERT INTO finding(finding_key,title,status,provenance,"
            "created_at,updated_at)"
            " VALUES ('pm.1','old','candidate','PRODUCTION_HUNT','x','x')")
        con.execute(
            "CREATE TABLE lesson (lesson_key TEXT PRIMARY KEY, topic TEXT,"
            " body TEXT, score REAL, state TEXT, provenance TEXT,"
            " evidence TEXT, created_at TEXT, updated_at TEXT)")
        con.commit()
        con.close()
        try:
            wks_config.db_path = lambda: partial
            orch_store.db_path = lambda: partial
            con = orch_store.open_db(create=True)
            self.le.ensure_schema(con)
            from orch import finalgate
            row = con.execute(
                "SELECT * FROM finding WHERE finding_key='pm.1'").fetchone()
            ok, detail = finalgate._origin_ok(con, row)
            check("a PRE-EXISTING unbacked production claim is REFUSED "
                  "by the gate", ok is False, str(detail)[:120])
            check("the correction table is created on a migrated database",
                  bool(con.execute(
                      "SELECT name FROM sqlite_master WHERE type='table'"
                      " AND name='provenance_correction'").fetchone()))
            con.close()
        finally:
            wks_config.db_path = original
            orch_store.db_path = original_store


if __name__ == "__main__":
    unittest.main(verbosity=2)
