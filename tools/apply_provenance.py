#!/usr/bin/env python3
"""APPLY the audited provenance to the live canonical database.

`tools/reconcile_incident_records.py` produces the DISPOSITION MANIFEST:
what every affected record is, and why. This tool applies the result --
it writes each record's `provenance` / `origin` so that the system's
queries can enforce eligibility structurally rather than by inspection.

THE TWO TOOLS ARE SEPARATE ON PURPOSE
=====================================
The reconciliation tool READS the pre-quarantine backup and produces a
manifest. It changes nothing. This tool READS that manifest and WRITES
the provenance. A tool that both decided and applied would make the
decision unauditable: there would be no artifact to check the decision
against.

REVERSIBLE
==========
Every write is recorded. The previous value of every row is captured in
the run's report, so a reviewer can restore exactly what was there
before. Nothing is deleted; the records' CONTENT, TIMESTAMPS, IDS and
TRANSITION HISTORY are untouched -- only the new column is set.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from orch import provenance as prov  # noqa: E402


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Apply audited provenance to the canonical database.")
    ap.add_argument("--manifest", required=True,
                    help="the disposition manifest to apply")
    ap.add_argument("--db", default=None,
                    help="the database to write (default: canonical)")
    ap.add_argument("--dry-run", action="store_true",
                    help="report what would change and write nothing")
    args = ap.parse_args()

    manifest_path = pathlib.Path(args.manifest)
    if not manifest_path.exists():
        print(f"no such manifest: {manifest_path}", file=sys.stderr)
        return 2
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    if args.db:
        db = pathlib.Path(args.db)
    else:
        from wks import config as wks_config
        db = wks_config.db_path()

    import sqlite3
    # OPEN THROUGH THE STORE, so the migrations run.
    #
    # MEASURED 2026-11-01: this connected with raw sqlite3, so the
    # `finding.provenance` and `lesson.origin` columns did not exist and
    # the tool failed on its first SELECT. The schema is owned by
    # `orch.store.open_db`, which applies the idempotent migrations; a
    # tool that writes to this database must go through the owner, not
    # around it.
    #
    # `open_db` takes no path: the database is a configured singleton.
    # `--db` therefore only accepts the configured path -- pointing the
    # tool at an arbitrary file would write to a database whose schema
    # and migrations were never applied.
    from orch import store as orch_store
    canonical = orch_store.db_path()
    if args.db and pathlib.Path(args.db).resolve() != canonical.resolve():
        print(f"--db must be the canonical database: {canonical}",
              file=sys.stderr)
        return 2
    con = orch_store.open_db(create=True)
    con.row_factory = sqlite3.Row

    # THE FUNCTIONAL DEPENDENCY: the reconciliation tool classified
    # against the PRE-QUARANTINE database, but the live database has
    # moved since (a further test leak was found and quarantined). So the
    # manifest is a starting point, and every record's provenance is
    # RE-DERIVED against the live row before it is written.
    #
    # A record the manifest does not mention is classified by the same
    # rules, applied to the live evidence.
    from tools.reconcile_incident_records import (  # noqa: E402
        _authorization_backed, build_source_index, classify_finding,
        finding_lineage, hunt_for_finding, source_names_key)

    hunt_ids = [r["hunt_id"] for r in con.execute(
        "SELECT hunt_id FROM hunt ORDER BY started_at")]
    source_index = build_source_index(ROOT)

    changes: list[dict] = []
    unchanged: list[dict] = []

    # ---- FINDINGS ----------------------------------------------------
    # The classification is computed FIRST and kept in memory, because a
    # lesson inherits the provenance of the finding it came from.
    #
    # MEASURED 2026-11-01: this tool re-read the finding's provenance from
    # the TABLE to classify its lessons. In a dry run nothing was written,
    # so the table still said UNKNOWN for every finding and every linked
    # lesson inherited UNKNOWN -- the dry run reported 14 lesson changes
    # when the true answer was 51. A dry run that does not predict the
    # real run is worse than no dry run: it is a false assurance.
    #
    # So the classification map is built from the computed values, and
    # the table is only ever read for what is already stored.
    finding_classification: dict[str, str] = {}
    for row in con.execute("SELECT * FROM finding ORDER BY id"):
        ev_prov, actors, _ev_rows, _tr_rows, _state_row = \
            finding_lineage(con, row)
        hunt = hunt_for_finding(con, row, hunt_ids)
        src_files = source_names_key(row["finding_key"], source_index)
        # THE RECEIPT IS CONSULTED BEFORE ANY WRITE.
        #
        # MEASURED 2026-11-02: this tool WROTE the classification into the
        # live database, and the classifier it called granted
        # PRODUCTION_HUNT on "routable target + no test actor" alone. So a
        # routable-looking host with no authorization anywhere could be
        # written into production as production impact.
        #
        # The receipt is consulted now, exactly as the runtime path does.
        # A hunt with no validated authorization is not a production hunt.
        backed, auth_reason = _authorization_backed(con, hunt, row)
        value, reason = classify_finding(
            row, hunt, ev_prov, actors, src_files,
            authorization_backed=backed,
            authorization_reason=auth_reason)
        value = prov.normalise(value)
        finding_classification[row["finding_key"]] = value
        current = row["provenance"] if "provenance" in row.keys() else None
        rec = {"table": "finding", "key": row["finding_key"],
               "current": current, "proposed": value, "reason": reason,
               "status": row["status"]}
        if current == value:
            unchanged.append(rec)
            continue
        changes.append(rec)
        if not args.dry_run:
            # THE CORRECTION PATH, NOT A BARE UPDATE.
            #
            # MEASURED 2026-11-02: the origin column is guarded by a
            # database trigger -- a raw UPDATE is refused by SQLite
            # itself unless a `provenance_correction` audit row exists.
            # This tool IS a correction, so it goes through
            # `set_provenance`, which writes the audit row and the UPDATE
            # in one transaction. The reason names the evidence the
            # reconciliation produced, so the audit trail says WHY.
            prov.set_provenance(
                con, "finding", row["finding_key"], value,
                reason=f"incident reconciliation: {reason}",
                corrected_by="tools/apply_provenance.py",
                evidence_ref=str(manifest_path))

    # ---- LESSONS -----------------------------------------------------
    # A lesson inherits the provenance of the finding it came from. A
    # standalone lesson (no finding link) is classified by its own
    # provenance and topic.
    finding_origin = finding_classification

    # THE LESSON WRITE GOES THROUGH THE KNOWLEDGE OWNER.
    #
    # MEASURED 2026-11-01: this wrote `UPDATE lesson SET origin=?`
    # directly and the runtime authorizer refused it with "not
    # authorized" -- the ownership boundary working exactly as designed
    # against a crossing that had never been sanctioned.
    #
    # `lesson` is a KNOWLEDGE table. The orchestrator may cause a lesson
    # to exist, but the knowledge owner decides how it is written. So the
    # write goes through `owner_write`, which lifts the restriction for
    # the duration and restores it afterwards: every other write on this
    # connection stays refused.
    #
    # The FINDING write above does NOT need this -- `finding` is an
    # orchestration table, and this connection owns it.
    from wks import ownership as _ownership
    lesson_rows = con.execute(
        "SELECT * FROM lesson ORDER BY lesson_key").fetchall()
    lesson_plan: list[tuple[str, str, str, str]] = []
    for row in lesson_rows:
        links = [r["finding_key"] for r in con.execute(
            "SELECT finding_key FROM finding_lesson WHERE lesson_key=?",
            (row["lesson_key"],))]
        if links:
            origins = {finding_origin.get(k, prov.UNKNOWN) for k in links}
            if origins == {prov.EXAM_FIXTURE}:
                value = prov.EXAM_FIXTURE
            elif origins <= {prov.EVAL_TEST}:
                value = prov.EVAL_TEST
            elif origins <= {prov.PRODUCTION_HUNT}:
                value = prov.PRODUCTION_HUNT
            elif prov.MANUAL_ENTRY in origins:
                value = prov.MANUAL_ENTRY
            else:
                value = prov.UNKNOWN
            reason = (f"inherited from finding(s) {links} with provenance "
                      f"{sorted(origins)}")
        else:
            # A standalone lesson. Its own provenance blob and topic are
            # the evidence.
            topic = row["topic"] or ""
            try:
                blob = json.loads(row["provenance"] or "{}")
            except (ValueError, TypeError):
                blob = {}
            if isinstance(blob, dict) and blob.get("migrated_from"):
                value = prov.EVAL_TEST
                reason = (f"migrated from the legacy store "
                          f"{blob['migrated_from']!r}")
            elif topic.startswith("probe topic"):
                value = prov.EVAL_TEST
                reason = f"topic {topic!r} is the learning-hooks probe"
            elif ":127.0.0.1" in topic:
                value = prov.EVAL_TEST
                reason = f"topic {topic!r} names the loopback host"
            else:
                value = prov.UNKNOWN
                reason = ("no finding link and no identifying provenance; "
                          "origin requires review")
        current = row["origin"] if "origin" in row.keys() else None
        rec = {"table": "lesson", "key": row["lesson_key"],
               "current": current, "proposed": value, "reason": reason,
               "state": row["state"]}
        if current == value:
            unchanged.append(rec)
            continue
        changes.append(rec)
        lesson_plan.append((row["lesson_key"], value, current, reason))

    if not args.dry_run and lesson_plan:
        with _ownership.owner_write(con, _ownership.WKS):
            for lesson_key, value, _current, reason in lesson_plan:
                # THE CORRECTION PATH, NOT A BARE UPDATE.
                #
                # The lesson's origin is guarded by the same trigger as the
                # finding's, and the reason names the evidence that
                # produced the classification.
                prov.set_provenance(
                    con, "lesson", lesson_key, value,
                    key_col="lesson_key",
                    reason=f"incident reconciliation: {reason}",
                    corrected_by="tools/apply_provenance.py",
                    evidence_ref=str(manifest_path))

    if not args.dry_run:
        con.commit()

    report = {
        "generated_at": _now(),
        "database": str(db),
        "manifest": str(manifest_path),
        "dry_run": bool(args.dry_run),
        "changed": len(changes),
        "unchanged": len(unchanged),
        "changes": changes,
    }
    out = ROOT / "runtime" / "state" / f"provenance-apply-{_stamp()}.json"
    out.write_text(json.dumps(report, indent=2, default=str),
                   encoding="utf-8")

    print(f"database: {db}")
    print(f"manifest: {manifest_path}")
    print(f"changed: {len(changes)}  unchanged: {len(unchanged)}")
    print(f"report:   {out}")
    if args.dry_run:
        print("\nDRY RUN -- nothing was written.")
    else:
        rep = prov.provenance_report(con)
        print("\nfindings by provenance:  ", rep["finding"]["by_provenance"])
        print("lessons by origin:       ", rep["lesson"]["by_provenance"])
        print("eligible for impact:     ",
              rep["finding"]["eligible_for_impact"], "finding(s)")
        print("never eligible:          ",
              rep["finding"]["never_eligible"], "finding(s)")
    con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
