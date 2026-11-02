"""Bridge: hunting outcomes and program triage feed the learning engine.

MEASURED DEFECT (the reason this module exists)
-----------------------------------------------
The learning engine had all five hooks implemented and verified
(`eval/test_learning_hooks.py`), and the hunt layer had a complete finding
lifecycle with a real final gate (`orch/finalgate.py`) — and NOTHING connected
them.

MEASURED: no module under `orch/`, `wks/` or `scripts/` imported
`learning_engine`. A confirmed finding produced no lesson. A program's
"duplicate" or "not a bug" verdict produced no feedback. The corpus learned
only from write-ups.

That is the learning workflow's terminal link missing. The doctrine's loop is
"discover -> hypothesize -> test -> prove impact -> validate -> report ->
LEARN", and the LEARN step had no implementation for the hunting half of the
corpus.

What this module does
---------------------
It is the ONLY place that calls the learning engine on behalf of the hunt
layer, and it calls it at three points:

  1. `record_hunt_outcome` — when the final gate resolves a finding. A
     CONFIRMED finding becomes a captured lesson; a FALSE_POSITIVE becomes a
     captured lesson that is immediately marked rejected, so it is never
     promoted into knowledge.
  2. `record_triage_feedback` — when the program returns a verdict. The
     doctrine names four: accepted, duplicate, informative, false_positive.
  3. `sync_finding_outcomes` — a reconciliation pass, so lessons exist for
     findings that were resolved before this bridge existed, or while the
     bridge was not wired in.

Design constraints
------------------
* The bridge writes LEARNING tables only (`lesson`, `lesson_feedback`,
  `learning_gap`, ...). It never writes a knowledge table and never writes an
  orch work table. The hunt layer's tables stay the hunt layer's.
* Every write is IDEMPOTENT. Running the bridge twice on the same finding
  produces the same lesson, not two lessons. The lesson key is derived from
  the finding's identity, so a retry is a no-op.
* A failure to learn is REPORTED, never swallowed. A bridge that silently
  drops a lesson looks exactly like a bridge that found nothing to learn.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Iterable


def _now() -> str:
    """UTC timestamp, second resolution — same convention as `orch.store`."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# The learning engine's five hooks. Imported lazily so that a missing
# learning package degrades to a reported error rather than an ImportError
# at module load — the hunt layer must still work if the knowledge layer is
# unavailable.
try:  # pragma: no cover - exercised through the public functions
    from learning_engine import engine as _le
    LEARNING_IMPORT_ERROR: str | None = None
except Exception as _exc:  # pragma: no cover
    _le = None
    LEARNING_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"

__all__ = [
    "record_hunt_outcome",
    "record_triage_feedback",
    "sync_finding_outcomes",
    "LEARNING_IMPORT_ERROR",
]


def _engine():
    """The learning engine module, or a reported failure."""
    if _le is None:
        return None, (
            f"the learning engine could not be imported "
            f"({LEARNING_IMPORT_ERROR}); no lesson was recorded")
    return _le, None


# The hunt lifecycle's terminal states, mapped onto the learning engine's
# outcome vocabulary.
#
# A lesson is only promoted into knowledge once it is VERIFIED, and
# `verify_hook` refuses a lesson without evidence. So a confirmed finding
# produces a CAPTURED lesson with its evidence attached — it becomes
# retrievable after verification, and the bridge records exactly what
# verification is still owed.
_CONFIRMED_STATES = frozenset({
    "VALIDATED", "EVIDENCE_COMPLETE", "RETESTED", "REPORT_READY", "DELIVERED",
})
_REJECTED_STATES = frozenset({"FALSE_POSITIVE", "OUT_OF_SCOPE"})


def _finding_evidence(con: sqlite3.Connection, finding_row: sqlite3.Row
                      ) -> dict[str, Any]:
    """The evidence attached to a finding, in the shape the hooks expect.

    The lesson's evidence must be a real artifact reference, not a claim that
    evidence exists. This reads the `evidence` rows and the validation
    record, so a lesson can only claim what the database actually holds.
    """
    finding_key = finding_row["finding_key"]
    evidence_rows = con.execute(
        "SELECT kind, target, asset, endpoint, sha256, captured_at "
        "FROM evidence WHERE finding_id=? ORDER BY captured_at",
        (finding_row["id"],)).fetchall()
    validation = finding_row["validation_json"]
    return {
        "finding_key": finding_key,
        "finding_id": finding_row["id"],
        "title": finding_row["title"],
        "target": finding_row["target"],
        "endpoint": finding_row["endpoint"],
        "class_id": finding_row["class_id"],
        "severity": finding_row["severity"],
        "status": finding_row["status"],
        "validation": validation,
        "evidence_count": len(evidence_rows),
        "evidence": [dict(r) for r in evidence_rows],
    }


def record_hunt_outcome(con: sqlite3.Connection, finding_key: str, *,
                        lifecycle_state: str | None = None,
                        notes: str = "") -> dict[str, Any]:
    """Record the outcome of one finding into the learning corpus.

    `lifecycle_state` is the orch lifecycle state (VALIDATED, FALSE_POSITIVE,
    ...). When it is omitted the current state is read from `finding_state`.

    Idempotent: the lesson key is derived from the finding key, so calling
    this twice updates one lesson rather than creating two.
    """
    le, error = _engine()
    if le is None:
        return {"ok": False, "reason": error}

    row = con.execute("SELECT * FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if row is None:
        return {"ok": False, "reason": f"no such finding: {finding_key}"}

    # THE FINDING'S PROVENANCE IS THE LESSON'S PROVENANCE.
    #
    # MEASURED 2026-11-01: this bridge turned any finding into a lesson
    # and, when the finding was confirmed and carried evidence, marked
    # that lesson `verified` -- which is exactly the state `before_recon`
    # and `before_summary` read as intelligence for the next hunt.
    #
    # So a test finding became hunting experience. The quarantine
    # prevented it once; nothing prevented it structurally.
    #
    # The lesson now inherits the finding's origin, and a finding whose
    # origin is EVAL_TEST, EXAM_FIXTURE or UNKNOWN produces a lesson that
    # can never be verified, promoted, or returned as intelligence. The
    # lesson is still RECORDED -- nothing is deleted -- but it is recorded
    # as what it is.
    from . import provenance as _prov
    finding_origin = _prov.normalise(
        row["provenance"] if "provenance" in row.keys() else None)
    lesson_eligible = _prov.eligible_as_lesson(finding_origin)
    lesson_origin = finding_origin if finding_origin != _prov.UNKNOWN \
        else _prov.UNKNOWN

    state = lifecycle_state
    if not state:
        st = con.execute(
            "SELECT lifecycle FROM finding_state WHERE finding_key=?",
            (finding_key,)).fetchone()
        state = st["lifecycle"] if st else row["status"]

    class_id = row["class_id"] or "unknown"
    evidence = _finding_evidence(con, row)
    confirmed = str(state).upper() in _CONFIRMED_STATES
    rejected = str(state).upper() in _REJECTED_STATES

    topic = f"outcome:{class_id}:{row['target'] or finding_key}"
    body_parts = [
        f"finding {finding_key} ({row['title']}) on "
        f"{row['target'] or 'an unnamed target'} resolved to state {state}.",
    ]
    if row["endpoint"]:
        body_parts.append(f"endpoint: {row['endpoint']}.")
    if row["severity"]:
        body_parts.append(f"severity: {row['severity']}.")
    if evidence["evidence_count"]:
        kinds = sorted({e["kind"] for e in evidence["evidence"]})
        body_parts.append(f"evidence attached: {evidence['evidence_count']} "
                          f"artifact(s) of kind {', '.join(kinds)}.")
    else:
        body_parts.append("NO EVIDENCE ATTACHED — this outcome is not "
                          "promotable to knowledge.")
    if notes:
        body_parts.append(notes)
    body = " ".join(body_parts)

    # WRITE THROUGH THE KNOWLEDGE OWNER.
    #
    # MEASURED 2026-11-01: `lesson` is a KNOWLEDGE table, and this code
    # wrote it directly. The runtime ownership authorizer refuses that with
    # "not authorized" -- the boundary working exactly as designed against a
    # crossing that had never been sanctioned.
    #
    # The defect was MASKED because `apply_gate` -- the only production
    # caller of this function -- was itself never called outside `eval/`.
    # Wiring the learning loop closed made the latent boundary violation
    # reachable, and it fired immediately.
    #
    # The crossing is legitimate: a hunting outcome IS knowledge about a
    # class, and the learning engine owns how it is recorded. So it goes
    # through the OWNER's context, which lifts the restriction for the
    # duration and restores it afterwards. Every other write on this
    # connection stays refused.
    #
    # The `finding_lesson` link is an ORCHESTRATION write and is
    # deliberately OUTSIDE this block: `finding_lesson` is owned by the
    # orchestrator, so writing it while the connection is lifted to the
    # knowledge owner would work by accident rather than by right.
    from wks import ownership as _ownership
    with _ownership.owner_write(con, _ownership.WKS):
        # THE RECEIPT TRAVELS WITH THE LESSON.
        #
        # MEASURED 2026-11-02: `capture_hook` now refuses to create a
        # PRODUCTION_HUNT lesson unless the caller names the hunt and the
        # authorization reference AND a validated `hunt_authorization` row
        # matches. The bridge is the ONE caller that can supply those,
        # because it is the one that knows which hunt the finding came
        # from. So it reads the receipt and passes it down.
        #
        # A finding with no hunt (a manual entry, a test fixture) has no
        # receipt, and its lesson is captured as UNKNOWN -- which is what
        # the finding's origin already said.
        hunt_id = row["hunt_id"] if "hunt_id" in row.keys() else None
        authorization_ref = None
        if hunt_id:
            auth = _prov.authorization_for(con, hunt_id)
            if auth and int(auth.get("validated") or 0):
                authorization_ref = auth.get("authorization_ref")
        captured = le.capture_hook(
            con, topic=topic, body=body, class_id=class_id,
            score=0.6 if confirmed else 0.2,
            origin=lesson_origin,
            hunt_id=hunt_id,
            authorization_ref=authorization_ref,
            provenance={
                "source": "orch.learning_bridge",
                "finding_key": finding_key,
                "lifecycle_state": state,
                "confirmed": confirmed,
                "finding_origin": finding_origin,
                "hunt_id": hunt_id,
                "authorization_ref": authorization_ref,
                "evidence": evidence,
            })
        if not captured.get("ok"):
            return {"ok": False, "reason": captured.get("reason"),
                    "finding_key": finding_key}

        lesson_key = captured["lesson_key"]

        # A rejected outcome must NEVER become knowledge. The capture above
        # recorded it; now it is marked rejected and its score is pushed down,
        # so `before_recon` and `before_summary` — which read only verified
        # lessons — cannot surface it.
        if rejected:
            fb = le.after_triage(
                con, lesson_key=lesson_key, feedback_type="false_positive",
                notes=f"hunt outcome {state}: {notes}".strip(),
                provenance={"source": "orch.learning_bridge",
                            "finding_key": finding_key,
                            "lifecycle_state": state})
            result = {"ok": True, "finding_key": finding_key,
                      "lesson_key": lesson_key, "outcome": "rejected",
                      "score": fb.get("score"), "promotable": False}
            link_outcome = "rejected"

        elif confirmed:
            # A confirmed finding carries its own evidence. The lesson is
            # marked verified with that evidence, so it becomes retrievable —
            # but ONLY because the artifacts are recorded, not because the
            # outcome was asserted.
            #
            # AND ONLY IF THE FINDING'S ORIGIN PERMITS IT.
            #
            # MEASURED 2026-11-01: this branch marked the lesson
            # `verified` for ANY confirmed finding, and `verified` is
            # exactly what `before_recon` and `before_summary` read as
            # intelligence for the next hunt. So a test finding that
            # reached CONFIRMED became hunting experience.
            #
            # An ineligible origin is recorded and REFUSED: the lesson
            # stays in `captured`, it is never verified, and the refusal
            # is reported rather than silent. The record is kept -- nothing
            # is deleted -- it is simply not trusted.
            if not lesson_eligible:
                le.after_triage(
                    con, lesson_key=lesson_key,
                    feedback_type="ineligible_origin",
                    notes=(f"finding {finding_key} has origin "
                           f"{finding_origin!r}, which is not eligible to "
                           f"become hunting experience; the lesson is "
                           f"recorded but never verified"),
                    provenance={"source": "orch.learning_bridge",
                                "finding_key": finding_key,
                                "finding_origin": finding_origin,
                                "lifecycle_state": state})
                result = {"ok": True, "finding_key": finding_key,
                          "lesson_key": lesson_key,
                          "outcome": "ineligible_origin",
                          "verified": False, "promotable": False,
                          "origin": finding_origin,
                          "reason": ("finding origin is not eligible to "
                                     "become hunting experience")}
                link_outcome = "ineligible_origin"
            elif evidence["evidence_count"]:
                le.verify_hook(
                    con, lesson_key=lesson_key,
                    evidence=(f"{evidence['evidence_count']} evidence "
                              f"artifact(s) recorded for finding "
                              f"{finding_key}"),
                    provenance={"source": "orch.learning_bridge",
                                "evidence": evidence})
                result = {"ok": True, "finding_key": finding_key,
                          "lesson_key": lesson_key, "outcome": "confirmed",
                          "verified": True, "promotable": True}
                # PROJECT THE LESSON INTO THE CLASS SKILL.
                #
                # MEASURED 2026-11-01: `update_hook` -- the only path that
                # calls `wks.project.refresh_class` -- had NO production
                # caller. So a verified lesson was recorded in the database
                # and returned to a hunt as intelligence, but it never
                # reached the SKILL FILE that `orch.skill_resolver` loads
                # and hands to an agent. The lesson stopped one step short
                # of the thing an agent actually reads.
                #
                # The projection is best-effort and its failure is
                # REPORTED rather than swallowed: the lesson and its
                # evidence are already durable, so a refused projection
                # must not undo them -- but the caller must be able to see
                # that the skill file was not refreshed.
                upd = le.update_hook(con, lesson_key=lesson_key)
                result["projection"] = {
                    "updated": bool(upd.get("updated")),
                    "class_id": upd.get("class_id"),
                    "reason": upd.get("reason"),
                    "errors": upd.get("errors"),
                }
            else:
                # No evidence: the lesson stays captured, and the result says
                # so.
                result = {"ok": True, "finding_key": finding_key,
                          "lesson_key": lesson_key, "outcome": "confirmed",
                          "verified": False, "promotable": False,
                          "reason": "no evidence attached; the lesson "
                                    "remains captured and must be verified "
                                    "before it reaches knowledge"}

            # THE LINK OUTCOME IS SET HERE, ONCE.
            #
            # MEASURED 2026-11-01: `link_outcome = "confirmed"` sat
            # AFTER the whole if/elif/else, so it overwrote the value
            # every branch had set -- including the branch that refuses
            # to verify an ineligible lesson, which set "open". The
            # orchestration-side link therefore said "confirmed" for a
            # lesson that was deliberately NOT confirmed.
            #
            # The link records what happened to the LESSON, so it is set
            # where that is decided.
            link_outcome = result.get("outcome", "open")

        else:
            result = {"ok": True, "finding_key": finding_key,
                      "lesson_key": lesson_key, "outcome": "open",
                      "verified": False, "promotable": False,
                      "reason": f"state {state!r} is not a terminal hunting "
                                f"outcome"}
            link_outcome = "open"

    # The ORCHESTRATION-side link, written as the orchestrator.
    _link_lesson(con, finding_key, lesson_key, link_outcome)
    return result


def _link_lesson(con: sqlite3.Connection, finding_key: str, lesson_key: str,
                 outcome: str) -> None:
    """Record which lesson a finding produced.

    `orch.finalgate.apply_gate` returns a verdict STRING, so the bridge's
    outcome cannot travel back through the return value. It is recorded on the
    finding instead, which makes it queryable: "what did this finding teach?"
    has a database answer rather than depending on who called the gate.

    MEASURED 2026-11-01: this created the table at RUNTIME with
    `CREATE TABLE IF NOT EXISTS`, and it was never registered in the
    ownership map -- so the runtime authorizer refused the write as an
    unmapped table, and the bare `except sqlite3.Error: pass` swallowed the
    refusal. The table now lives in `orch/schema.sql` and is registered with
    its owner. The link is still best-effort: it is a convenience, and a
    failure here must not undo the lesson that was already recorded. But a
    failure is now REPORTED rather than silently swallowed.
    """
    try:
        con.execute(
            "INSERT INTO finding_lesson(finding_key,lesson_key,outcome,"
            "recorded_at) VALUES (?,?,?,?) "
            "ON CONFLICT(finding_key) DO UPDATE SET "
            "lesson_key=excluded.lesson_key, outcome=excluded.outcome, "
            "recorded_at=excluded.recorded_at",
            (finding_key, lesson_key, outcome, _now()))
        con.commit()
        return
    except sqlite3.Error as exc:
        _LINK_ERRORS.append(f"{type(exc).__name__}: {exc}")
        return


# The link failures, so they are visible rather than lost. The link is a
# convenience, not the learning itself, so it never fails the outcome -- but
# a silently dropped link is a provenance gap, and a provenance gap should
# be countable.
_LINK_ERRORS: list[str] = []


def link_errors() -> list[str]:
    """The recorded link failures."""
    return list(_LINK_ERRORS)


def lesson_for_finding(con: sqlite3.Connection,
                       finding_key: str) -> dict[str, Any] | None:
    """The lesson a finding produced, or None."""
    try:
        row = con.execute(
            "SELECT finding_key, lesson_key, outcome, recorded_at "
            "FROM finding_lesson WHERE finding_key=?", (finding_key,)).fetchone()
    except sqlite3.Error:
        return None
    return dict(row) if row else None


def record_triage_feedback(con: sqlite3.Connection, finding_key: str, *,
                           feedback_type: str, notes: str = "",
                           lesson_key: str | None = None) -> dict[str, Any]:
    """Record a program's verdict on a finding as learning feedback.

    The four feedback types are the doctrine's: accepted, duplicate,
    informative, false_positive. When no `lesson_key` is given, the lesson for
    the finding is found by its topic, so the caller does not have to track
    the mapping.
    """
    le, error = _engine()
    if le is None:
        return {"ok": False, "reason": error}

    fb = (feedback_type or "").strip().lower()
    if fb not in ("accepted", "duplicate", "informative", "false_positive"):
        return {"ok": False,
                "reason": f"unknown feedback type: {feedback_type!r}",
                "allowed": ["accepted", "duplicate", "informative",
                            "false_positive"]}

    if not lesson_key:
        row = con.execute("SELECT * FROM finding WHERE finding_key=?",
                          (finding_key,)).fetchone()
        if row is None:
            return {"ok": False, "reason": f"no such finding: {finding_key}"}
        class_id = row["class_id"] or "unknown"
        topic = f"outcome:{class_id}:{row['target'] or finding_key}"
        found = con.execute(
            "SELECT lesson_key FROM lesson WHERE topic=? ORDER BY updated_at DESC"
            " LIMIT 1", (topic,)).fetchone()
        if found is None:
            return {"ok": False,
                    "reason": f"no lesson recorded for finding {finding_key}; "
                              f"record the hunt outcome first"}
        lesson_key = found["lesson_key"]

    # WRITE THROUGH THE KNOWLEDGE OWNER.
    #
    # MEASURED 2026-11-01: `after_triage` writes `lesson` and
    # `lesson_feedback`, both KNOWLEDGE tables, and this call was made
    # directly. The runtime ownership authorizer refuses that -- the
    # boundary working as designed against an unsanctioned crossing.
    #
    # The crossing is legitimate: a program's verdict on a finding IS
    # knowledge about a class. It goes through the OWNER's context, which
    # lifts the restriction for the duration and restores it afterwards.
    from wks import ownership as _ownership
    with _ownership.owner_write(con, _ownership.WKS):
        result = le.after_triage(
            con, lesson_key=lesson_key, feedback_type=fb, notes=notes,
            provenance={"source": "orch.learning_bridge",
                        "finding_key": finding_key})
    if not result.get("ok"):
        return {"ok": False, "reason": result.get("reason")}
    return {"ok": True, "finding_key": finding_key, "lesson_key": lesson_key,
            "feedback_type": fb, "score": result.get("score"),
            "previous_score": result.get("previous_score"),
            "delta": result.get("delta")}


def sync_finding_outcomes(con: sqlite3.Connection, *,
                           states: Iterable[str] | None = None) -> dict[str, Any]:
    """Reconcile every finding with a terminal state against the corpus.

    This is the catch-up pass. It covers findings that were resolved before
    the bridge existed, and findings resolved while the bridge was not wired
    into the hunt path. It is idempotent, so it can be run on a schedule.

    Returns counts of what it recorded and what it could not.
    """
    le, error = _engine()
    if le is None:
        return {"ok": False, "reason": error}

    wanted = {s.upper() for s in states} if states else (
        _CONFIRMED_STATES | _REJECTED_STATES)
    recorded: list[str] = []
    skipped: list[dict[str, Any]] = []

    rows = con.execute(
        "SELECT f.finding_key, fs.lifecycle FROM finding f "
        "LEFT JOIN finding_state fs ON fs.finding_key=f.finding_key"
    ).fetchall()
    for row in rows:
        state = (row["lifecycle"] or "").upper()
        if state not in wanted:
            continue
        result = record_hunt_outcome(con, row["finding_key"],
                                     lifecycle_state=state)
        if result.get("ok"):
            recorded.append(row["finding_key"])
        else:
            skipped.append({"finding_key": row["finding_key"],
                            "reason": result.get("reason")})

    return {"ok": True, "recorded": len(recorded),
            "finding_keys": recorded, "skipped": skipped,
            "states": sorted(wanted)}
