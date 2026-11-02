"""Finding lifecycle, weak evidence, dedup, retest, and target-change detection
(master prompt §35, §37, §38, §40, §41).

The existing `finding.status` vocabulary is candidate|validating|validated|
duplicate|false_positive|reported|rejected — six states that do NOT match §35's
twelve. So this module adds the missing ones and enforces the transitions:

    OBSERVED -> CANDIDATE -> TESTING -> VALIDATED -> EVIDENCE_COMPLETE
             -> RETESTED -> REPORT_READY -> DELIVERED

    plus RESEARCH_REQUIRED | REVALIDATION_REQUIRED | DUPLICATE |
         FALSE_POSITIVE | OUT_OF_SCOPE | ABANDONED

Three properties make the machine real rather than decorative:

1. **TRANSITIONS ARE CHECKED, NOT ASSUMED.** `transition()` refuses an illegal
   move and names the legal ones. Without that, a finding can jump
   OBSERVED -> REPORT_READY and every downstream claim is built on sand.

2. **WEAK EVIDENCE IS A QUEUE, NOT A DISCARDS (§37).** A finding whose
   validation came back partial goes to `REVALIDATION_REQUIRED` with its
   failing levels, and the queue is work — it is ranked with everything else.
   "Interesting but insufficient" must never read as "nothing there".

3. **DUPLICATE IS A CONCLUSION, NOT A LOOKUP (§38).** `compare_findings` runs
   the ladder — compare, existing finding, known program issue, same root
   cause, same behaviour, variant, independent — and returns which rung it
   stopped at. Two findings with the same endpoint are not automatically a
   duplicate; §38 is explicit that a similar result must not be marked
   duplicate without evaluating whether it is an independent variant.

`retest_due` (§40) is a real decision over the recorded reasons — weak
evidence, uncertainty, duplicate concern, validation inconsistency, report
preparation, target change — not a date field someone sets.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from . import store

# ---------------------------------------------------------------------------

# §35 lifecycle. Order matters only for readability; LEGAL is what is enforced.
LIFECYCLE = (
    "OBSERVED",
    "CANDIDATE",
    "TESTING",
    "VALIDATED",
    "EVIDENCE_COMPLETE",
    "RETESTED",
    "REPORT_READY",
    "DELIVERED",
    "RESEARCH_REQUIRED",
    "REVALIDATION_REQUIRED",
    "DUPLICATE",
    "FALSE_POSITIVE",
    "OUT_OF_SCOPE",
    "ABANDONED",
)

# The happy path, and every branch off it.
LEGAL: dict[str, tuple[str, ...]] = {
    "OBSERVED": ("CANDIDATE", "OUT_OF_SCOPE", "ABANDONED", "RESEARCH_REQUIRED"),
    "CANDIDATE": ("TESTING", "REVALIDATION_REQUIRED", "DUPLICATE",
                  "FALSE_POSITIVE", "OUT_OF_SCOPE", "ABANDONED",
                  "RESEARCH_REQUIRED", "OBSERVED"),
    "TESTING": ("VALIDATED", "REVALIDATION_REQUIRED", "RESEARCH_REQUIRED",
                "CANDIDATE", "FALSE_POSITIVE", "ABANDONED", "DUPLICATE"),
    "VALIDATED": ("EVIDENCE_COMPLETE", "RETESTED", "REVALIDATION_REQUIRED",
                  "DUPLICATE", "ABANDONED", "FALSE_POSITIVE"),
    "EVIDENCE_COMPLETE": ("RETESTED", "REVALIDATION_REQUIRED", "REPORT_READY",
                          "ABANDONED", "DUPLICATE", "FALSE_POSITIVE"),
    "RETESTED": ("EVIDENCE_COMPLETE", "REPORT_READY", "REVALIDATION_REQUIRED",
                 "VALIDATED", "ABANDONED", "FALSE_POSITIVE", "DUPLICATE"),
    "REPORT_READY": ("DELIVERED", "REVALIDATION_REQUIRED", "ABANDONED",
                     "RETESTED", "DUPLICATE"),
    "DELIVERED": ("REVALIDATION_REQUIRED",),
    "RESEARCH_REQUIRED": ("CANDIDATE", "TESTING", "ABANDONED",
                          "REVALIDATION_REQUIRED", "RESEARCH_REQUIRED"),
    "REVALIDATION_REQUIRED": ("TESTING", "VALIDATED", "CANDIDATE", "ABANDONED",
                              "FALSE_POSITIVE", "DUPLICATE"),
    "DUPLICATE": ("CANDIDATE", "ABANDONED", "REVALIDATION_REQUIRED"),
    "FALSE_POSITIVE": ("CANDIDATE", "ABANDONED"),
    "OUT_OF_SCOPE": ("CANDIDATE", "ABANDONED"),
    "ABANDONED": ("CANDIDATE", "TESTING"),
}

TERMINAL_LIFECYCLE = ("DELIVERED", "ABANDONED", "FALSE_POSITIVE",
                      "OUT_OF_SCOPE")

SCHEMA = """
CREATE TABLE IF NOT EXISTS finding_state (
  finding_key TEXT PRIMARY KEY,
  lifecycle   TEXT NOT NULL,
  levels_failed TEXT,                 -- JSON list
  evidence_refs  TEXT,                -- JSON list of evidence ids
  changed_by  TEXT,
  reason      TEXT,
  at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_fstate_life ON finding_state(lifecycle);

-- The APPEND-ONLY transition history.
--
-- MEASURED 2026-11-01: `finding_state` is keyed by `finding_key` alone and
-- written with INSERT OR REPLACE, so every transition OVERWRITES the
-- previous row. MEASURED: a finding driven through CANDIDATE -> TESTING ->
-- VALIDATED -> EVIDENCE_COMPLETE left ONE row behind, holding only the
-- last state. The transition history was therefore lost: there was no way
-- to answer "how did this finding get here", "who promoted it", or "was it
-- ever demoted".
--
-- `finding_state` remains the CURRENT state (it is what the rest of the
-- system reads). This table is the HISTORY, and it is append-only: one row
-- per transition, never updated, never replaced. A finding that reaches
-- REPORT_READY after being demoted and re-promoted shows all three moves.
CREATE TABLE IF NOT EXISTS finding_transition (
  seq          INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_key  TEXT NOT NULL,
  from_state   TEXT,
  to_state     TEXT NOT NULL,
  levels_failed TEXT,                -- JSON list
  evidence_refs TEXT,                -- JSON list of evidence ids
  changed_by   TEXT,
  reason       TEXT,
  at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_ftrans_key ON finding_transition(finding_key, seq);
CREATE INDEX IF NOT EXISTS ix_ftrans_at  ON finding_transition(at);

-- Promotion is EVIDENCE-GATED.
--
-- The lifecycle's LEGAL table says which moves are permitted, but nothing
-- required that a permitted move be BACKED. MEASURED 2026-11-01: a finding
-- could be driven OBSERVED -> CANDIDATE -> TESTING -> VALIDATED ->
-- EVIDENCE_COMPLETE -> RETESTED -> REPORT_READY with `evidence_refs` = []
-- and reach REPORT_READY with no evidence at all.
--
-- This table names, per target state, the evidence a promotion must carry.
-- A transition that does not meet it is REFUSED, not warned about.
CREATE TABLE IF NOT EXISTS promotion_requirement (
  to_state   TEXT PRIMARY KEY,
  requires_evidence INTEGER NOT NULL DEFAULT 0,
  requires_reason   INTEGER NOT NULL DEFAULT 0,
  note       TEXT
);

CREATE TABLE IF NOT EXISTS revalidation_queue (
  rq_key        TEXT PRIMARY KEY,
  hunt_id       TEXT,
  finding_key   TEXT NOT NULL,
  reason        TEXT NOT NULL,
  levels_failed TEXT,
  evidence_ids  TEXT,
  state         TEXT NOT NULL DEFAULT 'queued',  -- queued|retested|closed
  queued_at     TEXT NOT NULL,
  resolved_at   TEXT
);
CREATE INDEX IF NOT EXISTS ix_rq_state ON revalidation_queue(state);

CREATE TABLE IF NOT EXISTS retest_record (
  retest_key   TEXT PRIMARY KEY,
  hunt_id      TEXT,
  finding_key  TEXT NOT NULL,
  trigger      TEXT NOT NULL,   -- §40's list
  verdict      TEXT,            -- confirmed|weakened|refuted|inconclusive
  detail       TEXT,
  at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_retest_finding ON retest_record(finding_key);

CREATE TABLE IF NOT EXISTS dedup_decision (
  decision_key TEXT PRIMARY KEY,
  finding_key  TEXT NOT NULL,
  vs_key       TEXT NOT NULL,
  verdict      TEXT NOT NULL,   -- duplicate|variant|independent
  rung         TEXT NOT NULL,   -- which rung of the §38 ladder decided it
  reason       TEXT,
  at           TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_dedup_finding ON dedup_decision(finding_key);

CREATE TABLE IF NOT EXISTS target_change (
  change_key  TEXT PRIMARY KEY,
  hunt_id     TEXT,
  kind        TEXT NOT NULL,   -- endpoint_removed|asset_new|behaviour_changed|
                               -- scope_changed|tech_changed
  subject     TEXT,
  before      TEXT,
  after       TEXT,
  impact      TEXT,             -- tasks invalidated | none
  rebuilt     TEXT,             -- JSON list of what was rebuilt
  preserved   TEXT,             -- JSON list of what was preserved
  at          TEXT NOT NULL
);
"""


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    # The promotion gate's requirements. Seeded with INSERT OR IGNORE so an
    # operator can tighten them for a given deployment without the seed
    # overwriting their choice on the next call.
    #
    # The rule: once a finding has been TESTED, every further promotion
    # must cite evidence. CANDIDATE may be reached from a bare observation
    # (that is what a candidate IS), but VALIDATED means "the evidence
    # proves it", EVIDENCE_COMPLETE means "the evidence is complete", and
    # REPORT_READY means "a human can read it and act".
    for to_state, needs_ev, needs_reason, note in (
        ("CANDIDATE", 0, 1, "a candidate needs a reason, not yet evidence"),
        ("TESTING", 0, 1, "testing starts from a stated hypothesis"),
        ("VALIDATED", 1, 1, "validated means the evidence proves the claim"),
        ("EVIDENCE_COMPLETE", 1, 1, "the evidence must be complete and cited"),
        ("RETESTED", 1, 1, "a retest must cite the evidence it reproduced"),
        ("REPORT_READY", 1, 1, "a report-ready finding must cite its proof"),
        ("REPORTABLE", 1, 1, "a reportable finding must cite its proof"),
        ("CONFIRMED", 1, 1, "a confirmed finding must cite its proof"),
    ):
        con.execute(
            "INSERT OR IGNORE INTO promotion_requirement"
            "(to_state, requires_evidence, requires_reason, note)"
            " VALUES (?,?,?,?)", (to_state, needs_ev, needs_reason, note))
    con.commit()


class IllegalTransition(ValueError):
    """A lifecycle move the state machine does not permit."""


class PromotionNotSupported(ValueError):
    """A legal transition that lacks the evidence the gate requires.

    Distinct from `IllegalTransition` on purpose: the move is PERMITTED by
    the lifecycle's shape but NOT SUPPORTED by the evidence presented. The
    caller gets a message that says which requirement was unmet, so the
    fix is obvious rather than a refusal with no explanation.
    """


# ---------------------------------------------------------------------------

class FindingLifecycle:
    def __init__(self, con: sqlite3.Connection, hunt_id: str = "default"):
        self.con = con
        self.hunt_id = hunt_id
        _ensure(con)

    # ------------------------------------------------------------ transitions
    def state(self, finding_key: str) -> str:
        row = self.con.execute(
            "SELECT lifecycle FROM finding_state WHERE finding_key=?",
            (finding_key,)).fetchone()
        if row:
            return row["lifecycle"]
        # A finding that predates the lifecycle machine is inferred from the
        # older status column, never left blank: an unknown state is one that
        # cannot be reasoned about.
        #
        # MEASURED 2026-11-01: `candidate` was mapped to `CANDIDATE`. But
        # `candidate` is the SCHEMA DEFAULT for `finding.status` -- every
        # freshly filed row has it -- so it says nothing about where the
        # finding is in the lifecycle. Inferring CANDIDATE from it made the
        # first real transition (OBSERVED -> CANDIDATE) look like a no-op,
        # so it took the no-op path, skipped the promotion gate, and
        # recorded the history row with `from_state` = `to_state` = CANDIDATE.
        # A finding with no `finding_state` row has never been through this
        # machine, so its honest position is OBSERVED.
        f = self.con.execute(
            "SELECT status FROM finding WHERE finding_key=?",
            (finding_key,)).fetchone()
        if not f:
            return "OBSERVED"
        return {"validating": "TESTING",
                "validated": "VALIDATED", "duplicate": "DUPLICATE",
                "false_positive": "FALSE_POSITIVE", "reported": "REPORT_READY",
                "rejected": "ABANDONED"}.get(f["status"], "OBSERVED")

    def transition(self, finding_key: str, to_state: str, *, reason: str = "",
                   changed_by: str = "", levels_failed: Iterable[str] | None = None,
                   evidence_ids: Iterable[int] | None = None) -> dict[str, Any]:
        """Move a finding, refusing an illegal move and naming the legal ones."""
        if to_state not in LIFECYCLE:
            raise ValueError(f"unknown lifecycle state {to_state!r}; known: "
                             f"{LIFECYCLE}")
        cur = self.state(finding_key)
        if to_state == cur:
            self._write(finding_key, to_state, changed_by, reason,
                        levels_failed, evidence_ids)
            self._history(finding_key, cur, to_state, changed_by, reason,
                          levels_failed, evidence_ids)
            return {"ok": True, "from": cur, "to": to_state, "no_op": True}
        legal = LEGAL.get(cur, ())
        if to_state not in legal:
            raise IllegalTransition(
                f"{finding_key}: {cur} -> {to_state} is not a legal transition. "
                f"Legal from {cur}: {legal}")
        # The PROMOTION GATE. A move can be legal by shape and still be
        # unsupported by the evidence presented. This check runs BEFORE the
        # write, so a refused promotion leaves no trace in the current state.
        self._check_promotion(finding_key, cur, to_state, reason,
                              evidence_ids)
        self._write(finding_key, to_state, changed_by, reason,
                    levels_failed, evidence_ids)
        self._history(finding_key, cur, to_state, changed_by, reason,
                      levels_failed, evidence_ids)
        # Keep the older column consistent so nothing reads a stale status.
        legacy = {"CANDIDATE": "candidate", "TESTING": "validating",
                  "VALIDATED": "validated", "DUPLICATE": "duplicate",
                  "FALSE_POSITIVE": "false_positive",
                  "REPORT_READY": "reported", "ABANDONED": "rejected"}
        if to_state in legacy:
            self.con.execute(
                "UPDATE finding SET status=?, updated_at=? WHERE finding_key=?",
                (legacy[to_state], store.now(), finding_key))
        self.con.commit()
        return {"ok": True, "from": cur, "to": to_state, "reason": reason}

    def _check_promotion(self, finding_key: str, cur: str, to_state: str,
                         reason: str, evidence_ids) -> None:
        """Refuse a promotion that lacks what the gate requires.

        The requirement is read from the table, not hard-coded, so a
        deployment can require more (or, deliberately, less) without
        editing the state machine.
        """
        req = self.con.execute(
            "SELECT requires_evidence, requires_reason, note"
            " FROM promotion_requirement WHERE to_state=?",
            (to_state,)).fetchone()
        if req is None:
            return
        unmet: list[str] = []
        if req["requires_evidence"] and not list(evidence_ids or []):
            unmet.append("evidence ids")
        if req["requires_reason"] and not (reason or "").strip():
            unmet.append("a reason")
        if not unmet:
            return
        note = req["note"] or ""
        raise PromotionNotSupported(
            f"{finding_key}: {cur} -> {to_state} is legal but not supported: "
            f"missing {', '.join(unmet)}. "
            + (f"{note}." if note else "")
            + " The finding was not promoted.")

    def _history(self, finding_key: str, from_state: str | None,
                 to_state: str, changed_by: str, reason: str,
                 levels_failed, evidence_ids) -> None:
        """Append one row to the transition history. Never updates a row."""
        self.con.execute(
            "INSERT INTO finding_transition(finding_key, from_state, to_state,"
            " levels_failed, evidence_refs, changed_by, reason, at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (finding_key, from_state, to_state,
             json.dumps(sorted(levels_failed) if levels_failed else []),
             json.dumps(sorted(evidence_ids) if evidence_ids else []),
             changed_by or "system", reason, store.now()))

    def history(self, finding_key: str) -> list[dict[str, Any]]:
        """The full, ordered transition history of a finding."""
        rows = self.con.execute(
            "SELECT seq, from_state, to_state, levels_failed, evidence_refs,"
            " changed_by, reason, at FROM finding_transition"
            " WHERE finding_key=? ORDER BY seq", (finding_key,)).fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            d = dict(r)
            for k in ("levels_failed", "evidence_refs"):
                try:
                    d[k] = json.loads(d.get(k) or "[]")
                except json.JSONDecodeError:
                    d[k] = []
            out.append(d)
        return out

    def _write(self, finding_key: str, state: str, changed_by: str,
               reason: str, levels_failed, evidence_ids) -> None:
        self.con.execute(
            "INSERT OR REPLACE INTO finding_state(finding_key, lifecycle,"
            " levels_failed, evidence_refs, changed_by, reason, at)"
            " VALUES (?,?,?,?,?,?,?)",
            (finding_key, state,
             json.dumps(sorted(levels_failed) if levels_failed else []),
             json.dumps(sorted(evidence_ids) if evidence_ids else []),
             changed_by or "system", reason, store.now()))

    def board(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {s: [] for s in LIFECYCLE}
        for r in self.con.execute("SELECT finding_key, lifecycle FROM finding_state"):
            out.setdefault(r["lifecycle"], []).append(r["finding_key"])
        return out

    # ------------------------------------------------- §37 weak evidence queue
    def queue_revalidation(self, finding_key: str, *, reason: str,
                           levels_failed: Iterable[str] = (),
                           evidence_ids: Iterable[int] = ()) -> str:
        """Weak evidence is QUEUED, never discarded (§37)."""
        key = f"rq.{finding_key}"
        self.con.execute(
            "INSERT OR REPLACE INTO revalidation_queue(rq_key, hunt_id,"
            " finding_key, reason, levels_failed, evidence_ids, state,"
            " queued_at) VALUES (?,?,?,?,?,?,'queued',?)",
            (key, self.hunt_id, finding_key, reason,
             json.dumps(sorted(levels_failed)), json.dumps(sorted(evidence_ids)),
             store.now()))
        self.transition(finding_key, "REVALIDATION_REQUIRED", reason=reason,
                        levels_failed=levels_failed, evidence_ids=evidence_ids)
        self.con.commit()
        return key

    def revalidation_queue(self, state: str = "queued") -> list[dict[str, Any]]:
        return [dict(r) for r in self.con.execute(
            "SELECT * FROM revalidation_queue WHERE state=? ORDER BY queued_at",
            (state,))]

    def close_revalidation(self, rq_key: str, *, finding_key: str,
                           outcome: str) -> None:
        self.con.execute(
            "UPDATE revalidation_queue SET state=?, resolved_at=?"
            " WHERE rq_key=?",
            ("retested" if outcome == "confirmed" else "closed", store.now(),
             rq_key))
        self.con.commit()

    # ------------------------------------------------------------ §40 retest
    RETEST_TRIGGERS = ("weak_evidence", "uncertainty", "duplicate_concern",
                       "validation_inconsistency", "report_preparation",
                       "target_change", "new_research", "new_knowledge")

    def retest_due(self, finding_key: str, *, trigger: str) -> dict[str, Any]:
        """Record a retest and move the finding along. `trigger` must be named.

        A retest with no reason is indistinguishable from a second guess, and
        §40 enumerates when retesting is warranted — so an unnamed trigger is
        refused rather than defaulted.
        """
        if trigger not in self.RETEST_TRIGGERS:
            return {"retested": False,
                    "reason": f"trigger {trigger!r} is not one of §40's "
                              f"warranted cases: {self.RETEST_TRIGGERS}"}
        k = f"retest.{finding_key}.{abs(hash(trigger + store.now())) % (10 ** 8)}"
        self.con.execute(
            "INSERT OR REPLACE INTO retest_record(retest_key, hunt_id,"
            " finding_key, trigger, verdict, detail, at) VALUES (?,?,?,?,?,?,?)",
            (k, self.hunt_id, finding_key, trigger, None, None, store.now()))
        cur = self.state(finding_key)
        if "RETESTED" in LEGAL.get(cur, ()):
            self.transition(finding_key, "RETESTED", reason=trigger)
        self.con.commit()
        return {"retested": True, "retest_key": k, "trigger": trigger,
                "state": self.state(finding_key)}

    def record_retest_verdict(self, retest_key: str, verdict: str, *,
                              detail: str = "") -> None:
        allowed = {"confirmed", "weakened", "refuted", "inconclusive"}
        if verdict not in allowed:
            raise ValueError(f"retest verdict must be one of {sorted(allowed)}")
        row = self.con.execute(
            "SELECT finding_key FROM retest_record WHERE retest_key=?",
            (retest_key,)).fetchone()
        self.con.execute(
            "UPDATE retest_record SET verdict=?, detail=? WHERE retest_key=?",
            (verdict, detail, retest_key))
        self.con.commit()
        if row and verdict == "refuted":
            self.transition(row["finding_key"], "FALSE_POSITIVE",
                            reason=f"retest refuted: {detail}")

    def retest_history(self, finding_key: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self.con.execute(
            "SELECT * FROM retest_record WHERE finding_key=? ORDER BY at",
            (finding_key,))]

    # --------------------------------------------------- §38 dedup as a ladder
    def compare_findings(self, finding_key: str, other_key: str
                         ) -> dict[str, Any]:
        """Walk §38's ladder and report which rung decided it.

        Rungs: same finding -> existing finding -> known program issue ->
        same root cause -> same behaviour -> variant -> independent.

        The important behaviour is the BOTTOM: two findings sharing an endpoint
        land on `variant` or `independent`, never automatically `duplicate`,
        because §38 says a similar result must not be marked duplicate without
        evaluating whether it is an independent variant.
        """
        a = self.con.execute("SELECT * FROM finding WHERE finding_key=?",
                             (finding_key,)).fetchone()
        b = self.con.execute("SELECT * FROM finding WHERE finding_key=?",
                             (other_key,)).fetchone()
        if not a or not b:
            return {"verdict": "independent", "rung": "lookup",
                    "reason": "one of the findings does not exist"}

        if finding_key == other_key:
            verdict, rung = "duplicate", "same_finding"
        elif (a["dedup_group"] and a["dedup_group"] == b["dedup_group"]):
            verdict, rung = "duplicate", "existing_finding"
        elif _same_root_cause(a, b):
            verdict, rung = "duplicate", "same_root_cause"
        elif _same_behaviour(a, b):
            verdict, rung = "variant", "same_behaviour"
        elif (a["class_id"] and a["class_id"] == b["class_id"]):
            verdict, rung = "variant", "variant_same_class_different_behaviour"
        else:
            verdict, rung = "independent", "independent"

        reason = {
            "same_finding": "identical key",
            "existing_finding": "identical dedup_group",
            "same_root_cause": (f"both name the same weakness at "
                                f"{a['endpoint'] or a['asset']}"),
            "same_behaviour": ("same behaviour signature but a distinct "
                               "root cause or a distinct reproduction"),
            "variant_same_class_different_behaviour":
                "same bug class, different observable behaviour",
            "independent": "different class or different target behaviour",
        }[rung]

        self.con.execute(
            "INSERT OR REPLACE INTO dedup_decision(decision_key, finding_key,"
            " vs_key, verdict, rung, reason, at) VALUES (?,?,?,?,?,?,?)",
            (f"dd.{finding_key}.{other_key}", finding_key, other_key, verdict,
             rung, reason, store.now()))
        self.con.commit()
        return {"finding": finding_key, "vs": other_key, "verdict": verdict,
                "rung": rung, "reason": reason,
                "note": ("a similar result is only a duplicate after the ladder "
                         "is walked; a variant stays reportable (§38)")}

    def dedup_decisions(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.con.execute(
            "SELECT * FROM dedup_decision ORDER BY at")]

    # ------------------------------------------- §41 target change detection
    def record_change(self, *, kind: str, subject: str, before: Any = None,
                      after: Any = None, impact: str = "tasks invalidated",
                      rebuilt: Iterable[str] = (), preserved: Iterable[str] = ()
                      ) -> str:
        """Detect -> determine impact -> rebuild affected -> preserve unaffected.

        `preserved` is recorded explicitly, because §41's failure mode is
        restarting the whole hunt when one branch changed.
        """
        k = f"chg.{self.hunt_id}.{abs(hash(kind + subject + str(after))) % (10 ** 9)}"
        self.con.execute(
            "INSERT OR REPLACE INTO target_change(change_key, hunt_id, kind,"
            " subject, before, after, impact, rebuilt, preserved, at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (k, self.hunt_id, kind, subject, json.dumps(before, default=str),
             json.dumps(after, default=str), impact,
             json.dumps(list(rebuilt)), json.dumps(list(preserved)), store.now()))
        self.con.commit()
        return k

    def detect_change(self, *, expected: Iterable[str],
                      observed: Iterable[str]) -> dict[str, Any]:
        """Compare a recorded expectation against the live surface.

        Returns what appeared, what vanished, and which findings rest on
        something that vanished — so only those are revalidated.
        """
        exp, obs = set(expected or ()), set(observed or ())
        gone = sorted(exp - obs)
        new = sorted(obs - exp)
        affected: list[str] = []
        for g in gone:
            rows = self.con.execute(
                "SELECT finding_key FROM finding WHERE endpoint=? OR asset=?",
                (g, g)).fetchall()
            affected.extend(r["finding_key"] for r in rows)
        return {"removed": gone, "added": new, "affected_findings": affected,
                "needs_revalidation": bool(affected),
                "preserved": "everything not resting on a removed item",
                "note": ("only the affected branch is rebuilt; the rest of the "
                         "hunt keeps its state (§41)")}

    def changes(self) -> list[dict[str, Any]]:
        return [dict(r) for r in self.con.execute(
            "SELECT * FROM target_change WHERE hunt_id=? ORDER BY at",
            (self.hunt_id,))]

    def summary(self) -> dict[str, Any]:
        board = {k: v for k, v in self.board().items() if v}
        return {"hunt_id": self.hunt_id, "lifecycle": board,
                "revalidation_queued": len(self.revalidation_queue()),
                "changes": len(self.changes()),
                "retests": int(self.con.execute(
                    "SELECT count(*) n FROM retest_record WHERE hunt_id=?",
                    (self.hunt_id,)).fetchone()["n"]),
                "dedup_decisions": len(self.dedup_decisions())}


# ---------------------------------------------------------------------------

def _norm_words(*vals: str | None) -> set[str]:
    import re
    words: set[str] = set()
    for v in vals:
        for w in re.findall(r"[a-z0-9]+", (v or "").lower()):
            if len(w) > 3:
                words.add(w)
    return words


def _same_root_cause(a: sqlite3.Row, b: sqlite3.Row) -> bool:
    if a["class_id"] and a["class_id"] == b["class_id"] \
            and (a["endpoint"] or "") == (b["endpoint"] or "") \
            and a["endpoint"]:
        wa, wb = _norm_words(a["hypothesis"]), _norm_words(b["hypothesis"])
        if wa and wb:
            return len(wa & wb) / max(len(wa | wb), 1) >= 0.6
    return False


def _same_behaviour(a: sqlite3.Row, b: sqlite3.Row) -> bool:
    """Same endpoint AND overlapping claim vocabulary: same behaviour observed,
    plausibly a different cause. §38's 'variant' rung."""
    if not a["endpoint"] or (a["endpoint"] or "") != (b["endpoint"] or ""):
        return False
    wa, wb = _norm_words(a["hypothesis"]), _norm_words(b["hypothesis"])
    return bool(wa and wb) and len(wa & wb) / max(len(wa | wb), 1) >= 0.35