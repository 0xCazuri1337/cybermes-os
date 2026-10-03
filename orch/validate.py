"""Validation engine (spec §26). Six levels, and L4 is the one that matters.

L1 structural · L2 logical · L3 reproduction · L4 independent agent ·
L5 evidence · L6 impact

The design constraint that shapes this module: the agent that produced a claim
must not be the only one able to pass it. `check_independence` enforces that by
comparing the claimant's run against the validator's, and a validator that
turns out to be the claimant scores nothing — a check that cannot fail is
exactly the failure invariant I3 exists to prevent.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import store

LEVELS = ("L1", "L2", "L3", "L4", "L5", "L6")

LEVEL_NAMES = {
    "L1": "structural",
    "L2": "logical",
    "L3": "reproduction",
    "L4": "independent_agent",
    "L5": "evidence",
    "L6": "impact",
}

# What a finding must clear to be called validated. Deliberately demanding:
# a "validated" finding that a triager would reject is worse than one still
# marked candidate, because it stops looking.
REPORTABLE_REQUIRES = ("L1", "L2", "L3", "L5")


def _result(level: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"level": level, "name": LEVEL_NAMES[level], "passed": passed,
            "detail": detail}


def check_l1_structure(con: sqlite3.Connection, finding_key: str) -> dict[str, Any]:
    """The record is well-formed enough to be examined at all."""
    row = con.execute("SELECT * FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if not row:
        return _result("L1", False, "finding does not exist")
    missing = [f for f in ("title", "finding_key") if not (row[f] or "").strip()]
    if missing:
        return _result("L1", False, f"empty required field(s): {missing}")
    return _result("L1", True, f"record well-formed; status={row['status']}")


def check_l2_logic(con: sqlite3.Connection, finding_key: str) -> dict[str, Any]:
    """A claim needs a falsifiable statement and a stated impact."""
    row = con.execute("SELECT * FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if not row:
        return _result("L2", False, "finding does not exist")
    if not (row["hypothesis"] or "").strip():
        return _result("L2", False,
                       "no hypothesis: the claim cannot be judged true or false")
    if len(row["hypothesis"]) < 20:
        return _result("L2", False, "hypothesis too vague to be falsifiable")
    if not (row["endpoint"] or row["asset"] or row["target"]):
        return _result("L2", False, "no target/asset/endpoint named")
    return _result("L2", True,
                   f"falsifiable claim against {row['endpoint'] or row['asset']}")


def check_l3_reproduction(con: sqlite3.Connection, finding_key: str,
                          *, reproduced: bool = False,
                          detail: str = "") -> dict[str, Any]:
    """Reproduction is asserted by the caller because only a real attempt can
    establish it. Recorded as unproven unless explicitly marked reproduced."""
    if reproduced:
        return _result("L3", True, detail or "reproduction observed")
    return _result("L3", False,
                   detail or "no reproduction recorded; a claim is not a finding")


def check_independence(con: sqlite3.Connection, finding_key: str,
                       *, claimant_run: str | None = None,
                       validator_run: str | None = None) -> dict[str, Any]:
    """L4. The validator must not be the claimant.

    Two things are required, and omitting either must FAIL rather than pass
    vacuously. An earlier version compared run-key strings and treated a
    missing validator as merely "unknown", so `validate_finding(con, key,
    reproduced=True)` — with no claimant at all — passed L4 and reached
    `verdict='validated'` with no independent agent anywhere in the system.
    Absence of a party is not independence; it is absence of evidence.

    Independence is also checked on the ROLE, not only the run key: the same
    agent role producing and validating a claim is one agent, however many
    run keys it used.
    """
    row = con.execute(
        "SELECT validator_run FROM finding WHERE finding_key=?",
        (finding_key,)).fetchone()
    validator = validator_run or (row["validator_run"] if row else None)
    if not validator:
        return _result("L4", False,
                       "no validator recorded: independence unproven. "
                       "A missing validator is not an independent one.")
    if not claimant_run:
        return _result("L4", False,
                       "no claimant recorded, so it cannot be shown that the "
                       "validator is someone other than the producer")
    if validator == claimant_run:
        return _result("L4", False,
                       f"validator {validator} IS the claimant; independence "
                       "not established")

    # Same ROLE on both sides is one agent wearing two run keys.
    def role_of(run_key: str) -> str | None:
        r = con.execute("SELECT role_key FROM agent_run WHERE run_key=?",
                        (run_key,)).fetchone()
        return r["role_key"] if r else None

    cv, cc = role_of(validator), role_of(claimant_run)
    if cv and cc and cv == cc:
        return _result("L4", False,
                       f"validator and claimant share role {cv!r}; one agent "
                       "cannot independently validate its own claim")
    return _result("L4", True,
                   f"validator {validator} (role {cv or 'unknown'}) differs "
                   f"from claimant {claimant_run} (role {cc or 'unknown'})")


def check_l5_evidence(con: sqlite3.Connection, finding_key: str) -> dict[str, Any]:
    """Evidence must exist and be inspectable, not merely counted."""
    row = con.execute("SELECT id FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if not row:
        return _result("L5", False, "finding does not exist")
    ev = con.execute(
        "SELECT kind, request_raw, response_raw, payload, sha256 FROM evidence"
        " WHERE finding_id=?", (row["id"],)).fetchall()
    if not ev:
        return _result("L5", False, "zero evidence attached")
    substantive = [e for e in ev if (e["request_raw"] or e["response_raw"]
                                     or e["payload"] or "")]
    if not substantive:
        return _result("L5", False,
                       f"{len(ev)} evidence row(s) but none carries content")
    return _result("L5", True,
                   f"{len(substantive)} substantive evidence item(s) with hashes")


def check_l6_impact(con: sqlite3.Connection, finding_key: str) -> dict[str, Any]:
    """Impact must be stated and consistent with the severity claimed."""
    row = con.execute("SELECT severity, hypothesis FROM finding"
                      " WHERE finding_key=?", (finding_key,)).fetchone()
    if not row:
        return _result("L6", False, "finding does not exist")
    if not (row["severity"] or "").strip():
        return _result("L6", False, "no severity assigned")
    if (row["severity"] or "").lower() in {"critical", "high"} \
            and not row["hypothesis"]:
        return _result("L6", False,
                       "critical/high severity asserted without a claim")
    return _result("L6", True, f"severity={row['severity']} with stated basis")


def validate_finding(con: sqlite3.Connection, finding_key: str, *,
                     reproduced: bool = False,
                     claimant_run: str | None = None,
                     validator_run: str | None = None,
                     rep_detail: str = "") -> dict[str, Any]:
    """Run every level and return the full vector. Never mutates the finding —
    the caller decides what a result means, so validation stays a pure read
    that can be re-run and compared."""
    results = {
        "L1": check_l1_structure(con, finding_key),
        "L2": check_l2_logic(con, finding_key),
        "L3": check_l3_reproduction(con, finding_key, reproduced=reproduced,
                                    detail=rep_detail),
        "L4": check_independence(con, finding_key, claimant_run=claimant_run,
                                 validator_run=validator_run),
        "L5": check_l5_evidence(con, finding_key),
        "L6": check_l6_impact(con, finding_key),
    }
    passed = [lv for lv in LEVELS if results[lv]["passed"]]
    reportable = all(lv in passed for lv in REPORTABLE_REQUIRES)
    return {
        "finding_key": finding_key,
        "results": results,
        "levels_passed": passed,
        "levels_failed": [lv for lv in LEVELS if not results[lv]["passed"]],
        "score": f"{len(passed)}/{len(LEVELS)}",
        "reportable": reportable,
        "validated": reportable and "L4" in passed,
        "verdict": ("validated" if (reportable and "L4" in passed)
                    else "candidate" if "L1" in passed and "L2" in passed
                    else "rejected"),
        "checked_at": store.now(),
    }


def validate_task_artifact(con: sqlite3.Connection, task_key: str,
                           *, result: str | None = None) -> dict[str, Any]:
    """L1-L2 for a completed task: does the artifact exist and is it non-trivial?

    Invariant I10: improvement requires an artifact. A task marked done with no
    result recorded is the cheapest way for this system to lie to itself.

    `result` lets the caller pass the artifact the run just produced. Without
    it the gate can only read `task.result`, which is still empty at the moment
    a run finishes — so gating before the result is written rejects every
    genuine success. That ordering bug made 16 real tasks look failed.
    """
    row = store.get_task(con, task_key)
    if not row:
        return {"task_key": task_key, "passed": False, "detail": "task not found"}
    if not (row["expected_artifact"] or "").strip():
        return {"task_key": task_key, "passed": False,
                "detail": "task declares no expected artifact (L1)"}
    text = result if result is not None else (row["result"] or "")
    text = (text or "").strip()
    if not text:
        return {"task_key": task_key, "passed": False,
                "detail": "task has no recorded result (L5-equivalent)"}
    if len(text) < 10:
        return {"task_key": task_key, "passed": False,
                "detail": "result string too short to be an artifact"}
    return {"task_key": task_key, "passed": True,
            "detail": f"artifact recorded ({len(text)} chars)"}


def apply_validation(con: sqlite3.Connection, finding_key: str,
                     result: dict[str, Any]) -> str:
    """Persist a validation vector and move the finding to its verdict state.

    The verdict is RE-DERIVED here, never taken from `result`. Trusting the
    caller's verdict string means any caller holding a dict can write
    `validated` onto a finding that passed nothing — and since `validated` is
    the state a triager trusts, that is the most damaging single field in the
    system. Reproduced: `apply_validation({"verdict": "validated"})` set the
    status straight to validated.
    """
    derived = validate_finding(
        con, finding_key,
        reproduced=bool(result.get("reproduced")),
        claimant_run=result.get("claimant_run"),
        validator_run=result.get("validator_run"))
    store.set_finding_status(con, finding_key, derived["verdict"],
                             validation=derived)
    return derived["verdict"]


def false_positive(con: sqlite3.Connection, finding_key: str, *,
                   invalidated_by: str, early_signal_missed: str,
                   rejection_rule: str, class_id: str | None = None
                   ) -> str:
    """Turn a failed claim into a durable lesson (spec §27).

    A false positive that is not written down is a false positive that recurs.
    The rule is written into the knowledge engine's fp_case table so the class
    maturity gate — which is blocked on fp_rules — can eventually see it.
    """
    import hashlib
    fp_key = "fp." + hashlib.sha256(
        f"{class_id}|{rejection_rule}".encode()).hexdigest()[:12]
    now = store.now()

    # The lesson is only useful if the claim it came from actually exists.
    # Writing a lesson for an unknown finding means a typo silently produces
    # an unattributable rule that will later be cited as evidence of experience.
    row = con.execute("SELECT id FROM finding WHERE finding_key=?",
                      (finding_key,)).fetchone()
    if not row:
        raise KeyError(f"cannot record a false positive for unknown finding "
                       f"{finding_key!r}; the claim must exist first")

    # A lesson attached to a class that is not registered is unattributable,
    # and the raw IntegrityError would say nothing about which value was wrong.
    if class_id:
        known = con.execute("SELECT 1 FROM bug_class WHERE id=?",
                            (class_id,)).fetchone()
        if not known:
            raise KeyError(f"class {class_id!r} is not a registered bug_class; "
                           "the rule could never be attributed")

    con.execute(
        "INSERT OR IGNORE INTO fp_case(fp_key, class_id, hypothesis,"
        " test_performed, invalidated_by, early_signal_missed, rejection_rule,"
        " created_at) VALUES (?,?,?,?,?,?,?,?)",
        (fp_key, class_id, invalidated_by, "validation pipeline",
         invalidated_by, early_signal_missed, rejection_rule, now))
    store.set_finding_status(con, finding_key, "false_positive",
                             validation={"invalidated_by": invalidated_by,
                                         "rejection_rule": rejection_rule})
    con.commit()
    return fp_key


def dedupe(con: sqlite3.Connection) -> dict[str, Any]:
    """Collapse duplicate findings into a canonical one (spec §28).

    Identity is the dedup_group the caller derived; this resolves groups whose
    members point at different targets by evidence overlap (endpoint + asset),
    and links rather than deletes, so unique evidence survives (§28).
    """
    groups: dict[str, list[sqlite3.Row]] = {}
    for f in store.findings(con):
        if f["status"] in {"rejected", "false_positive"}:
            continue
        g = f["dedup_group"] or f"{f['target']}|{f['asset']}|{f['endpoint']}"
        groups.setdefault(g, []).append(f)

    merged = []
    for g, members in groups.items():
        if len(members) < 2:
            continue
        # canonical = earliest created, so the merge is stable across runs
        members.sort(key=lambda r: (r["created_at"], r["id"]))
        canon = members[0]
        for m in members[1:]:
            con.execute("UPDATE finding SET status='duplicate', canonical_id=?,"
                        " updated_at=? WHERE id=?",
                        (canon["id"], store.now(), m["id"]))
            con.execute("UPDATE evidence SET finding_id=? WHERE finding_id=?",
                        (canon["id"], m["id"]))
        merged.append({"group": g, "canonical": canon["finding_key"],
                       "canonical_id": canon["id"],
                       "duplicates": [m["finding_key"] for m in members[1:]]})
    con.commit()
    return {"groups_merged": len(merged), "detail": merged}