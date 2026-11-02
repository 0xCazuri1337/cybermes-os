"""Capability lifecycle — Proposed -> Validated -> Active -> Deprecated.

WHY THIS IS SEPARATE FROM FINDING VALIDITY
------------------------------------------
`orch/validate.py` answers "is this FINDING technically well-formed, reproduced,
independently checked and evidenced?". That is a question about a result. This
module answers a different question: "is this CAPABILITY trustworthy enough to
run at all?".

Conflating them produces two real defects:

  * A capability that is perfectly good but has never produced a reportable
    finding would look untrustworthy, and would be switched off.
  * A capability that is broken would look trustworthy because one of its
    findings happened to validate.

The two are therefore independent by construction. A capability's lifecycle
state is stored in its own tables and NEVER read from, or written to, the
finding tables. `orch/validate.py` is not imported here, and nothing here
imports it.

THE GATES
----------
  PROPOSED -> VALIDATED   the artifact satisfies the static contract: the
                           manifest parses, the referenced files exist, the
                           declared inputs/outputs are non-empty, the
                           dependency graph resolves, and the registry entry
                           is real.
  VALIDATED -> ACTIVE     the routing benchmark covers this capability, its
                           execution test passes, its contract test passes and
                           its references are intact. The threshold is 90%
                           routing success over the labelled tasks that
                           exercise it. A capability the dataset does not
                           exercise is NOT activated -- it is recorded as
                           `insufficiently_evaluated`, because unmeasured is
                           not measured.
  ACTIVE -> DEPRECATED    a replacement exists and is itself ACTIVE, or an
                           operator records the reason. The capability's
                           original source is never deleted.

Every transition is append-only in `capability_lifecycle_transition`, so
"how did this capability become Active" is answerable after the fact.
"""
from __future__ import annotations

import sqlite3
from typing import Any

from .capability_contract import (
    LIFECYCLE_STATES,
    LIFECYCLE_TRANSITIONS,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS capability_lifecycle (
  capability_id TEXT PRIMARY KEY,
  lifecycle     TEXT NOT NULL DEFAULT 'PROPOSED',
  reason        TEXT,
  updated_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capability_lifecycle_transition (
  id            INTEGER PRIMARY KEY,
  capability_id TEXT NOT NULL,
  from_state    TEXT,
  to_state      TEXT NOT NULL,
  reason        TEXT,
  actor         TEXT,
  at            TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_cap_lifecycle_transition
  ON capability_lifecycle_transition(capability_id, id);
"""

#: The routing-success threshold for VALIDATED -> ACTIVE.
ACTIVATION_ROUTING_THRESHOLD = 0.90

#: The evaluation outcomes a capability can have at the activation gate.
EVALUATION_OUTCOMES = (
    "sufficiently_evaluated",
    "insufficiently_evaluated",
    "failed",
)


class LifecycleError(RuntimeError):
    """An illegal lifecycle transition, or a gate that did not pass.

    The message names the gate and what it required, because "promotion
    refused" without a reason is the kind of refusal that gets worked around.
    """


def _now() -> str:
    from . import store
    return store.now()


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


def current_state(con: sqlite3.Connection, capability_id: str) -> str:
    """The capability's lifecycle state. Unknown capabilities are PROPOSED.

    An unregistered capability is PROPOSED rather than ACTIVE: the default for
    an unknown artifact is the most restrictive state, not the most permissive
    one.
    """
    ensure_schema(con)
    row = con.execute(
        "SELECT lifecycle FROM capability_lifecycle WHERE capability_id=?",
        (capability_id,)).fetchone()
    if row is None:
        return "PROPOSED"
    state = str(row["lifecycle"] or "PROPOSED")
    return state if state in LIFECYCLE_STATES else "PROPOSED"


def state_of(con: sqlite3.Connection, capability_id: str) -> dict[str, Any]:
    """The state plus its reason and update time."""
    ensure_schema(con)
    row = con.execute(
        "SELECT lifecycle, reason, updated_at FROM capability_lifecycle "
        "WHERE capability_id=?", (capability_id,)).fetchone()
    if row is None:
        return {"capability_id": capability_id, "lifecycle": "PROPOSED",
                "reason": "not registered", "updated_at": ""}
    return {"capability_id": capability_id,
            "lifecycle": str(row["lifecycle"]),
            "reason": str(row["reason"] or ""),
            "updated_at": str(row["updated_at"] or "")}


def all_states(con: sqlite3.Connection) -> dict[str, str]:
    ensure_schema(con)
    rows = con.execute(
        "SELECT capability_id, lifecycle FROM capability_lifecycle").fetchall()
    return {str(r["capability_id"]): str(r["lifecycle"]) for r in rows}


def transitions(con: sqlite3.Connection, capability_id: str) -> list[dict[str, Any]]:
    """The append-only transition history for one capability."""
    ensure_schema(con)
    rows = con.execute(
        "SELECT from_state, to_state, reason, actor, at FROM "
        "capability_lifecycle_transition WHERE capability_id=? ORDER BY id",
        (capability_id,)).fetchall()
    return [{"from": r["from_state"], "to": r["to_state"],
             "reason": r["reason"], "actor": r["actor"], "at": r["at"]}
            for r in rows]


def _assert_transition(from_state: str, to_state: str) -> None:
    if to_state not in LIFECYCLE_STATES:
        raise LifecycleError(
            f"{to_state!r} is not a lifecycle state; expected one of "
            f"{LIFECYCLE_STATES}")
    allowed = LIFECYCLE_TRANSITIONS.get(from_state, ())
    if to_state not in allowed:
        raise LifecycleError(
            f"illegal lifecycle transition {from_state} -> {to_state}; "
            f"allowed from {from_state}: {list(allowed) or 'none'}")


def set_state(con: sqlite3.Connection, capability_id: str, to_state: str, *,
              reason: str = "", actor: str = "") -> dict[str, Any]:
    """Move a capability to a new lifecycle state, recording the transition.

    This is the LOW-LEVEL mover. The gate functions (`validate_capability`,
    `activate_capability`) decide whether a promotion is justified; this
    function only records that it was decided. It still refuses an illegal
    transition, because the illegal edge is illegal in the data too.
    """
    ensure_schema(con)
    if not capability_id:
        raise LifecycleError("a capability id is required")
    from_state = current_state(con, capability_id)
    _assert_transition(from_state, to_state)
    at = _now()
    con.execute(
        "INSERT INTO capability_lifecycle_transition"
        "(capability_id, from_state, to_state, reason, actor, at)"
        " VALUES (?,?,?,?,?,?)",
        (capability_id, from_state, to_state, reason, actor, at))
    con.execute(
        "INSERT INTO capability_lifecycle(capability_id, lifecycle, reason, "
        "updated_at) VALUES (?,?,?,?)"
        " ON CONFLICT(capability_id) DO UPDATE SET lifecycle=excluded.lifecycle,"
        " reason=excluded.reason, updated_at=excluded.updated_at",
        (capability_id, to_state, reason, at))
    con.commit()
    return {"capability_id": capability_id, "from": from_state, "to": to_state,
            "reason": reason, "actor": actor, "at": at}


# ---------------------------------------------------------------------------
# the gates
# ---------------------------------------------------------------------------

def validate_capability(con: sqlite3.Connection, capability_id: str, *,
                        spec: dict[str, Any] | None = None,
                        actor: str = "") -> dict[str, Any]:
    """The PROPOSED -> VALIDATED gate.

    `spec` is the capability's static manifest, as the runtime loaded it. The
    gate checks that the manifest is complete and that everything it names
    exists. It does NOT check whether the capability executes correctly --
    that is the ACTIVE gate's job, and separating the two is what lets a
    capability be "valid" while its execution test is still failing.
    """
    state = current_state(con, capability_id)
    if state == "ACTIVE":
        return {"capability_id": capability_id, "ok": True,
                "lifecycle": state,
                "note": "already Active; the validation gate is satisfied"}
    problems: list[str] = []
    spec = spec or {}
    if not spec:
        problems.append("no capability manifest was supplied")
    else:
        if not spec.get("id"):
            problems.append("manifest has no id")
        if not spec.get("path"):
            problems.append("manifest has no path")
        if spec.get("artifact_type") != "EXECUTABLE_CAPABILITY":
            problems.append(
                f"artifact_type is {spec.get('artifact_type')!r}, not "
                f"EXECUTABLE_CAPABILITY")
        required = spec.get("required_inputs") or []
        expected = spec.get("expected_outputs") or []
        if not required:
            problems.append("manifest declares no required_inputs")
        if not expected:
            problems.append("manifest declares no expected_outputs")
        if not spec.get("entrypoint"):
            problems.append("manifest declares no entrypoint")
    if problems:
        return {"capability_id": capability_id, "ok": False,
                "lifecycle": state, "problems": problems,
                "note": "validation gate not satisfied"}
    out = set_state(con, capability_id, "VALIDATED",
                    reason="static contract satisfied", actor=actor)
    out["ok"] = True
    out["problems"] = []
    return out


def activate_capability(con: sqlite3.Connection, capability_id: str, *,
                        routing: dict[str, Any] | None = None,
                        execution_ok: bool = False,
                        contract_ok: bool = False,
                        references_ok: bool = False,
                        replacement: str = "",
                        actor: str = "") -> dict[str, Any]:
    """The VALIDATED -> ACTIVE gate.

    All four conditions must hold:

      * `routing` reports at least `ACTIVATION_ROUTING_THRESHOLD` success on
        the labelled tasks that exercise this capability, AND the dataset
        actually covers it. A capability the dataset never exercises is
        `insufficiently_evaluated`, not Active.
      * `execution_ok` — the capability's execution test passed.
      * `contract_ok` — the capability's shared-contract test passed.
      * `references_ok` — the capability's references are intact.

    Every failure is named. The gate does not have a single "not yet" answer:
    it says which condition failed.
    """
    state = current_state(con, capability_id)
    if state == "ACTIVE":
        return {"capability_id": capability_id, "ok": True, "lifecycle": state,
                "note": "already Active"}
    if state != "VALIDATED":
        return {"capability_id": capability_id, "ok": False, "lifecycle": state,
                "problems": [
                    f"a capability must be VALIDATED before it can be ACTIVE; "
                    f"it is {state}"],
                "note": "activation gate not satisfied"}

    problems: list[str] = []
    evaluation = "insufficiently_evaluated"
    rate = 0.0
    if routing is None:
        problems.append("no routing evaluation was supplied")
    else:
        rate = float(routing.get("success_rate") or 0.0)
        covered = int(routing.get("covered_tasks") or 0)
        evaluation = str(routing.get("outcome")
                         or EVALUATION_OUTCOMES[1])
        if covered <= 0:
            problems.append(
                "the routing dataset does not exercise this capability, so "
                "its routing success cannot be measured")
        elif rate < ACTIVATION_ROUTING_THRESHOLD:
            problems.append(
                f"routing success {rate:.1%} is below the "
                f"{ACTIVATION_ROUTING_THRESHOLD:.0%} activation threshold")
        else:
            evaluation = "sufficiently_evaluated"
    if not execution_ok:
        problems.append("the capability's execution test has not passed")
    if not contract_ok:
        problems.append("the capability's shared-contract test has not passed")
    if not references_ok:
        problems.append("the capability's references are not intact")

    if problems:
        return {"capability_id": capability_id, "ok": False, "lifecycle": state,
                "problems": problems, "routing_success_rate": rate,
                "evaluation_outcome": evaluation,
                "note": "activation gate not satisfied"}

    out = set_state(con, capability_id, "ACTIVE",
                    reason=(f"routing {rate:.1%} over "
                            f"{routing.get('covered_tasks')} labelled task(s); "
                            f"execution, contract and references verified"),
                    actor=actor)
    out["ok"] = True
    out["routing_success_rate"] = rate
    out["evaluation_outcome"] = evaluation
    out["problems"] = []
    return out


def deprecate_capability(con: sqlite3.Connection, capability_id: str, *,
                         reason: str = "", replacement: str = "",
                         actor: str = "") -> dict[str, Any]:
    """The ACTIVE -> DEPRECATED gate.

    A deprecation names either a replacement that is itself ACTIVE, or an
    operator-supplied reason. A deprecated capability's original source is
    NOT deleted — deprecation is a routing decision, and the artifact remains
    in the corpus and in the migration map.
    """
    state = current_state(con, capability_id)
    if state == "DEPRECATED":
        return {"capability_id": capability_id, "ok": True, "lifecycle": state,
                "note": "already Deprecated"}
    if not reason:
        return {"capability_id": capability_id, "ok": False, "lifecycle": state,
                "problems": ["a deprecation requires a reason"],
                "note": "deprecation gate not satisfied"}
    if replacement:
        rep_state = current_state(con, replacement)
        if rep_state != "ACTIVE":
            return {"capability_id": capability_id, "ok": False,
                    "lifecycle": state,
                    "problems": [
                        f"replacement {replacement!r} is {rep_state}, not "
                        f"ACTIVE; a deprecated capability must point at a "
                        f"live one"],
                    "note": "deprecation gate not satisfied"}
    out = set_state(con, capability_id, "DEPRECATED",
                    reason=reason, actor=actor)
    out["ok"] = True
    if replacement:
        out["replacement"] = replacement
    return out


def dispatchable_states() -> tuple[str, ...]:
    """The lifecycle states a coordinator may dispatch.

    PROPOSED and DEPRECATED are excluded. VALIDATED is included: a
    VALIDATED capability has satisfied its static contract and is safe to
    run, and refusing to run it until it is Active would mean the Active gate
    — which requires an EXECUTION test — could never be reached, because the
    execution test is the thing that runs the capability.
    """
    return ("VALIDATED", "ACTIVE")


__all__ = [
    "SCHEMA",
    "ACTIVATION_ROUTING_THRESHOLD",
    "EVALUATION_OUTCOMES",
    "LifecycleError",
    "ensure_schema",
    "current_state",
    "state_of",
    "all_states",
    "transitions",
    "set_state",
    "validate_capability",
    "activate_capability",
    "deprecate_capability",
    "dispatchable_states",
]
