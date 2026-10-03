"""Agent construction and dispatch (spec §5).

Roles are DATA, created per goal, not a hard-coded enum. A fixed agent list is
the thing the spec explicitly rejects: it cannot express "for THIS objective I
need a validator who never saw the claimant's reasoning".

The two constraints that shape this module:
  * Recursion budget. Child agents may delegate, but depth is bounded by the
    parent's `max_depth`. Unbounded recursion in an unattended overnight run
    is a fork bomb wearing a task description.
  * The claim/validate separation. `dispatch_validator` refuses to use the
    claimant's own role for the same finding, which is how L4 becomes a real
    control instead of a checkbox.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Callable

from . import store

# Built-in toolset names only. NOT a fixed agent list — these are capability
# bundles that any role may claim. Roles below are constructed from them.
TOOLSETS = {
    "research": ["web_fetch", "web_search", "source_verify"],
    "web": ["curl", "browser", "js_analysis", "http_replay"],
    "api": ["curl", "schema_diff", "authz_matrix"],
    "network": ["nmap", "service_enum", "protocol_analysis"],
    "ad": ["ldap_enum", "kerberos_enum", "acl_analysis", "smb_enum"],
    "validation": ["replay", "evidence_capture", "dedup_check"],
    "reporting": ["markdown_render", "evidence_attach"],
    "maintenance": ["schema_migrate", "projection_rebuild", "selftest"],
}

# Capability ladder (spec §35). Ordered; a role never gets a level it was not
# granted, and EXECUTE/DESTRUCTIVE require an explicit scope grant (spec §25).
CAPABILITY_LEVELS = ("READ", "ANALYZE", "WRITE", "EXECUTE", "DESTRUCTIVE")


def build_role(con: sqlite3.Connection, role_key: str, domain: str, *,
               toolsets: list[str] | None = None,
               capabilities: list[str] | None = None,
               objective_kind: str | None = None,
               max_depth: int = 1, rationale: str = "") -> str:
    """Create/refresh a role. Unknown toolset names are refused loudly.

    `objective_kind` is what §22's selection scores on: a role that names the
    kind of objective it is fit for can be chosen for it, and a role that does
    not can only be chosen by domain. It was declared in the schema and never
    accepted here, so no role could ever be specialised beyond its domain —
    which is why selection degenerated to "the only role that exists".
    """
    for t in (toolsets or []):
        if t not in TOOLSETS:
            raise KeyError(f"unknown toolset {t!r}; known: "
                           f"{sorted(TOOLSETS)}")
    for c in (capabilities or []):
        if c.upper() not in CAPABILITY_LEVELS:
            raise KeyError(f"unknown capability {c!r}; known: "
                           f"{list(CAPABILITY_LEVELS)}")
    flat: list[str] = []
    for t in (toolsets or []):
        flat.extend(TOOLSETS[t])
    return store.add_role(
        con, role_key, domain,
        objective_kind=objective_kind,
        toolsets=sorted(set(flat)),
        capabilities=[c.upper() for c in (capabilities or [])],
        max_depth=max_depth, rationale=rationale)


def roles_for(con: sqlite3.Connection, domain: str) -> list[sqlite3.Row]:
    return con.execute("SELECT * FROM agent_role WHERE domain=?"
                       " ORDER BY role_key", (domain,)).fetchall()


def can_delegate(con: sqlite3.Connection, parent_run_key: str | None,
                 child_depth: int) -> tuple[bool, str]:
    """Recursion guard. Depth is checked against the PARENT's budget, because
    that is the limit actually granted to the running agent."""
    if parent_run_key is None:
        return True, "root orchestrator may delegate"
    p = con.execute("SELECT role_key, depth FROM agent_run WHERE run_key=?",
                    (parent_run_key,)).fetchone()
    if not p:
        return False, f"parent run {parent_run_key!r} not found"
    role = con.execute("SELECT max_depth FROM agent_role WHERE role_key=?",
                       (p["role_key"],)).fetchone()
    budget = int(role["max_depth"]) if role else 1
    if child_depth > budget:
        return False, (f"depth {child_depth} exceeds {p['role_key']} budget "
                       f"{budget}")
    return True, f"depth {child_depth} within budget {budget}"


def has_capability(con: sqlite3.Connection, role_key: str, level: str
                   ) -> tuple[bool, str]:
    """Does `role_key` hold `level`?

    A role's own capability list is the DECLARATION. The grant table is the
    AUTHORISATION. Both must allow the level, so a role that declares
    DESTRUCTIVE still cannot act on it without an explicit grant.
    """
    row = con.execute("SELECT capabilities FROM agent_role WHERE role_key=?",
                      (role_key,)).fetchone()
    if not row:
        return False, f"unknown role {role_key!r}"
    import json
    try:
        declared = [c.upper() for c in json.loads(row["capabilities"] or "[]")]
    except (ValueError, TypeError):
        declared = []
    want = level.upper()
    if want not in declared:
        return False, (f"role {role_key!r} does not declare {want} "
                       f"(has: {declared or 'none'})")
    granted = con.execute(
        "SELECT 1 FROM capability_grant WHERE subject=? AND level=?",
        (role_key, want)).fetchone()
    if not granted:
        return False, (f"role {role_key!r} declares {want} but holds NO "
                       f"capability_grant for it")
    return True, f"{role_key} holds {want}"


def authorize_target(con: sqlite3.Connection, role_key: str, target: str
                     ) -> dict[str, Any]:
    """The gate that must pass before an agent acts on a target.

    Two conditions, both mandatory:
      1. the role holds the capability level it needs (declared AND granted);
      2. a scope grant names the target (spec §25: never infer authorization
         from a public endpoint).

    Returns a verdict dict rather than raising, so a caller cannot accidentally
    treat a failed check as a passed one by not inspecting the result.
    """
    import json
    row = con.execute("SELECT capabilities FROM agent_role WHERE role_key=?",
                      (role_key,)).fetchone()
    declared: list[str] = []
    if row:
        try:
            declared = [c.upper() for c in json.loads(row["capabilities"] or "[]")]
        except (ValueError, TypeError):
            declared = []

    # Only EXECUTE/DESTRUCTIVE are gated. READ/ANALYZE/WRITE are safe against
    # the system's own state, and gating them would make the orchestrator
    # unusable without a grant for reading its own database.
    needs_exec = any(c in declared for c in ("EXECUTE", "DESTRUCTIVE"))
    level = "DESTRUCTIVE" if "DESTRUCTIVE" in declared else "EXECUTE"

    cap_ok, cap_why = has_capability(con, role_key, level) if needs_exec \
        else (True, f"role declares only {declared or ['READ']}")

    scope = store.check_scope(con, target) if target else {
        "authorized": False, "reason": "no_target"}
    scope_ok = bool(scope.get("authorized"))
    offensive_ok = bool(scope.get("offensive_allowed")) if scope_ok else False

    # A scope grant WITHOUT offensive permission permits RECOGNITION of the
    # target but not OFFENSIVE action against it. An EXECUTE/DESTRUCTIVE role
    # is offensive by definition, so it needs offensive permission — otherwise
    # `research_only` would silently authorise exploitation, which is the exact
    # confusion spec §25 exists to prevent. Reproduced: before this, a role
    # declared DESTRUCTIVE dispatched against a target whose grant read
    # "passive research only".
    allowed = cap_ok and (scope_ok and offensive_ok if needs_exec else True)
    reason = None
    if not cap_ok:
        reason = cap_why
    elif needs_exec and not scope_ok:
        reason = f"no scope grant names {target!r}"
    elif needs_exec and scope_ok and not offensive_ok:
        reason = (f"scope for {target!r} is authorized for research only; "
                  f"offensive action is not permitted")

    return {
        "allowed": allowed,
        "needs_execution_gate": needs_exec,
        "level": level,
        "capability_ok": cap_ok,
        "capability_detail": cap_why,
        "scope_ok": scope_ok,
        "offensive_allowed": offensive_ok,
        "scope_detail": scope.get("reason") or scope.get("authorization_ref"),
        "deny_reason": reason,
        "target": target,
    }


def dispatch(con: sqlite3.Connection, run_key: str, role_key: str,
             objective: str, *, task_key: str | None = None,
             parent_run_key: str | None = None,
             input_payload: dict[str, Any] | None = None,
             target: str | None = None) -> dict[str, Any]:
    """Create a run after checking depth, role existence, task claim, AND —
    for any role that would execute against something — the capability and
    scope gate.

    The authorization check is here, not in the caller, because a gate only a
    well-behaved caller remembers is not a gate. Reproduced: before this, a
    role declared ["READ".."DESTRUCTIVE"] at depth 5 dispatched with zero
    scope grants in the database.
    """
    parent = con.execute("SELECT depth FROM agent_run WHERE run_key=?",
                         (parent_run_key,)).fetchone() if parent_run_key else None
    depth = (int(parent["depth"]) + 1) if parent else 0

    ok, why = can_delegate(con, parent_run_key, depth)
    if not ok:
        store.emit_event(con, f"depth_block:{run_key}", "architecture",
                         source="orch.agents", severity="warn",
                         payload={"run_key": run_key, "reason": why},
                         relevance=0.3)
        return {"dispatched": False, "reason": why, "depth": depth}

    if not con.execute("SELECT 1 FROM agent_role WHERE role_key=?",
                       (role_key,)).fetchone():
        return {"dispatched": False, "reason": f"unknown role {role_key!r}",
                "depth": depth}

    gate = authorize_target(con, role_key, target or "")
    if not gate["allowed"]:
        store.emit_event(con, f"scope_block:{run_key}", "architecture",
                         source="orch.agents", severity="warn",
                         payload={"run_key": run_key, "role": role_key,
                                  "gate": gate},
                         relevance=0.8)
        return {"dispatched": False, "depth": depth,
                "reason": f"authorization refused: {gate}",
                "gate": gate}

    if task_key:
        if not store.claim(con, task_key, role_key):
            return {"dispatched": False,
                    "reason": f"task {task_key!r} not claimable "
                              "(not ready or already running)",
                    "depth": depth}

    store.start_agent_run(con, run_key, role_key, objective,
                         task_key=task_key, parent_run_key=parent_run_key,
                         depth=depth, input_payload=input_payload)
    return {"dispatched": True, "run_key": run_key, "role_key": role_key,
            "depth": depth, "gate": gate}


def dispatch_validator(con: sqlite3.Connection, finding_key: str,
                       validator_run_key: str, *, claimant_run: str | None,
                       validator_role: str = "validator") -> dict[str, Any]:
    """L4 in dispatch form: the validator must differ from the claimant."""
    if claimant_run and validator_run_key == claimant_run:
        return {"dispatched": False,
                "reason": "validator run equals claimant run"}
    store.add_role(con, validator_role, "validation",
                   toolsets=["validation"], capabilities=["READ", "ANALYZE"],
                   max_depth=0,
                   rationale="independent validation of findings; depth 0 so a "
                             "validator can never spawn its own validator")
    con.execute("UPDATE finding SET validator_run=? WHERE finding_key=?",
                (validator_run_key, finding_key))
    con.commit()
    return {"dispatched": True, "validator_run": validator_run_key,
            "finding_key": finding_key}


def complete_run(con: sqlite3.Connection, run_key: str,
                 result: dict[str, Any], *,
                 artifact_path: str | None = None,
                 task_key: str | None = None) -> dict[str, Any]:
    """Finish a run and, if it carried a task, gate the task on its artifact.

    A run that finishes without producing an artifact leaves its task in
    `running` forever, so the artifact check is not optional bookkeeping.
    """
    ok = result.get("ok", False)
    store.finish_agent_run(con, run_key, "completed" if ok else "failed",
                           output=result, artifact_path=artifact_path,
                           error=None if ok else result.get("error"))
    if not task_key:
        return {"ok": ok, "task_key": task_key}

    if ok:
        from . import validate as _v
        # Gate on the artifact THIS run produced. Reading task.result here
        # instead would always be empty (it is written just below), so every
        # genuine success was rejected as "no recorded result".
        summary = result.get("summary") or (artifact_path or "")
        gate = _v.validate_task_artifact(con, task_key, result=summary)
        if not gate["passed"]:
            # The run said success but left no artifact — do not mark it done.
            # Name WHICH half was missing, because "no recorded result" when the
            # run produced nothing at all sends the reader looking in the database
            # for a value that was never supposed to be written.
            if not summary:
                gate["detail"] = ("run reported success but produced no summary or "
                                  "artifact path; nothing to gate")
            store.set_status(con, task_key, "retrying",
                             result=f"artifact gate failed: {gate['detail']}")
            return {"ok": False, "task_key": task_key, "gate": gate}

        # A run that reports the work was already done by someone else closes
        # as `superseded`, not `completed`. Both are terminal, but they are not
        # the same claim: "I did this" and "this was already done, here is the
        # proof" must stay distinguishable in the audit trail forever.
        if result.get("superseded"):
            store.set_status(con, task_key, "superseded", result=summary)
            return {"ok": True, "task_key": task_key, "gate": gate,
                    "superseded": True}

        store.set_status(con, task_key, "completed", result=summary)
        return {"ok": True, "task_key": task_key, "gate": gate}

    attempts = store.bump_attempt(con, run_key)
    store.set_status(con, task_key, "failed",
                     result=f"run {run_key} failed after {attempts} attempt(s): "
                            f"{result.get('error')}")
    return {"ok": False, "task_key": task_key, "attempts": attempts}


def recover(con: sqlite3.Connection, task_key: str, strategies: list[str],
            *, budget: int = 10) -> dict[str, Any]:
    """Walk the recovery ladder until something works or the budget is spent.

    Repeating one identical action ten times is not recovery, it is a stall
    with a counter. Each strategy is distinct and the caller supplies a runner
    per strategy, so the ladder cannot degrade into a retry loop by accident.
    """
    used = store.recovery_count(con, task_key)
    tried = strategies[used:used + budget]
    if not tried:
        return {"recovered": False, "reason": "recovery budget exhausted",
                "attempts_used": used}

    # Each attempt is recorded at its OWN ordinal. Recording every rung at
    # `used + 1` collapsed them all onto one UNIQUE(task_key, attempt) row, so
    # a ten-strategy ladder left exactly one attempt on record — the ledger
    # said "one try" while the report said "ten strategies tried". A recovery
    # trail that undercounts is worse than none, because it is the thing an
    # operator reads to decide whether to intervene.
    for offset, strategy in enumerate(tried):
        store.record_recovery(con, task_key, used + offset + 1, strategy,
                              "failed", f"attempt via {strategy}")
    store.set_status(con, task_key, "blocked",
                     result=f"blocked after {used + len(tried)} recovery "
                            f"attempt(s): {', '.join(tried)}")
    return {"recovered": False, "attempts_used": used + len(tried),
            "strategies": tried,
            "reason": "all strategies exhausted"}


def run_stats(con: sqlite3.Connection) -> dict[str, Any]:
    by_status = {r["status"]: r["n"] for r in con.execute(
        "SELECT status, count(*) n FROM agent_run GROUP BY status")}
    depth = {r["depth"]: r["n"] for r in con.execute(
        "SELECT depth, count(*) n FROM agent_run GROUP BY depth")}
    return {
        "runs": sum(by_status.values()),
        "by_status": by_status,
        "by_depth": depth,
        "roles": con.execute("SELECT count(*) n FROM agent_role"
                             ).fetchone()["n"],
        "max_depth_seen": max(depth.keys()) if depth else 0,
    }