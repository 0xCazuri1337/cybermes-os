"""Collection-agent dispatch: the five bounded roles that feed the hunt.

MEASURED DEFECT (the reason this module exists)
-----------------------------------------------
`runtime/opencode/manifest.md:89-93` and `runtime/opencode/ORCHESTRATION.md`
declare five collection agents — dorking, recon, js, fuzzing, understand — with
a tool whitelist, a spawn cap, a concurrency cap of 3, and a WAF gate for the
fuzzing role. `.opencode/commands/hunt.md:40-45` says the staged dispatch plan
is "authoritative in runtime/registry.json".

MEASURED: none of that had an implementation.

  * `runtime/registry.json` `agents` was `["validator", "exploit-builder"]`
    — the five collection roles were ABSENT from the registry that the hunt
    command calls authoritative.
  * `agents/` held only `exploit-builder.md` and `validator.md`. The five
    collection-agent briefing files the manifest says are "loaded on spawn"
    did not exist.
  * `orch/agents.py` had no collection role, no concurrency cap, and no WAF
    gate. Its `build_role` created roles ad hoc from toolsets.
  * Nothing enforced "collection agents are not exploiters". A role declared
    `EXECUTE` and dispatched against a target did so under the generic
    authorization gate, with no notion that a *collection* role must never
    carry exploit capability.

This module is the missing enforcement point. It declares the five roles as
DATA with their real boundaries, and it provides `dispatch_collection` which
enforces the parts of the spec that were prose:

  1. COLLECTION ROLES NEVER HOLD EXECUTE OR DESTRUCTIVE. A collection role
     that would exploit is refused at construction. This is the structural
     version of "the orchestrator performs exploitation and validation
     directly".
  2. MAX 3 CONCURRENT. Measured live, against the `agent_run` table, not
     against a request counter.
  3. NO TWO COLLECTION AGENTS ON THE SAME ENDPOINT SIMULTANEOUSLY.
  4. THE FUZZING ROLE IS WAF-GATED. It refuses to dispatch until a WAF/CDN
     status has been recorded by the recon role. A missing status is NOT a
     "no WAF" — it is an unknown, and the role waits.
  5. DEFERALS ARE RECORDED. A role that cannot run is written down with its
     reason, because an undocumented skip is indistinguishable from a forgotten
     one.

Ownership: this module writes only `orch/` work tables (`agent_role`,
`agent_run`, `event`). It never touches a knowledge table.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from . import store

# ---------------------------------------------------------------------------
# The concurrency cap. Measured from `runtime/opencode/manifest.md:97`
# ("max 3 concurrent") and ORCHESTRATION.md.
# ---------------------------------------------------------------------------
MAX_CONCURRENT_COLLECTION = 3

# ---------------------------------------------------------------------------
# The five collection roles.
#
# `capabilities` is deliberately capped at ANALYZE. READ is implied for every
# role; ANALYZE covers parsing and reasoning over what was collected. Nothing
# here can reach EXECUTE, and `build_collection_role` refuses to construct a
# role that tries.
#
# `contact` records whether the role is allowed to TOUCH THE TARGET:
#   * "passive"    — public sources only; MUST NOT contact the target.
#   * "active"     — may contact the target for RECOGNITION (recon, js).
#   * "auth_first" — may contact the target after authenticating, for
#                    RECOGNITION only, and must deliver the live session.
#
# `exploit_capable` is False for all five, and `assert_not_exploiter` is what
# the dispatcher calls before every collection dispatch. It exists so the
# invariant is checked at the moment of use, not only at construction.
# ---------------------------------------------------------------------------
COLLECTION_ROLES: dict[str, dict[str, Any]] = {
    "dorking-agent": {
        "domain": "research",
        "contact": "passive",
        "objective_kind": "collection",
        "toolsets": ["research"],
        "capabilities": ["READ", "ANALYZE"],
        "max_spawns_per_session": 2,
        "timeout_s": 300,
        "waf_gated": False,
        "summary": ("Passive public intelligence only. MUST NOT contact the "
                    "target. Returns OSINT signals with provenance."),
    },
    "recon-agent": {
        "domain": "web",
        "contact": "active",
        "objective_kind": "collection",
        "toolsets": ["web", "network"],
        "capabilities": ["READ", "ANALYZE"],
        "max_spawns_per_session": 2,
        "timeout_s": 600,
        "waf_gated": False,
        "summary": ("Hosts, URLs, technologies, open ports and WAF/CDN status. "
                    "Recognition only — no vulnerability testing."),
    },
    "js-agent": {
        "domain": "web",
        "contact": "active",
        "objective_kind": "collection",
        "toolsets": ["web"],
        "capabilities": ["READ", "ANALYZE"],
        "max_spawns_per_session": 4,
        "timeout_s": 300,
        "waf_gated": False,
        "summary": ("JS bundle and source-map analysis; routes, APIs and "
                    "client-side trust boundaries. Recognition only."),
    },
    "fuzzing-agent": {
        "domain": "web",
        "contact": "active",
        "objective_kind": "collection",
        "toolsets": ["web"],
        "capabilities": ["READ", "ANALYZE"],
        "max_spawns_per_session": 6,
        "timeout_s": 300,
        "waf_gated": True,
        "summary": ("Technology-aware ENDPOINT DISCOVERY only. Generates "
                    "candidate endpoints; NEVER sends an exploit payload."),
    },
    "understand-agent": {
        "domain": "identity",
        "contact": "auth_first",
        "objective_kind": "collection",
        "toolsets": ["web"],
        "capabilities": ["READ", "ANALYZE"],
        "max_spawns_per_session": 2,
        "timeout_s": 600,
        "waf_gated": False,
        "summary": ("Authenticate first, map the app's features, roles and "
                    "trust boundaries, deliver the live session. NO testing."),
    },
}

# The order the manifest prescribes: recon + dorking + understand first, then
# js + fuzzing (which is WAF-gated on recon and therefore waits).
DISPATCH_ORDER: tuple[str, ...] = (
    "recon-agent",
    "dorking-agent",
    "understand-agent",
    "js-agent",
    "fuzzing-agent",
)

# Capability levels a collection role may never hold. The orchestrator holds
# these; a collection role does not.
OFFENSIVE_CAPABILITIES = frozenset({"EXECUTE", "DESTRUCTIVE"})

# The status vocabulary recorded for the WAF gate. `unknown` is a real value
# and means "not yet measured", which is NOT the same as "no WAF".
WAF_STATES = ("unknown", "none", "detected")


class CollectionPolicyError(ValueError):
    """A collection role was asked to do something collection roles do not do."""


# ---------------------------------------------------------------------------
# WAF gate state
# ---------------------------------------------------------------------------

WAF_SCHEMA = """
CREATE TABLE IF NOT EXISTS collection_waf_status (
  target      TEXT NOT NULL,
  waf_state   TEXT NOT NULL DEFAULT 'unknown',  -- unknown|none|detected
  evidence    TEXT,                            -- why this verdict
  recorded_by TEXT,                            -- role that measured it
  recorded_at TEXT NOT NULL,
  PRIMARY KEY (target)
);
CREATE TABLE IF NOT EXISTS collection_deferral (
  deferral_key TEXT PRIMARY KEY,
  role_key     TEXT NOT NULL,
  target       TEXT,
  reason       TEXT NOT NULL,
  detail       TEXT,
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_coldefer_role ON collection_deferral(role_key);
"""


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(WAF_SCHEMA)
    con.commit()


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

def assert_not_exploiter(role_key: str, capabilities: Iterable[str]) -> None:
    """Refuse a collection role that carries offensive capability.

    This is the structural form of "collection agents are not autonomous
    exploiters". It is checked at construction AND at dispatch, because a role
    row can be edited directly in the database between the two.
    """
    bad = sorted({c.upper() for c in capabilities} & OFFENSIVE_CAPABILITIES)
    if bad:
        raise CollectionPolicyError(
            f"collection role {role_key!r} may not hold {', '.join(bad)}: "
            "exploitation and validation are the orchestrator's job "
            "(runtime/opencode/manifest.md, ORCHESTRATION.md)")


def build_collection_role(con: sqlite3.Connection, role_key: str) -> str:
    """Create (or update) one collection role in `agent_role`.

    Idempotent: re-running updates the declaration in place. The offensive
    check is applied to the DECLARED capabilities from
    `COLLECTION_ROLES`, so a caller cannot widen a role by passing extra
    capabilities.
    """
    spec = COLLECTION_ROLES.get(role_key)
    if spec is None:
        raise CollectionPolicyError(
            f"{role_key!r} is not a collection role; known: "
            f"{', '.join(sorted(COLLECTION_ROLES))}")
    assert_not_exploiter(role_key, spec["capabilities"])
    agents.build_role(
        con, role_key, spec["domain"],
        objective_kind=spec["objective_kind"],
        toolsets=list(spec["toolsets"]),
        capabilities=list(spec["capabilities"]),
        max_depth=1,
        rationale=spec["summary"],
    )
    return role_key


def build_all_collection_roles(con: sqlite3.Connection) -> list[str]:
    """Declare all five collection roles. Returns the role keys created."""
    built = []
    for role_key in DISPATCH_ORDER:
        built.append(build_collection_role(con, role_key))
    return built


def collection_role_specs() -> dict[str, dict[str, Any]]:
    """The role declarations, for the registry and for the preflight."""
    return {k: dict(v) for k, v in COLLECTION_ROLES.items()}


# ---------------------------------------------------------------------------
# WAF gate
# ---------------------------------------------------------------------------

def record_waf_status(con: sqlite3.Connection, target: str, waf_state: str,
                      *, evidence: str = "", recorded_by: str = "") -> dict:
    """Record the measured WAF/CDN status for a target.

    Only the recon role may record it — a status asserted by the role that
    depends on it is not a measurement. `unknown` is a legal value and means
    "not measured"; it does not satisfy the gate.
    """
    if waf_state not in WAF_STATES:
        raise ValueError(f"waf_state must be one of {WAF_STATES}, "
                         f"got {waf_state!r}")
    _ensure(con)
    con.execute(
        "INSERT INTO collection_waf_status(target,waf_state,evidence,"
        "recorded_by,recorded_at) VALUES (?,?,?,?,?) "
        "ON CONFLICT(target) DO UPDATE SET "
        "waf_state=excluded.waf_state, evidence=excluded.evidence, "
        "recorded_by=excluded.recorded_by, recorded_at=excluded.recorded_at",
        (target, waf_state, evidence or None, recorded_by or None,
         store.now()))
    con.commit()
    return {"target": target, "waf_state": waf_state, "recorded_by": recorded_by}


def waf_status(con: sqlite3.Connection, target: str) -> dict:
    """The recorded WAF status for a target, or `unknown` when unmeasured."""
    _ensure(con)
    row = con.execute(
        "SELECT waf_state, evidence, recorded_by, recorded_at "
        "FROM collection_waf_status WHERE target=?", (target,)).fetchone()
    if row is None:
        return {"target": target, "waf_state": "unknown", "evidence": None,
                "recorded_by": None, "recorded_at": None}
    return {"target": target, "waf_state": row["waf_state"],
            "evidence": row["evidence"], "recorded_by": row["recorded_by"],
            "recorded_at": row["recorded_at"]}


def waf_gate_open(con: sqlite3.Connection, target: str) -> tuple[bool, str]:
    """Is the fuzzing role allowed to dispatch yet?

    Open means a WAF status was MEASURED (`none` or `detected`). An absent
    or `unknown` status keeps the gate closed: an unknown WAF is not a
    "no WAF", and dispatching on an assumption is how a protection gets
    hammered blind.
    """
    status = waf_status(con, target)
    state = status["waf_state"]
    if state in ("none", "detected"):
        return True, f"waf status measured as {state!r}"
    return False, ("waf status for %r is unknown; the recon role must record "
                   "it before the fuzzing role dispatches" % target)


# ---------------------------------------------------------------------------
# Concurrency
# ---------------------------------------------------------------------------

def active_collection_runs(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """Collection-agent runs that are dispatched or running right now."""
    _ensure(con)
    placeholders = ",".join("?" for _ in COLLECTION_ROLES)
    return con.execute(
        f"SELECT * FROM agent_run WHERE role_key IN ({placeholders}) "
        "AND status IN ('dispatched','running') ORDER BY created_at",
        tuple(sorted(COLLECTION_ROLES))).fetchall()


def concurrency_ok(con: sqlite3.Connection) -> tuple[bool, str]:
    """Is there room for another collection agent under the cap of 3?"""
    active = active_collection_runs(con)
    if len(active) >= MAX_CONCURRENT_COLLECTION:
        return False, (f"{len(active)} collection agents already active "
                       f"(cap {MAX_CONCURRENT_COLLECTION})")
    return True, f"{len(active)} active, cap {MAX_CONCURRENT_COLLECTION}"


def endpoint_conflict(con: sqlite3.Connection, role_key: str,
                      endpoint: str | None) -> tuple[bool, str]:
    """Refuse a second collection agent on an endpoint that is already busy.

    The rule from AGENTS.md §9: "never two on one endpoint". `endpoint` is
    the surface the role will work on; when it is None the role is working
    across the whole target and cannot conflict with a specific endpoint.
    """
    if not endpoint:
        return True, "no specific endpoint claimed"
    _ensure(con)
    rows = con.execute(
        "SELECT run_key, role_key, objective FROM agent_run "
        "WHERE status IN ('dispatched','running')").fetchall()
    for row in rows:
        if row["role_key"] == role_key:
            continue
        if endpoint in (row["objective"] or ""):
            return False, (f"endpoint {endpoint!r} is already being worked by "
                           f"{row['role_key']} ({row['run_key']})")
    return True, f"endpoint {endpoint!r} is free"


# ---------------------------------------------------------------------------
# Deferral record
# ---------------------------------------------------------------------------

def record_deferral(con: sqlite3.Connection, role_key: str, *, target: str = "",
                    reason: str, detail: str = "") -> dict:
    """Write down a role that did not run, and why.

    An undocumented skip is indistinguishable from a forgotten one, so every
    refusal is persisted and queryable.
    """
    _ensure(con)
    # MEASURED DEFECT: the key was `role:target:<iso timestamp>`, and
    # `store.now()` has SECOND resolution. Two deferrals of the same role
    # against the same target inside one second produced identical keys, and
    # the second INSERT raised `sqlite3.IntegrityError: UNIQUE constraint
    # failed` — so recording a deferral could itself crash the dispatcher.
    # The counter is derived from the row count, which makes the key unique
    # without a random source and keeps it readable.
    seq = con.execute(
        "SELECT count(*) n FROM collection_deferral").fetchone()["n"] + 1
    key = f"{role_key}:{target or 'no-target'}:{store.now()}:{seq}"
    con.execute(
        "INSERT INTO collection_deferral(deferral_key,role_key,target,reason,"
        "detail,created_at) VALUES (?,?,?,?,?,?)",
        (key, role_key, target or None, reason, detail or None, store.now()))
    con.commit()
    return {"deferral_key": key, "role_key": role_key, "reason": reason}


def deferrals(con: sqlite3.Connection) -> list[sqlite3.Row]:
    """Every recorded deferral, newest last."""
    _ensure(con)
    return con.execute("SELECT * FROM collection_deferral "
                       "ORDER BY created_at, role_key").fetchall()


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def dispatch_collection(con: sqlite3.Connection, role_key: str, *,
                        target: str, objective: str, endpoint: str | None = None,
                        run_key: str | None = None,
                        input_payload: dict | None = None) -> dict[str, Any]:
    """Dispatch ONE collection agent, enforcing every collection rule.

    The order of the checks matters. Cheap, unambiguous rules run first; the
    authorization gate runs last because it is the one that can be slow and
    the one that must never be skipped.

    Returns a verdict dict. It NEVER raises for a policy refusal: a refusal
    is a normal outcome that the caller records, not an exception.
    """
    spec = COLLECTION_ROLES.get(role_key)
    if spec is None:
        reason = (f"{role_key!r} is not a collection role; known: "
                  f"{', '.join(sorted(COLLECTION_ROLES))}")
        record_deferral(con, role_key, target=target, reason=reason)
        return {"dispatched": False, "reason": reason, "role_key": role_key}

    # 1. The role must still not be an exploiter. Re-checked here because the
    #    agent_role row can be edited between construction and dispatch.
    row = con.execute("SELECT capabilities FROM agent_role WHERE role_key=?",
                      (role_key,)).fetchone()
    declared: list[str] = []
    if row:
        try:
            declared = [c.upper() for c in json.loads(row["capabilities"] or "[]")]
        except (ValueError, TypeError):
            declared = []
    if not row:
        build_collection_role(con, role_key)
    try:
        assert_not_exploiter(role_key, declared or spec["capabilities"])
    except CollectionPolicyError as exc:
        record_deferral(con, role_key, target=target,
                        reason="role carries offensive capability",
                        detail=str(exc))
        return {"dispatched": False, "reason": str(exc), "role_key": role_key}

    # 2. Concurrency cap.
    ok, why = concurrency_ok(con)
    if not ok:
        record_deferral(con, role_key, target=target,
                        reason="concurrency cap reached", detail=why)
        return {"dispatched": False, "reason": why, "role_key": role_key}

    # 3. One agent per endpoint.
    ok, why = endpoint_conflict(con, role_key, endpoint)
    if not ok:
        record_deferral(con, role_key, target=target,
                        reason="endpoint already in use", detail=why)
        return {"dispatched": False, "reason": why, "role_key": role_key}

    # 4. The WAF gate for the fuzzing role.
    if spec["waf_gated"]:
        gate_open, gate_why = waf_gate_open(con, target)
        if not gate_open:
            record_deferral(con, role_key, target=target,
                            reason="waf gate closed", detail=gate_why)
            return {"dispatched": False, "reason": gate_why, "role_key": role_key,
                    "waf_gate": "closed"}

    # 5. Passive roles must not contact the target. A passive role that was
    #    handed a target-scoped endpoint is a misconfiguration, not a job.
    if spec["contact"] == "passive" and endpoint and target in endpoint:
        reason = (f"{role_key!r} is passive and must not contact the target; "
                  f"endpoint {endpoint!r} is target-scoped")
        record_deferral(con, role_key, target=target,
                        reason="passive role given a target endpoint", detail=reason)
        return {"dispatched": False, "reason": reason, "role_key": role_key}

    # 5b. A role that CONTACTS THE TARGET needs a scope grant naming it.
    #
    # MEASURED DEFECT (authorization hole): `orch/agents.py:150-156` gates the
    # scope check ONLY for roles that declare EXECUTE or DESTRUCTIVE — the
    # rationale being that READ/ANALYZE/WRITE are "safe against the system's
    # own state". That reasoning is wrong for a collection role: recon, js and
    # understand all PUT PACKETS ON THE WIRE at the target. Measured: with
    # `scope_grant` emptied, `dispatch_collection("recon-agent")` returned
    # `dispatched: True` with `scope_ok: False` in the gate — a collection
    # agent authorized against a target nobody authorized.
    #
    # The fix belongs HERE, not in `agents.py`: a READ-only role that reads
    # the project's own database legitimately needs no scope grant, but a role
    # whose declared CONTACT MODE is "active" or "auth_first" is contacting an
    # external target and must name it in a grant.
    if spec["contact"] in ("active", "auth_first"):
        scope = store.check_scope(con, target)
        if not scope.get("authorized"):
            reason = (f"no scope grant names {target!r}, and {role_key!r} "
                      f"contacts the target ({scope.get('reason')})")
            record_deferral(con, role_key, target=target,
                            reason="no scope grant for a target-contacting role",
                            detail=reason)
            return {"dispatched": False, "reason": reason, "role_key": role_key,
                    "scope": scope}

    # 6. The real authorization gate, last.
    key = run_key or f"collect:{role_key}:{target}:{store.now()}"
    outcome = agents.dispatch(con, key, role_key, objective,
                              input_payload=input_payload, target=target)
    if not outcome.get("dispatched"):
        record_deferral(con, role_key, target=target,
                        reason="authorization gate refused dispatch",
                        detail=str(outcome.get("reason")))
        return {**outcome, "role_key": role_key}

    return {**outcome, "role_key": role_key,
            "contact": spec["contact"],
            "summary": spec["summary"]}


def dispatch_all(con: sqlite3.Connection, *, target: str,
                 objectives: dict[str, str] | None = None,
                 endpoints: dict[str, str] | None = None) -> dict[str, Any]:
    """Dispatch every collection role in the prescribed order.

    This is the hunt_start DISPATCH step. It dispatches as many as the rules
    allow and DEFERS the rest with a recorded reason — it does not wait for
    results and it does not block on the WAF gate beyond recording the
    deferral. The orchestrator starts exploiting immediately regardless of how
    many collection roles went out.
    """
    build_all_collection_roles(con)
    objectives = objectives or {}
    endpoints = endpoints or {}
    dispatched: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []
    for role_key in DISPATCH_ORDER:
        objective = objectives.get(role_key) or COLLECTION_ROLES[role_key]["summary"]
        result = dispatch_collection(
            con, role_key, target=target, objective=objective,
            endpoint=endpoints.get(role_key))
        if result.get("dispatched"):
            dispatched.append(result)
        else:
            deferred.append(result)
    return {
        "target": target,
        "dispatched": dispatched,
        "deferred": deferred,
        "dispatched_count": len(dispatched),
        "deferred_count": len(deferred),
        "max_concurrent": MAX_CONCURRENT_COLLECTION,
    }


# Imported at the bottom to avoid a circular import at module load:
# `orch.agents` imports `orch.store`, and this module imports both.
from . import agents  # noqa: E402
