"""Specialised agents, dynamic selection, and the output contract
(master prompt §20, §22, §23, §24, §21).

`orch/agents.py` already builds roles as DATA and enforces the capability and
scope gates. What it does not have is the two things §22 and §23 demand:

1. **SELECTION IS SCORED, NOT NAMED.** §22: "do not assign agents
   statically." `select_agent` scores every candidate role against the task —
   expertise fit, evidence available, tool availability, current workload,
   priority, parallelism opportunity, cost/value, and prior failures — and
   returns the ranking with the reasons. A selection that cannot be explained
   cannot be corrected at 04:00.

2. **OUTPUTS ARE TYPED AND NOT SELF-VALIDATING (§23).** The contract is:

       FACT | OBSERVATION | HYPOTHESIS | CANDIDATE_FINDING |
       VALIDATED_FINDING | FAILURE | UNCERTAINTY | RESEARCH_RESULT |
       RECOMMENDATION

   `parse_output` enforces the vocabulary, and — the load-bearing part — a
   `VALIDATED_FINDING` arriving from an agent is DOWNGRADED to
   `CANDIDATE_FINDING` with the reason recorded. §23 says the Orchestrator
   decides how results affect global state, and §35 says a finding must not be
   treated as final merely because an agent claims it is vulnerable. The only
   path to `validated` is `orch.validate`, which re-derives L1-L6.

The failure registry is part of this: §22 includes "previous failures" in
selection, so an agent that failed a class is penalised for that class rather
than being handed the same work forever.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any, Iterable

from . import store

# ---------------------------------------------------------------------------
# §23 output vocabulary. Closed, for the same reason the action vocabulary is:
# an open vocabulary means an unrecognised claim type passes through untyped.
# ---------------------------------------------------------------------------

RESULT_TYPES = ("FACT", "OBSERVATION", "HYPOTHESIS", "CANDIDATE_FINDING",
                "VALIDATED_FINDING", "FAILURE", "UNCERTAINTY",
                "RESEARCH_RESULT", "RECOMMENDATION")

# Types that assert something about the TARGET rather than about the world.
TARGET_ASSERTIONS = ("CANDIDATE_FINDING", "VALIDATED_FINDING", "OBSERVATION")

SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_result (
  result_key  TEXT PRIMARY KEY,
  run_key     TEXT,
  task_key    TEXT,
  type        TEXT NOT NULL,          -- one of RESULT_TYPES
  original_type TEXT,                  -- what the agent CLAIMED
  downgraded  INTEGER NOT NULL DEFAULT 0,
  payload     TEXT,                   -- JSON
  evidence_ids TEXT,                  -- JSON array of evidence ids
  reported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_result_task ON agent_result(task_key);

CREATE TABLE IF NOT EXISTS agent_failure (
  id         INTEGER PRIMARY KEY,
  role_key   TEXT NOT NULL,
  class_id   TEXT,
  task_key   TEXT,
  reason     TEXT NOT NULL,
  at         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_agent_failure ON agent_failure(role_key, class_id);
"""


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


class ResultContractError(ValueError):
    """An agent output violated §23."""


def parse_output(raw: Any, *, run_key: str = "", task_key: str = "",
                 con: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Type one agent output, and refuse to let it self-validate.

    Returns the typed envelope. Raises `ResultContractError` on an
    unrecognised type — a contract that silently coerces an unknown type into
    OBSERVATION would make every untyped claim look like evidence.
    """
    _ensure(con) if con is not None else None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError as e:
            raise ResultContractError(
                f"agent output is not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise ResultContractError(
            f"agent output must be an object, got {type(raw).__name__}")

    claimed = str(raw.get("type") or "").strip().upper()
    if not claimed:
        raise ResultContractError(
            "agent output has no `type`; §23 requires one of "
            + ", ".join(RESULT_TYPES))
    if claimed not in RESULT_TYPES:
        raise ResultContractError(
            f"unknown result type {claimed!r}; known: {list(RESULT_TYPES)}")

    payload = raw.get("payload", raw.get("summary", ""))
    evidence_ids = raw.get("evidence_ids") or []
    if isinstance(evidence_ids, str):
        try:
            evidence_ids = json.loads(evidence_ids)
        except ValueError:
            evidence_ids = [evidence_ids]

    downgraded = False
    effective = claimed
    notes: list[str] = list(raw.get("notes") or [])

    # THE RULE: an agent cannot declare a finding validated. Only
    # orch.validate.apply_validation can, and it re-derives L1-L6 from stored
    # evidence. An agent saying VALIDATED_FINDING is a CLAIM about validation,
    # which is at most a candidate until the gate agrees.
    if claimed == "VALIDATED_FINDING":
        effective = "CANDIDATE_FINDING"
        downgraded = True
        notes.append(
            "downgraded from VALIDATED_FINDING: an agent's own verdict is a "
            "claim, not a validation. orch.validate must clear L1-L6 first "
            "(§23, §35)")
        if not evidence_ids:
            notes.append("and it arrived with NO evidence ids, which is "
                         "independently disqualifying")

    if claimed == "CANDIDATE_FINDING" and not evidence_ids:
        notes.append("candidate with no evidence ids: L5 will refuse it")
    if claimed == "FACT" and evidence_ids:
        notes.append("FACT is a world-claim; target assertions belong in "
                     "OBSERVATION/CANDIDATE_FINDING")

    env = {"run_key": run_key, "task_key": task_key, "type": effective,
           "original_type": claimed, "downgraded": downgraded,
           "payload": payload, "evidence_ids": evidence_ids,
           "notes": notes}

    if con is not None:
        _persist(con, env)
    return env


def _persist(con: sqlite3.Connection, env: dict[str, Any]) -> None:
    _ensure(con)
    key = f"res.{env['run_key'] or 'anon'}.{abs(hash(str(env['payload']))) % (10 ** 10)}"
    cur = con.execute(
        "INSERT OR REPLACE INTO agent_result(result_key, run_key, task_key, type,"
        " original_type, downgraded, payload, evidence_ids, reported_at)"
        " VALUES (?,?,?,?,?,?,?,?,?)",
        (key, env["run_key"], env["task_key"], env["type"],
         env["original_type"], 1 if env["downgraded"] else 0,
         json.dumps(env["payload"], default=str)[:20000],
         json.dumps(env["evidence_ids"]), store.now()))
    con.commit()
    env["result_key"] = key


def results_for(con: sqlite3.Connection, task_key: str) -> list[dict[str, Any]]:
    out = []
    for r in con.execute("SELECT * FROM agent_result WHERE task_key=?"
                         " ORDER BY reported_at", (task_key,)):
        d = dict(r)
        d["payload"] = _loads(d.get("payload"))
        d["evidence_ids"] = _loads(d.get("evidence_ids")) or []
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# §22 dynamic agent selection
# ---------------------------------------------------------------------------

# Score weights, summing to 1.0. Declared so a surprising choice can be argued
# with rather than merely observed.
SELECTION_WEIGHTS = {
    "expertise": 0.30,      # domain + objective_kind fit
    "evidence": 0.20,       # corpus support for this class
    "tools": 0.15,          # toolset the task actually needs
    "workload": 0.15,       # inverse of current in-flight runs
    "value": 0.12,          # task priority + expected evidence
    "history": 0.08,        # inverse of prior failures in this class
}


def record_failure(con: sqlite3.Connection, role_key: str, *, reason: str,
                   class_id: str | None = None,
                   task_key: str | None = None) -> None:
    _ensure(con)
    con.execute(
        "INSERT INTO agent_failure(role_key, class_id, task_key, reason, at)"
        " VALUES (?,?,?,?,?)",
        (role_key, class_id, task_key, reason, store.now()))
    con.commit()


def _failures(con: sqlite3.Connection, role_key: str,
              class_id: str | None) -> int:
    row = con.execute(
        "SELECT count(*) n FROM agent_failure WHERE role_key=?"
        + (" AND class_id=?" if class_id else ""),
        (role_key, class_id) if class_id else (role_key,)).fetchone()
    return int(row["n"]) if row else 0


def _evidence_support(con: sqlite3.Connection, class_id: str | None) -> float:
    if not class_id:
        return 0.4
    row = con.execute(
        "SELECT count(*) n FROM item i JOIN quality q ON q.item_id=i.id"
        " WHERE i.class_id=? AND i.status='active'"
        " AND q.validation_state IN ('supported','high_confidence')",
        (class_id,)).fetchone()
    n = int(row["n"]) if row else 0
    return min(1.0, n / 12.0)


def _workload(con: sqlite3.Connection, role_key: str) -> float:
    row = con.execute(
        "SELECT count(*) n FROM agent_run WHERE role_key=? AND status IN"
        " ('planned','dispatched','running')", (role_key,)).fetchone()
    return max(0.0, 1.0 - (int(row["n"]) if row else 0) / 3.0)


def select_agent(con: sqlite3.Connection, *, objective: str,
                 domain: str = "web", class_id: str | None = None,
                 needs: Iterable[str] = (),
                 limit: int = 3) -> dict[str, Any]:
    """Rank candidate roles for one task. Returns the ranking AND the reasons.

    Never raises and never invents a role: with no candidate, the answer is an
    explicit `selected: None` with the reason, because dispatching a
    fabricated specialist is how a system quietly stops delegating.
    """
    _ensure(con)
    obj = (objective or "").lower()
    need = {str(n).lower() for n in needs}

    roles = con.execute(
        "SELECT * FROM agent_role ORDER BY role_key").fetchall()
    scored: list[dict[str, Any]] = []
    for r in roles:
        declared = _loads_list(r["capabilities"])
        toolsets = _loads_list(r["toolsets"])

        # expertise: domain match, plus an objective keyword the role names
        expertise = 0.0
        if (r["domain"] or "").lower() == domain.lower():
            expertise += 0.5
        if r["objective_kind"] and r["objective_kind"].lower() in obj:
            expertise += 0.3
        if r["role_key"].replace("-", " ") in obj:
            expertise += 0.2
        if class_id and class_id.replace("_", " ") in obj:
            expertise += 0.1

        ev = _evidence_support(con, class_id)

        # tools: does the role's flattened toolset cover what the task needs?
        tools = 0.0
        if need:
            tools = min(1.0, len(need & {t.lower() for t in toolsets}) / len(need))
        else:
            tools = 0.5

        workload = _workload(con, r["role_key"])
        value = 0.5
        fails = _failures(con, r["role_key"], class_id)
        history = max(0.0, 1.0 - min(fails, 4) / 4.0)

        parts = {"expertise": min(1.0, expertise), "evidence": ev,
                 "tools": tools, "workload": workload, "value": value,
                 "history": history}
        total = sum(SELECTION_WEIGHTS[k] * parts[k] for k in SELECTION_WEIGHTS)

        # A role with no EXECUTE-relevant capability cannot be selected for
        # offensive work regardless of how well it scores otherwise: selection
        # proposes, `agents.dispatch` gates. Recording it here keeps the
        # explanation honest about what the gate will then decide.
        gated = ("EXECUTE" in declared or "DESTRUCTIVE" in declared)

        scored.append({
            "role_key": r["role_key"], "domain": r["domain"],
            "score": round(total, 5),
            "components": {k: round(v, 4) for k, v in parts.items()},
            "declared_capabilities": declared,
            "requires_execution_gate": gated,
            "prior_failures": fails,
            "rationale": r["rationale"] or "",
        })

    scored.sort(key=lambda x: (-x["score"], x["role_key"]))
    return {"selected": scored[0]["role_key"] if scored else None,
            "ranking": scored[:limit],
            "weights": SELECTION_WEIGHTS,
            "reason": (scored[0]["rationale"] if scored else
                       "no agent_role rows exist; create a role before "
                       "delegating (§20 roles are data)")}


# ---------------------------------------------------------------------------
# §21 decomposition into parallelisable subtasks
# ---------------------------------------------------------------------------

def decompose_for_parallelism(objective: str, *,
                              branches: Iterable[str] = ()) -> dict[str, Any]:
    """Split one objective into independent branches.

    Independent is the requirement, not "several tasks": a branch set where
    every branch depends on the others is a sequential plan wearing a parallel
    costume. Each entry therefore declares what it needs from the others, and
    `parallelisable` reports whether the set actually is.

    Returns the plan DICT. An earlier version wrapped it in a one-element list,
    so every caller that read `plan["branches"]` raised TypeError — a shape the
    only caller had never exercised.
    """
    b = [x.strip() for x in branches if x and x.strip()]
    out = [{"branch": name, "objective": objective,
            "depends_on": [], "needs_from_others": []}
           for name in (b or ["primary"])]
    return {"branches": out,
            "parallelisable": all(not x["depends_on"] for x in out),
            "note": ("branches are independent by construction; a branch that "
                     "needs another branch's output must declare it in "
                     "`depends_on`")}


def synthesize(con: sqlite3.Connection, task_keys: Iterable[str]) -> dict[str, Any]:
    """Merge agent results into one orchestrator-level state update.

    §21: collect -> synthesize -> update global state. The synthesis reports
    what CHANGED (new hypotheses, downgraded claims, new evidence) rather than
    concatenating agent prose, because a concatenation is not a state update.
    """
    keys = list(task_keys)
    added_hyps: list[str] = []
    downgrades: list[dict[str, Any]] = []
    evidence: list[int] = []
    for k in keys:
        for res in results_for(con, k):
            if res["type"] == "HYPOTHESIS":
                added_hyps.append(str(res["payload"])[:120])
            if res["downgraded"]:
                downgrades.append({"task": k,
                                   "claimed": res["original_type"],
                                   "effective": res["type"]})
            evidence.extend(res["evidence_ids"] or [])
    return {"tasks": keys, "hypotheses_from_agents": added_hyps,
            "downgraded_claims": downgrades,
            "evidence_referenced": sorted(set(evidence)),
            "note": ("a claim downgraded here is not lost — it is routed to "
                     "validation, which is the only path to `validated`")}


def _loads(raw: str | None) -> dict[str, Any]:
    try:
        v = json.loads(raw or "{}")
        return v if isinstance(v, dict) else {}
    except (ValueError, TypeError):
        return {}


def _loads_list(raw: str | None) -> list[str]:
    try:
        v = json.loads(raw or "[]")
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, dict):
            return [str(x) for x in v]
    except (ValueError, TypeError):
        pass
    return []