"""Priority engine (spec §7): choose the next task without being told.

A priority number a human typed once is a guess that never updates. This scores
every ready task against live state — how much it unblocks, whether it closes a
measured gap, what the knowledge engine already knows about it — so reordering
happens as evidence arrives rather than when someone remembers to re-sort.

Weights are declared, not hidden, so a surprising ordering can be explained
instead of argued with.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Any

from . import dag, store

# Sum to 1.0. Unblocking dominates because a task that gates others converts
# directly into throughput; evidence value dominates the rest because the
# system's purpose is knowledge that changes a hunter's next request.
WEIGHTS = {
    "unblocks": 0.22,        # how many tasks this one gates
    "priority_declared": 0.14,  # the existing human/heuristic priority field
    "gap_closure": 0.20,    # closes a class the metrics call weak
    "evidence_value": 0.18, # would produce a gated, cited artifact
    "learning_value": 0.12, # opens a new capability rather than deepening one
    "cost": 0.08,           # cheaper first, all else equal
    "staleness": 0.06,      # untouched work ages into higher priority
}

GAP_WEIGHT = {
    "no_items": 1.0,        # a declared class with zero evidence
    "thin": 0.7,
    "no_fp_rules": 0.6,     # blocks class maturity
    "unreviewed": 0.4,
}


def _unblock_count(con: sqlite3.Connection, task_key: str) -> int:
    return con.execute(
        "SELECT count(*) n FROM task_dep WHERE depends_on=?",
        (task_key,)).fetchone()["n"]


def _class_health(con: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """Live per-class weakness, read from the knowledge engine's own gate.

    Deliberately not a second source of truth: if the gate says a class is thin,
    the priority engine must not believe a stale copy of thinness.
    """
    rows = con.execute("""
        SELECT c.id,
               count(i.id)                              AS n_items,
               count(DISTINCT i.id)                     AS n_items2,
               sum(CASE WHEN q.validation_state IN ('supported','high_confidence')
                        THEN 1 ELSE 0 END)              AS n_promoted,
               max(c.status)                            AS cstatus
        FROM bug_class c
        LEFT JOIN item i   ON i.class_id = c.id AND i.status='active'
        LEFT JOIN quality q ON q.item_id = i.id
        GROUP BY c.id
    """).fetchall()
    out: dict[str, dict[str, Any]] = {}
    for r in rows:
        n = int(r["n_promoted"] or 0)
        if n == 0:
            w = GAP_WEIGHT["no_items"]
        elif n < 4:
            w = GAP_WEIGHT["thin"]
        else:
            w = 0.0
        out[r["id"]] = {"n_items": n, "weight": w, "status": r["cstatus"]}
    return out


def score_task(con: sqlite3.Connection, row: sqlite3.Row,
               health: dict[str, dict[str, Any]]) -> dict[str, float]:
    unblocks = _unblock_count(con, row["task_key"])

    # declared priority: 1 is highest, so invert onto a 0..1 scale
    try:
        p = int(row["priority"])
    except (TypeError, ValueError):
        p = 5
    declared = max(0.0, min(1.0, (10 - p) / 9.0))

    gap = 0.0
    if row["class_id"] and row["class_id"] in health:
        gap = health[row["class_id"]]["weight"]

    # evidence value: does this task promise a verifiable artifact?
    ev = 1.0 if (row["evidence_req"] or "").strip() else 0.2
    if not (row["expected_artifact"] or "").strip():
        ev *= 0.5

    # learning value: a task that creates a new capability, not just more of one
    learn = 0.6
    obj = (row["objective"] or "").lower()
    if any(k in obj for k in ("build", "implement", "add capability",
                              "integrate", "wire", "orchestrat")):
        learn = 1.0
    elif any(k in obj for k in ("audit", "verify", "check")):
        learn = 0.3

    # cost: no duration column exists, so proxy by objective length. A longer
    # objective is usually a broader one. Weak signal, declared as weak.
    cost = max(0.0, min(1.0, 1.0 - len(obj or "") / 400.0))

    # staleness: nothing tracks age of an untouched task, so this stays 0 until
    # a real signal exists rather than inventing one.
    stale = 0.0

    parts = {
        "unblocks": min(1.0, unblocks / 5.0),
        "priority_declared": declared,
        "gap_closure": gap,
        "evidence_value": ev,
        "learning_value": learn,
        "cost": cost,
        "staleness": stale,
    }
    total = sum(WEIGHTS[k] * parts[k] for k in WEIGHTS)
    parts["score"] = round(total, 5)
    parts["unblocks_raw"] = unblocks
    return parts


def rank(con: sqlite3.Connection, limit: int | None = None
         ) -> list[dict[str, Any]]:
    """Rank every ready task. Returns dicts, not Rows, so callers can serialize."""
    health = _class_health(con)
    rows = dag.ready_tasks(con)
    scored = []
    for r in rows:
        s = score_task(con, r, health)
        scored.append({
            "task_key": r["task_key"],
            "objective": r["objective"],
            "class_id": r["class_id"],
            "declared_priority": r["priority"],
            "score": s["score"],
            "components": {k: round(v, 4) for k, v in s.items()
                           if k in WEIGHTS},
            "unblocks": s["unblocks_raw"],
        })
    scored.sort(key=lambda x: (-x["score"], x["declared_priority"],
                               x["task_key"]))
    return scored[:limit] if limit else scored


def next_task(con: sqlite3.Connection) -> dict[str, Any] | None:
    r = rank(con, limit=1)
    return r[0] if r else None


def explain(con: sqlite3.Connection, task_key: str) -> str:
    """Human-readable justification. A ranking nobody can interrogate is a
    ranking nobody will trust when it picks the wrong task."""
    row = store.get_task(con, task_key)
    if not row:
        return f"{task_key}: not found"
    health = _class_health(con)
    s = score_task(con, row, health)
    lines = [f"# Priority: {task_key}", f"score = {s['score']}",
             f"objective: {row['objective']}"]
    for k in WEIGHTS:
        lines.append(f"- {k:18} {s[k]:.3f} x {WEIGHTS[k]:.2f}")
    lines.append(f"- gates {s['unblocks_raw']} other task(s)")
    blocked = dag.blocked_by(con).get(task_key, [])
    if blocked:
        lines.append(f"- waiting on: {', '.join(blocked)}")
    return "\n".join(lines)


def reorder_tasks(con: sqlite3.Connection) -> int:
    """Write the computed score back into the declared priority column.

    This is the adaptive behaviour in §7: the backlog reorders itself as
    evidence arrives. Written 1..9 so the column keeps its documented meaning.
    """
    ranked = rank(con)
    changed = 0
    for i, t in enumerate(ranked):
        newp = min(9, max(1, 1 + i))
        cur = con.execute("SELECT priority FROM task WHERE task_key=?",
                          (t["task_key"],)).fetchone()
        if cur and int(cur["priority"]) != newp:
            con.execute("UPDATE task SET priority=? WHERE task_key=?",
                        (newp, t["task_key"]))
            changed += 1
    con.commit()
    return changed


def weakest_classes(con: sqlite3.Connection, limit: int = 10
                    ) -> list[dict[str, Any]]:
    health = _class_health(con)
    rows = sorted(health.items(), key=lambda kv: (-kv[1]["weight"],
                                                  kv[1]["n_items"]))
    return [{"class_id": k, **v} for k, v in rows[:limit] if v["weight"] > 0]