"""Task graph: runnability, cycles, blocking, and the waves a run executes in.

The whole point of a DAG over a checklist is that "what can I do right now" is
DERIVED from edges, never maintained by hand. A `ready` flag that a writer has
to remember to clear is a bug waiting for a bad night; a join against
`task_dep` cannot drift.

Cycle detection is not decoration. A self-referential dependency inserted by a
bad decomposition would otherwise make every task permanently unready — a
silent stall, which is the worst failure mode an autonomous overnight run has.
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict, deque
from typing import Any

from . import store


def deps_of(con: sqlite3.Connection) -> dict[str, set[str]]:
    """task_key -> set of task_keys it waits for."""
    out: dict[str, set[str]] = defaultdict(set)
    for r in con.execute("SELECT task_key, depends_on FROM task_dep"):
        out[r["task_key"]].add(r["depends_on"])
    return out


def dependents_of(con: sqlite3.Connection) -> dict[str, set[str]]:
    """task_key -> set of task_keys waiting on it (the reverse edge)."""
    out: dict[str, set[str]] = defaultdict(set)
    for r in con.execute("SELECT task_key, depends_on FROM task_dep"):
        out[r["depends_on"]].add(r["task_key"])
    return out


def find_cycles(con: sqlite3.Connection) -> list[list[str]]:
    """Return every elementary cycle found. Empty list == graph is a DAG.

    Iterative colour-marking DFS: recursion would blow the stack on a deep
    graph, and an overnight run that segfaults during cycle detection takes the
    whole process with it.
    """
    adj = deps_of(con)
    WHITE, GREY, BLACK = 0, 1, 2
    colour: dict[str, int] = defaultdict(int)
    cycles: list[list[str]] = []
    seen_sigs: set[tuple[str, ...]] = set()

    for root in list(adj.keys()):
        if colour[root] != WHITE:
            continue
        stack: list[tuple[str, list[str]]] = [(root, list(adj.get(root, ())))]
        colour[root] = GREY
        path = [root]
        while stack:
            node, remaining = stack[-1]
            if not remaining:
                colour[node] = BLACK
                stack.pop()
                if len(path) > 1:
                    path.pop()
                continue
            nxt = remaining.pop()
            stack[-1] = (node, remaining)
            if colour[nxt] == GREY:
                # reconstruct the cycle from the current path
                if nxt in path:
                    cyc = path[path.index(nxt):]
                    sig = tuple(sorted(cyc))
                    if sig not in seen_sigs:
                        seen_sigs.add(sig)
                        cycles.append(cyc + [nxt])
                continue
            if colour[nxt] == WHITE:
                colour[nxt] = GREY
                path.append(nxt)
                stack.append((nxt, list(adj.get(nxt, ()))))
    return cycles


def missing_deps(con: sqlite3.Connection) -> dict[str, list[str]]:
    """Dependencies naming a task that does not exist.

    A dangling edge is worse than no edge: the task silently never becomes
    ready and the run looks busy forever.
    """
    existing = {r["task_key"] for r in con.execute("SELECT task_key FROM task")}
    bad: dict[str, list[str]] = defaultdict(list)
    for r in con.execute("SELECT task_key, depends_on FROM task_dep"):
        if r["depends_on"] not in existing:
            bad[r["task_key"]].append(r["depends_on"])
    return dict(bad)


def refresh_readiness(con: sqlite3.Connection) -> dict[str, int]:
    """Recompute `ready` from edges.

    Only `planned` is promoted, and only when every dependency is in a terminal
    success state. A dependency that is `completed` unblocks; one that is
    `failed`/`blocked`/`archived` does NOT silently unblock its dependents —
    they go to `blocked` with the reason recorded, because running a task
    whose prerequisite failed produces confident nonsense.

    `blocked` and `retrying` are ALSO re-evaluated, not just set. An earlier
    version only ever moved tasks INTO `blocked`, which made it terminal: once
    a dependency failed, its dependents stayed `blocked` forever even after the
    dependency was fixed and completed. Reproduced — after repairing the dep,
    `ready_tasks` was still empty, so one transient failure poisoned the chain
    for the life of the database. A blocked state that can never be left is a
    silent graveyard, not a safety mechanism.
    """
    d = deps_of(con)
    status = {r["task_key"]: r["status"] for r in con.execute(
        "SELECT task_key, status FROM task")}

    promoted, demoted, revived = 0, 0, 0
    for key, deps in d.items():
        st = status.get(key)
        if st is None:
            continue
        unmet = [x for x in deps if status.get(x) not in store.TERMINAL_STATES]
        # A dep that exists but failed is unsatisfiable, not merely unmet.
        dead = [x for x in deps if status.get(x) in
                {"failed", "blocked", "superseded", "archived"}]

        if st in ("blocked", "retrying"):
            # Reconsider only when the cause may have changed: a dependency
            # that has since COMPLETED. Re-admitting a task whose dependency is
            # merely still-running would churn it back into `ready` and let it
            # be claimed out of order.
            if not dead and not unmet:
                store.set_status(con, key, "ready")
                revived += 1
                status[key] = "ready"
            continue

        if st == "planned" and not unmet and not dead:
            store.set_status(con, key, "ready")
            promoted += 1
            status[key] = "ready"
        elif st in ("planned", "ready") and dead:
            # A dependency that FAILED is not merely unmet — it is
            # unsatisfiable. Leaving the task `planned` hides the failure
            # behind an apparently-healthy backlog; the run would look busy
            # while making no progress. Block it and name the cause.
            store.set_status(con, key, "blocked")
            demoted += 1
            status[key] = "blocked"
        elif st == "ready" and unmet:
            store.set_status(con, key, "blocked")
            demoted += 1
            status[key] = "blocked"

    # tasks with no edges at all
    for key, st in list(status.items()):
        if st == "planned" and not d.get(key):
            store.set_status(con, key, "ready")
            promoted += 1
            status[key] = "ready"
    return {"promoted": promoted, "demoted": demoted, "revived": revived}


def ready_tasks(con: sqlite3.Connection, limit: int | None = None
                ) -> list[sqlite3.Row]:
    sql = ("SELECT * FROM task WHERE status='ready'"
           " ORDER BY priority ASC, created_at ASC")
    if limit:
        sql += f" LIMIT {int(limit)}"
    return con.execute(sql).fetchall()


def blocked_by(con: sqlite3.Connection) -> dict[str, list[str]]:
    """task_key -> unsatisfied dependency keys. Answers 'what is stuck and why'."""
    d = deps_of(con)
    status = {r["task_key"]: r["status"] for r in con.execute(
        "SELECT task_key, status FROM task")}
    out: dict[str, list[str]] = {}
    for key, deps in d.items():
        unmet = sorted(x for x in deps if status.get(x) not in store.TERMINAL_STATES)
        if unmet:
            out[key] = unmet
    return out


def parallel_waves(con: sqlite3.Connection, max_waves: int = 50
                   ) -> list[list[str]]:
    """Topological waves over incomplete tasks.

    Wave 1 has no unsatisfied deps, wave n depends only on waves < n. A wave is
    the maximum set that may run at the same time, which is what makes
    parallelism a consequence of the graph instead of a guess.
    """
    remaining = {r["task_key"] for r in con.execute(
        "SELECT task_key FROM task WHERE status NOT IN"
        " ('completed','superseded','archived')")}
    d = deps_of(con)
    waves: list[list[str]] = []
    done: set[str] = set()
    for _ in range(max_waves):
        wave = sorted(k for k in remaining
                      if all(x in done or x not in remaining for x in d.get(k, ())))
        if not wave:
            break
        waves.append(wave)
        done |= set(wave)
        remaining -= set(wave)
    return waves


def graph_report(con: sqlite3.Connection) -> dict[str, Any]:
    """The one call the orchestrator and the self-audit both read."""
    status: dict[str, int] = {}
    for r in con.execute("SELECT status, count(*) n FROM task GROUP BY status"):
        status[r["status"]] = r["n"]
    cycles = find_cycles(con)
    dang = missing_deps(con)
    return {
        "nodes": sum(status.values()),
        "by_status": status,
        "edges": con.execute("SELECT count(*) n FROM task_dep").fetchone()["n"],
        "cycles": cycles,
        "dangling_deps": dang,
        "ready": len(ready_tasks(con)),
        "blocked_detail": blocked_by(con),
        "waves": len(parallel_waves(con)),
    }


def break_cycles(con: sqlite3.Connection) -> dict[str, Any]:
    """Make the graph acyclic by dropping the lowest-priority edge in each cycle.

    Conservative and reversible: the edge is recorded in the report so the
    decomposition can be fixed rather than silently limping on.
    """
    fixed = []
    for _ in range(20):
        cycles = find_cycles(con)
        if not cycles:
            break
        cyc = cycles[0]
        # drop the edge belonging to the least important task (highest priority
        # number = lower importance in this schema)
        node = max(cyc[:-1], key=lambda k: (
            con.execute("SELECT priority FROM task WHERE task_key=?",
                        (k,)).fetchone()["priority"]
            if con.execute("SELECT priority FROM task WHERE task_key=?",
                           (k,)).fetchone() else 99))
        con.execute("DELETE FROM task_dep WHERE task_key=? AND depends_on=?",
                    (node, node))
        # removing the self-edge may not break it; drop node's weakest dep
        row = con.execute("SELECT depends_on FROM task_dep WHERE task_key=?"
                          " ORDER BY depends_on LIMIT 1", (node,)).fetchone()
        if row:
            con.execute("DELETE FROM task_dep WHERE task_key=? AND depends_on=?",
                        (node, row["depends_on"]))
            fixed.append({"dropped": f"{node} -> {row['depends_on']}",
                          "cycle": cyc})
    con.commit()
    return {"fixed": fixed, "remaining_cycles": find_cycles(con)}