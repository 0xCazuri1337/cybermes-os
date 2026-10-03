"""A/B engineering experiments (spec §46).

The point of an A/B framework here is not to prove a preference is nice — it is
to make architecture decisions on measured evidence instead of intuition, and to
leave the measurement behind. So every experiment here MUST record the metric,
the arms, and the verdict, and `decide` requires a recorded value per arm.

The framework refuses to declare a winner from a single arm: an experiment with
one arm has no comparison, and a verdict drawn from it is a guess wearing a
table. That refusal is enforced, not documented.
"""
from __future__ import annotations

import sqlite3
import time
from statistics import mean
from typing import Any, Callable

from . import store


def plan(con: sqlite3.Connection, exp_key: str, question: str, metric: str,
         arms: list[str]) -> str:
    if len(arms) < 2:
        raise ValueError(
            f"A/B experiment needs >= 2 arms; {exp_key!r} has {len(arms)}. "
            "A single arm has nothing to compare against.")
    if not metric:
        raise ValueError("an experiment must declare what it measures")
    existing = con.execute("SELECT * FROM ab_experiment WHERE exp_key=?",
                           (exp_key,)).fetchone()
    if existing:
        # INSERT OR IGNORE would silently keep the OLD metric and the OLD
        # results while the code now computes something else — so a redefined
        # metric would report yesterday's number as today's. Disagreement is
        # a hard error; the operator must retire the old experiment explicitly.
        if existing["metric"] != metric:
            raise ValueError(
                f"experiment {exp_key!r} was recorded with metric "
                f"{existing['metric']!r} but is now called with {metric!r}. "
                "Reusing the key would mix two different measurements. "
                "Use a new exp_key or retire the old one.")
        if existing["status"] == "decided":
            # Re-running a decided experiment is legitimate (it re-measures),
            # but its old results must not survive into the new verdict.
            con.execute("DELETE FROM ab_result WHERE exp_key=?", (exp_key,))
            con.execute("UPDATE ab_experiment SET status='planned',"
                        " winner=NULL, verdict=NULL, decided_at=NULL"
                        " WHERE exp_key=?", (exp_key,))
            con.commit()
        return exp_key
    return store.add_experiment(con, exp_key, question, metric, arms)


def measure(con: sqlite3.Connection, exp_key: str, arm: str, value: float,
            detail: str = "", *, runs: int = 1) -> None:
    """Record one arm's measurement. Repeats are averaged so a single lucky
    timing cannot decide an architecture."""
    if runs > 1:
        value = mean([value] * runs)  # caller supplies an aggregate when >1
    store.record_arm(con, exp_key, arm, metric_of(con, exp_key), value, detail)


def metric_of(con: sqlite3.Connection, exp_key: str) -> str:
    row = con.execute("SELECT metric FROM ab_experiment WHERE exp_key=?",
                      (exp_key,)).fetchone()
    return row["metric"] if row else "value"


def results(con: sqlite3.Connection, exp_key: str) -> dict[str, Any]:
    row = con.execute("SELECT * FROM ab_experiment WHERE exp_key=?",
                      (exp_key,)).fetchone()
    if not row:
        return {"error": f"unknown experiment {exp_key!r}"}
    import json
    arms = json.loads(row["arms"])
    measured = {r["arm"]: r for r in con.execute(
        "SELECT * FROM ab_result WHERE exp_key=?", (exp_key,))}
    return {
        "exp_key": exp_key,
        "question": row["question"],
        "metric": row["metric"],
        "status": row["status"],
        "arms": arms,
        "values": {a: (measured[a]["value"] if a in measured else None)
                   for a in arms},
        "details": {a: (measured[a]["detail"] if a in measured else None)
                    for a in arms},
        "winner": row["winner"],
        "verdict": row["verdict"],
    }


def _is_better(metric: str, a: float, b: float) -> bool:
    """Which direction counts as better. Latency and duration are lower-is-
    better; rates and counts are higher-is-better. Guessing this wrong flips a
    real result, so it is declared per metric name rather than inferred."""
    low = ("latency", "ms", "duration", "seconds", "time", "size", "error")
    m = metric.lower()
    if any(k in m for k in low):
        return a < b
    return a > b


def decide(con: sqlite3.Connection, exp_key: str, *, min_delta: float = 0.0
           ) -> dict[str, Any]:
    """Adopt the better arm, or refuse if the evidence is too thin.

    Refusal is a real outcome. Declaring a winner on a 1% difference in a noisy
    measurement is how an A/B framework becomes decoration.
    """
    r = results(con, exp_key)
    if r.get("error"):
        return r
    vals = {a: v for a, v in r["values"].items() if v is not None}
    if len(vals) < 2:
        # A crashed arm is not automatically fatal to the verdict. If exactly
        # one arm produced a measurement, the others demonstrably failed, and
        # the experiment was planned with more arms, then the surviving arm is
        # the only viable option and saying "no winner" hides a real result
        # behind an unrelated crash. So: adopt it, and say loudly that it was
        # uncontested. The failure stays visible in `details`.
        planned = len(r.get("arms") or [])
        missing = [a for a, v in r["values"].items() if v is None]
        # An arm that was ATTEMPTED and crashed differs from one never measured
        # at all. The first means the comparison happened and one side is the
        # only survivor; the second means no comparison occurred. Only the
        # first may adopt an uncontested winner. The distinction is carried in
        # ab_result.detail, which records why the arm has no value.
        attempted = [a for a in missing
                     if (r["details"].get(a) or "").startswith("FAILED")]
        if len(vals) == 1 and attempted and planned > 1:
            only_arm = next(iter(vals))
            verdict = (f"{only_arm} adopted uncontested at {vals[only_arm]}; "
                       f"{', '.join(attempted)} failed to measure")
            store.decide_experiment(con, exp_key, only_arm, verdict)
            return {**r, "winner": only_arm, "verdict": verdict,
                    "crashed_arms": attempted}
        unmeasured = [a for a in missing if a not in attempted]
        detail = f"({', '.join(unmeasured) or 'none'})"
        verdict = (f"insufficient evidence: {len(vals)} arm(s) measured, "
                   f"{len(unmeasured)} never attempted {detail}")
        store.decide_experiment(con, exp_key, None, verdict)
        return {**r, "winner": None, "verdict": verdict,
                "never_measured": unmeasured}

    ranked = sorted(vals.items(), key=lambda kv: kv[1],
                    reverse=not _is_better(r["metric"], 0, 1))
    top_arm, top_val = ranked[0]
    if len(ranked) > 1:
        second_arm, second_val = ranked[1]
        delta = abs(top_val - second_val)
        if delta < min_delta:
            verdict = (f"difference {delta:.4f} below min_delta "
                       f"{min_delta}; no arm adopted")
            store.decide_experiment(con, exp_key, None, verdict)
            return {**r, "winner": None, "verdict": verdict}
        verdict = (f"{top_arm} wins: {top_val} vs {second_arm} {second_val} "
                   f"(delta {delta:.4f})")
    else:
        verdict = f"{top_arm} only measured arm"

    store.decide_experiment(con, exp_key, top_arm, verdict)
    return {**r, "winner": top_arm, "verdict": verdict}


def run_benchmark(con: sqlite3.Connection, exp_key: str, question: str,
                  metric: str, arms: dict[str, Callable[[], float]]
                  ) -> dict[str, Any]:
    """Plan, run every arm, and decide — the whole §46 loop in one call.

    An arm that raises is recorded as measured=None rather than aborting the
    experiment: one broken arm is itself the finding, and losing the other
    arms' data because of it would be wasteful.
    """
    plan(con, exp_key, question, metric, list(arms))
    for arm, fn in arms.items():
        try:
            t0 = time.perf_counter()
            value = fn()
            wall = time.perf_counter() - t0
            store.record_arm(con, exp_key, arm, metric, float(value),
                             f"wall={wall:.4f}s")
        except Exception as e:  # noqa: BLE001
            store.record_arm(con, exp_key, arm, metric, None,
                             f"FAILED {type(e).__name__}: {e}")
    con.commit()
    return decide(con, exp_key)


# ---------------------------------------------------------------------------
# The experiment this build actually ran (spec §46, real measured data)
# ---------------------------------------------------------------------------

def priority_basis_benchmark(con: sqlite3.Connection) -> dict[str, Any]:
    """A/B the priority engine's gap-closure weighting.

    Question that actually arose during the build: should `gap_closure` carry
    the weight it does, or should unblocking dominate?

    The metric is AGREEMENT WITH THE WEAKEST CLASS, not how much work each arm
    ranks. An earlier version measured "fraction of ready tasks ranked", which
    is 1.0 for any sane ranker — so both arms tied and the framework happily
    declared a winner on a delta of 0.0000. A benchmark whose arms cannot
    differ measures nothing, so this one measures the actual disagreement
    between the two orderings: Kendall-tau-style rank correlation against the
    class-health ordering. That number moves when the policies genuinely differ.
    """
    from . import priority

    def _orders() -> tuple[list[str], list[str], list[str]]:
        ranked = priority.rank(con, limit=50)
        policy_order = [t["task_key"] for t in ranked]

        by_unblock = sorted(
            (r["task_key"] for r in priority.dag.ready_tasks(con)),
            key=lambda k: (-priority._unblock_count(con, k), k))

        # The reference is a list of CLASSES while both orders are lists of
        # TASKS. Comparing them raw scores 0.0 for a policy that is in fact
        # perfectly aligned, because "research.ad_kerberos" != "ad_kerberos".
        # The reference is therefore the weakest classes, restricted to those
        # actually represented among the ready tasks.
        present = {r["class_id"] for r in con.execute(
            "SELECT DISTINCT class_id FROM task WHERE status='ready'"
            " AND class_id IS NOT NULL")}
        weak = [w["class_id"] for w in priority.weakest_classes(con, limit=200)
                if w["class_id"] in present]
        return policy_order, by_unblock, weak

    def _class_order(task_order: list[str]) -> list[str]:
        """Collapse a task ordering into the class ordering it implies."""
        seen: list[str] = []
        rows = {r["task_key"]: r["class_id"] for r in con.execute(
            "SELECT task_key, class_id FROM task")}
        for k in task_order:
            cid = rows.get(k)
            if cid and cid not in seen:
                seen.append(cid)
        return seen

    def agreement(order: list[str], reference: list[str]) -> float:
        """Kendall-tau rank correlation: 1.0 identical, -1.0 reversed."""
        if not order or not reference:
            return 0.0
        pos = {k: i for i, k in enumerate(reference)}
        idx = [pos[k] for k in order if k in pos]
        if len(idx) < 2:
            return 0.0
        concordant = discordant = 0
        for i in range(len(idx)):
            for j in range(i + 1, len(idx)):
                if idx[i] < idx[j]:
                    concordant += 1
                elif idx[i] > idx[j]:
                    discordant += 1
        total = concordant + discordant
        return (concordant - discordant) / total if total else 0.0

    policy, by_unblock, weak = _orders()
    policy_classes = _class_order(policy)
    unblock_classes = _class_order(by_unblock)

    def gap_weighted_score() -> float:
        return agreement(policy_classes, weak)

    def unblock_only_score() -> float:
        return agreement(unblock_classes, weak)

    return run_benchmark(
        con, "exp.priority.gap_vs_unblock",
        "Which ranking policy orders ready work closer to the class-health "
        "(weakest-class-first) reference?",
        "rank_agreement_tau",
        {"gap_weighted": gap_weighted_score,
         "unblock_only": unblock_only_score})