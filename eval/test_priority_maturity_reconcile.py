"""T29 -- the priority engine and the maturity gate must agree on every class.

THE DEFECT (measured on the live corpus, not hypothesised).

`orch/priority.py::_class_health` had a gap model of its own: a class was
"no gap" once it had 4 promoted items. The knowledge engine's definition of
done -- `wks/quality.maturity` -- measures SEVEN capabilities:

    taxonomy_placed, methodology, items, supported_items, fp_rules, chain, skill

So a class with 12 promoted items but no FP rule and no chain read as
NO GAP to the priority engine and as "researching" to the maturity gate.

MEASURED SCALE: 25 of 70 classes disagreed. The priority engine's docstring
claimed it read "the knowledge engine's own gate", but it re-implemented a
weaker model instead of calling it. The consequence is concrete: the
research worker builds its queue from `priority.weakest_classes()`
(`orch/workers.py::research_cycle`), so those 25 classes never entered the
research queue even though the gate had named them incomplete.

THE FIX: `_class_health` now calls `quality.maturity()` and derives the
weight from the capabilities that are actually missing. One gap model, owned
by the gate that owns the corpus.

This test drives the REAL corpus (read-only) and asserts two things:

  1. RECONCILIATION -- for every class, "the priority engine sees a gap"
     and "maturity says the class is not mature" are the same answer.
  2. SENSITIVITY -- a class that is missing a capability the item count
     cannot see (an FP rule, a chain, a skill, a methodology) IS reported as
     a gap. This is the negative control: without it, a fix that simply
     returned "every class is a gap" would pass check 1.

Run: python eval/test_priority_maturity_reconcile.py
Exit: non-zero when the two disagree or the sensitivity check fails.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from orch import priority, store  # noqa: E402
from wks import quality  # noqa: E402

FAILURES: list[str] = []
PASSES = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASSES
    if cond:
        PASSES += 1
        print(f"  [PASS] {name}")
    else:
        FAILURES.append(f"{name}: {detail}")
        print(f"  [FAIL] {name}  {detail}")


def main() -> int:
    print("T29 priority/maturity reconciliation")
    # THIS TEST READS THE LIVE CORPUS, AND THAT IS CORRECT.
    #
    # MEASURED 2026-11-01: an earlier version of this file sandboxed the
    # database, and two checks then failed:
    #   "the live corpus has classes missing a structural capability"
    #   "gap weights vary across classes"
    # The check names say what it needs: the LIVE CORPUS. Its negative
    # control is a class whose item-count bar is cleared but whose
    # STRUCTURAL capability (fp_rules / chain / skill / methodology) is
    # missing -- a property of the corpus's accumulated state, not of a
    # freshly seeded taxonomy. A fresh seed has no such class, so the
    # control cannot run and the check reports "only 0 distinct weight(s)",
    # which is the check failing to find a condition that is not there.
    #
    # A test that reads the live corpus is legitimate. A test that WRITES
    # to it is not -- and that is what `eval/test_p1_live_db_isolation.py`
    # now enforces, structurally and behaviourally. This file writes
    # nothing: it calls `priority._class_health`, `quality.gap_report` and
    # `priority.weakest_classes`, all of which are SELECTs.
    #
    # To make "writes nothing" checkable rather than asserted, the
    # database is opened READ-ONLY.
    import sqlite3 as _sqlite3
    from pathlib import Path as _Path
    from wks import config as _wks_config
    _db = _wks_config.db_path()
    _uri = f"file:{_db}?mode=ro"
    con = _sqlite3.connect(_uri, uri=True, timeout=30)
    con.row_factory = _sqlite3.Row
    try:
        health = priority._class_health(con)
        gaps = quality.gap_report(con)

        # ---- CHECK 1: the two agree on every class -------------------------
        mismatches = []
        for g in gaps:
            cid = g["class_id"]
            h = health.get(cid)
            if h is None:
                mismatches.append((cid, "priority has no entry", None))
                continue
            sees_gap = h["weight"] > 0
            is_gap = g["state"] != "mature"
            if sees_gap != is_gap:
                mismatches.append((cid, g["state"], g.get("missing")))

        check("every class reconciles between priority and maturity",
              not mismatches,
              f"{len(mismatches)} of {len(gaps)} classes disagree: "
              + "; ".join(f"{c}(state={s},missing={m})"
                          for c, s, m in mismatches[:6]))

        # Every class the priority engine knows about must be one maturity
        # also knows about. A class present in one and absent from the other
        # is the same defect in a different shape.
        only_priority = set(health) - {g["class_id"] for g in gaps}
        only_maturity = {g["class_id"] for g in gaps} - set(health)
        check("the two see the same set of classes",
              not only_priority and not only_maturity,
              f"only in priority: {sorted(only_priority)[:5]}; "
              f"only in maturity: {sorted(only_maturity)[:5]}")

        # ---- CHECK 2: the negative control --------------------------------
        # A class can be missing a capability that a promoted-item count
        # cannot see. If the priority engine cannot report those as gaps,
        # reconciliation would have been achieved by making every class a
        # gap -- which is not a fix, it is a second uninformative metric.
        #
        # The live corpus contains real classes with the item-count bar
        # already cleared but a structural capability missing. Those MUST
        # appear in `weakest_classes()`.
        structural = [g for g in gaps
                      if g["state"] != "mature"
                      and ({"fp_rules", "chain", "skill", "methodology"}
                           & set(g.get("missing") or []))]
        check("the live corpus has classes missing a structural capability",
              bool(structural),
              "no class is missing fp_rules/chain/skill/methodology; "
              "the negative control cannot run")

        if structural:
            weak = {w["class_id"] for w in priority.weakest_classes(con,
                                                                   limit=200)}
            unreported = [g["class_id"] for g in structural
                          if g["class_id"] not in weak]
            check("a class missing fp_rules/chain/skill/methodology is "
                  "reported as a gap",
                  not unreported,
                  f"not reported: {unreported[:8]}")

            # And it must carry a NON-ZERO weight -- appearing in the list
            # with weight 0 would not influence any ordering.
            weights = {w["class_id"]: w["weight"]
                       for w in priority.weakest_classes(con, limit=200)}
            zero = [g["class_id"] for g in structural
                    if weights.get(g["class_id"], 0) <= 0]
            check("that gap carries a non-zero weight",
                  not zero,
                  f"weight 0: {zero[:8]}")

            # The ordering must put the structurally-incomplete classes
            # ABOVE the mature ones -- that is what "weakest first" means.
            ranked = [w["class_id"] for w in priority.weakest_classes(
                con, limit=200)]
            mature_ids = {g["class_id"] for g in gaps
                          if g["state"] == "mature"}
            if ranked and mature_ids:
                first_mature = next((i for i, c in enumerate(ranked)
                                     if c in mature_ids), None)
                last_gap = max((i for i, c in enumerate(ranked)
                                if c not in mature_ids), default=None)
                check("structurally-incomplete classes rank above mature ones",
                      first_mature is None or last_gap is None
                      or last_gap < first_mature,
                      f"last gap at {last_gap}, first mature at {first_mature}")

        # ---- CHECK 3: the gap weight is not a constant ---------------------
        # Every class being the same weight would satisfy checks 1 and 2.
        # The weights must vary with how much is actually missing.
        ws = {round(h["weight"], 3) for h in health.values()}
        check("gap weights vary across classes",
              len(ws) > 1,
              f"only {len(ws)} distinct weight(s): {sorted(ws)}")

        # ---- CHECK 3b: the ORDER is the same ------------------------------
        # Agreeing on the SET of gaps is not enough. `CONTROL/OPERATOR.md`
        # tells operators to follow `wks.cli gaps` ordering, and the
        # research worker walks `priority.weakest_classes()`. If those two
        # orderings differ, the operator is told to work a different class
        # than the system does.
        #
        # MEASURED 2026-10-31: they agreed on the set (26 of 26) but only
        # 1 of the top 3 in ORDER -- the priority engine used flat weights
        # and its own tie-break, while `gap_report` used the cost model in
        # `quality.maturity()`.
        gap_order = [x["class_id"] for x in gaps if x["state"] != "mature"]
        weak_order = [w["class_id"]
                      for w in priority.weakest_classes(con, limit=200)]
        check("the gaps queue and the research queue are the SAME ORDER",
              gap_order == weak_order,
              f"gaps: {gap_order[:6]} | weakest: {weak_order[:6]}")

        # ---- CHECK 4: the research queue is fed by this --------------------
        # The research worker builds its queue from `weakest_classes`. If
        # that call is disconnected from the gate's verdict, the whole
        # goal-selection chain is decorative.
        import inspect
        from orch import workers
        src = inspect.getsource(workers.research_cycle)
        check("the research worker reads the priority engine's weakest "
              "classes",
              "weakest_classes" in src,
              "research_cycle does not call weakest_classes")

    finally:
        con.close()

    print(f"\n{PASSES} checks, {len(FAILURES)} failed")
    if FAILURES:
        print("FAILED:")
        for f in FAILURES:
            print("  -", f)
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
