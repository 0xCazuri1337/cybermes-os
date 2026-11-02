"""Routing benchmark — does the router find the right capability class?

THE GAP THIS CLOSES
-------------------
MEASURED 2026-11-02: there was no labelled routing dataset anywhere in the
repository and no script that computed a routing metric. `eval/test_p0_
skill_registry.py` had five labelled scenarios, and its NEGATIVE branch —
the `else` that asserted a scenario should resolve to nothing — was dead
code that was never instantiated. So the router had never been measured, and
"the resolver works" was an assertion about a handful of hand-picked
scenarios rather than a property of the system.

THE METRICS, AND WHY EACH ONE IS HERE
-------------------------------------
A single aggregate score is not enough, and the mission names the specific
metrics. They are computed here from the same predictions, so they cannot
disagree:

  accuracy        fraction of tasks whose EXPECTED class appears among the
                  routed classes. This is the headline number, and it is the
                  one the 90% activation gate is measured against.
  precision       of the classes the router returned, how many were wanted.
                  A router that returns every class for every task scores
                  1.0 accuracy and a very low precision; both are reported.
  recall          of the classes that were wanted, how many the router
                  found.
  F1              the harmonic mean of the two, because a router that
                  finds nothing and a router that finds everything are
                  equally useless and only the balance between precision
                  and recall distinguishes them.
  exact match     the routed class set equals the expected class set
                  exactly. A router that returns the right class AND three
                  wrong ones is not an exact match, and reporting only
                  accuracy would hide that.
  false positives routes to a class the task did not ask for.
  false negatives routes that missed the expected class entirely.

Multi-label tasks are scored with micro and macro averages, as the mission
requires. The current dataset is single-label, but the scorer handles both,
because a router that is only ever measured on single-label tasks has not
been measured on the ambiguous ones.

NO FABRICATION
--------------
If the dataset does not cover a capability, the scorer says the capability
is `insufficiently_evaluated`. It does not score it as passing, and it does
not exclude it silently — a capability the benchmark never touches cannot
be activated, because the activation gate needs a measured routing rate.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BENCHMARK = ROOT / "runtime" / "routing_benchmark.json"


def load_dataset(path: Path = BENCHMARK) -> dict[str, Any]:
    """The labelled dataset. It is kept on disk so routing changes can be
    compared against the same tasks — a benchmark that is regenerated with
    the code it measures measures nothing."""
    if not path.is_file():
        raise FileNotFoundError(
            f"routing benchmark dataset not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    tasks = data.get("tasks") or []
    if len(tasks) < 50:
        raise ValueError(
            f"the routing dataset has {len(tasks)} tasks; the acceptance "
            f"criterion is at least 50")
    seen: set[str] = set()
    for task in tasks:
        tid = str(task.get("id") or "")
        if not tid:
            raise ValueError("a routing task has no id")
        if tid in seen:
            raise ValueError(f"duplicate routing task id: {tid}")
        seen.add(tid)
        if not task.get("expected_class"):
            raise ValueError(f"routing task {tid} has no expected_class")
    return data


def _classes_of(routed: list[str], registry: dict[str, Any]) -> set[str]:
    """The capability classes a routing result covers.

    A routed skill path maps to its class through the registry's own class
    fields, so the scorer does not re-derive the taxonomy in a second place.

    MEASURED 2026-11-02: this originally read only `capability_class`, which
    is populated for the executable capabilities under `skills/capabilities/`
    and EMPTY for the generated domain skills under `domains/`. The router
    routes a class scenario to its DOMAIN skill (`domains/web/sqli/skills/
    SKILL.md`), whose class lives in `class_id`, so every routed class came
    back empty and the benchmark scored 18.5% for a resolver that was
    actually finding the right class. The scorer now reads `class_id` first
    — it is the taxonomy's own field — and falls back to `capability_class`.
    """
    skills = registry.get("skills") or {}
    out: set[str] = set()
    for path in routed:
        rec = skills.get(path) or {}
        klass = rec.get("class_id") or rec.get("capability_class") or ""
        if klass:
            out.add(klass)
    return out


def score(registry: dict[str, Any], dataset: dict[str, Any], *,
          resolver: Any = None, limit: int = 8) -> dict[str, Any]:
    """Score the router against the labelled dataset.

    `resolver` is the callable under test. It receives
    `(registry, scenario, mode, limit)` and returns the resolver's dict.
    The default is the registry's own `resolve_scenario`, which is the
    function the runtime actually uses — a benchmark that scored a
    re-implementation would measure the wrong thing.
    """
    if resolver is None:
        from scripts import skill_registry as _sr  # type: ignore
        resolver = _sr.resolve_scenario

    tasks = dataset.get("tasks") or []
    mode = str(dataset.get("mode") or "test")

    per_task: list[dict[str, Any]] = []
    true_pos = 0
    false_pos = 0
    false_neg = 0
    exact_hits = 0
    routed_total = 0
    expected_total = 0
    covered_classes: set[str] = set()

    for task in tasks:
        scenario = str(task.get("scenario") or "")
        expected = {str(task["expected_class"])} if isinstance(
            task.get("expected_class"), str) else {
            str(x) for x in (task.get("expected_class") or [])}
        result = resolver(registry, scenario, mode=mode, limit=limit)
        routed_paths = list(result.get("paths") or [])
        routed = _classes_of(routed_paths, registry)

        hits = expected & routed
        extras = routed - expected
        misses = expected - routed
        tp = len(hits)
        fp = len(extras)
        fn = len(misses)
        true_pos += tp
        false_pos += fp
        false_neg += fn
        routed_total += len(routed)
        expected_total += len(expected)
        covered_classes |= expected
        if not extras and not misses:
            exact_hits += 1
        per_task.append({
            "id": task.get("id"),
            "scenario": scenario,
            "expected": sorted(expected),
            "routed": sorted(routed),
            "routed_paths": routed_paths,
            "hits": sorted(hits),
            "false_positives": sorted(extras),
            "false_negatives": sorted(misses),
            "matched_by": [s.get("matched_by") for s in (result.get("skills") or [])],
            "note": str(result.get("note") or ""),
        })

    n = len(tasks) or 1
    accuracy = sum(1 for t in per_task if t["hits"]) / n
    exact_rate = exact_hits / n
    precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) else 0.0
    recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fp_route_rate = false_pos / routed_total if routed_total else 0.0
    fn_route_rate = false_neg / expected_total if expected_total else 0.0

    return {
        "dataset": dataset.get("version"),
        "tasks": len(tasks),
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "exact_match_rate": round(exact_rate, 4),
        "false_positive_routes": false_pos,
        "false_negative_routes": false_neg,
        "false_positive_route_rate": round(fp_route_rate, 4),
        "false_negative_route_rate": round(fn_route_rate, 4),
        "classes_covered": len(covered_classes),
        "micro": {
            "true_positives": true_pos,
            "false_positives": false_pos,
            "false_negatives": false_neg,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
        },
        "macro": _macro(per_task),
        "per_task": per_task,
    }


def _macro(per_task: list[dict[str, Any]]) -> dict[str, Any]:
    """Macro averages: the mean of the per-task scores.

    Reported alongside the micro figures because a single task that routed
    twenty classes can dominate the micro numbers. The macro figure says
    what the typical task looks like.
    """
    if not per_task:
        return {"precision": 0.0, "recall": 0.0, "f1": 0.0}
    precisions: list[float] = []
    recalls: list[float] = []
    f1s: list[float] = []
    for task in per_task:
        tp = len(task["hits"])
        fp = len(task["false_positives"])
        fn = len(task["false_negatives"])
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        precisions.append(p)
        recalls.append(r)
        f1s.append(2 * p * r / (p + r) if (p + r) else 0.0)
    return {
        "precision": round(sum(precisions) / len(precisions), 4),
        "recall": round(sum(recalls) / len(recalls), 4),
        "f1": round(sum(f1s) / len(f1s), 4),
    }


def coverage_by_class(registry: dict[str, Any],
                      dataset: dict[str, Any]) -> dict[str, Any]:
    """Which capability classes the dataset exercises.

    A class the dataset never mentions is `insufficiently_evaluated`: the
    activation gate needs a measured routing rate, and a class with no
    labelled task has none.
    """
    expected = set()
    for task in dataset.get("tasks") or []:
        value = task.get("expected_class")
        if isinstance(value, str):
            expected.add(value)
        else:
            expected.update(str(x) for x in (value or []))
    registered = set(registry.get("capability_routes") or {})
    covered = sorted(expected & registered)
    uncovered = sorted(expected - registered)
    unmeasured = sorted(registered - expected)
    return {
        "expected_classes": len(expected),
        "registered_capability_classes": len(registered),
        "covered": covered,
        "uncovered": uncovered,
        "registered_but_unmeasured": unmeasured,
        "sufficiently_evaluated": len(covered),
        "insufficiently_evaluated": len(unmeasured),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        prog="routing_benchmark",
        description="Score the capability router against the labelled dataset.")
    ap.add_argument("--dataset", default=str(BENCHMARK))
    ap.add_argument("--json", action="store_true",
                    help="emit the full per-task report as JSON")
    ap.add_argument("--limit", type=int, default=8)
    ap.add_argument("--per-task", action="store_true",
                    help="list the tasks that missed")
    args = ap.parse_args(argv)

    from scripts import skill_registry as _sr  # type: ignore
    registry = _sr.load_registry()
    dataset = load_dataset(Path(args.dataset))
    report = score(registry, dataset, limit=args.limit)
    report["coverage"] = coverage_by_class(registry, dataset)

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0

    print(f"routing benchmark: {report['tasks']} labelled tasks")
    print(f"  accuracy        {report['accuracy']:.1%}")
    print(f"  precision       {report['precision']:.1%}")
    print(f"  recall          {report['recall']:.1%}")
    print(f"  f1              {report['f1']:.1%}")
    print(f"  exact match     {report['exact_match_rate']:.1%}")
    print(f"  false positives {report['false_positive_routes']} "
          f"({report['false_positive_route_rate']:.1%} of routed classes)")
    print(f"  false negatives {report['false_negative_routes']} "
          f"({report['false_negative_route_rate']:.1%} of expected classes)")
    cov = report["coverage"]
    print(f"  classes         {cov['sufficiently_evaluated']} measured, "
          f"{cov['insufficiently_evaluated']} registered but unmeasured")
    if args.per_task:
        misses = [t for t in report["per_task"] if t["false_negatives"]]
        for task in misses:
            print(f"  MISS {task['id']}: {task['scenario']}")
            print(f"       expected {task['expected']} got {task['routed']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
