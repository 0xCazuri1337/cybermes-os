"""One autonomous improvement cycle (brief §21, §30).

Order matters, and it is the order in the brief:
  inspect state -> identify weakest area -> pick highest-value task -> gate ->
  resolve conflicts -> normalise -> update db + markdown + index -> quality
  checks -> evaluation -> record what changed -> generate next tasks.

Research is delegated, not done here: this module decides WHAT is worth
knowing and verifies WHAT came back. A cycle with nothing to improve still
produces an artifact — a gap report and a run record — so "no change" is always
distinguishable from "never ran".
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

from . import config, evalm, pipeline, quality, retrieval, store


def run_cycle(con: sqlite3.Connection, *, max_items: int = 5) -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    # Microsecond precision + a collision guard. A second-resolution key meant
    # every cycle inside one second reused the same run_key, so each cycle
    # overwrote the previous run record and the audit trail lost all but the
    # last — which is exactly the failure invariant R10 exists to prevent.
    base = started.strftime("run-%Y%m%dT%H%M%S%fZ")
    run_key = base
    n = 1
    while con.execute("SELECT 1 FROM run WHERE run_key=?", (run_key,)).fetchone():
        run_key = f"{base}-{n}"
        n += 1
    store.start_run(con, run_key)

    lines: list[str] = [f"# WKS cycle {run_key}", ""]
    changes: list[str] = []

    # 1-2. inspect + weakest area
    gaps = quality.gap_report(con)
    weakest = gaps[0] if gaps else None
    lines.append("## Inspected")
    lines.append(f"- classes: {len(gaps)}, items: "
                 f"{con.execute('SELECT count(*) n FROM item').fetchone()['n']}")
    if weakest:
        lines.append(f"- weakest: `{weakest['class_id']}` "
                     f"(priority {weakest['priority']}, missing "
                     f"{', '.join(weakest['missing']) or 'nothing'})")

    # 3. pick highest-value unfinished task
    task = store.next_task(con)
    lines.append("")
    lines.append("## Selected task")
    if task:
        lines.append(f"- `{task['task_key']}` — {task['objective']}")
        lines.append(f"  - expected artifact: {task['expected_artifact']}")
        lines.append(f"  - evidence required: {task['evidence_req']}")
        store.claim_task(con, task["task_key"], "master")
    else:
        lines.append("- none runnable; generating from measured gaps")
        pipeline.next_tasks(con)
        task = store.next_task(con)
        if task:
            lines.append(f"- `{task['task_key']}` — {task['objective']}")
            store.claim_task(con, task["task_key"], "master")

    # 4. re-gate everything (idempotent, catches regressions in existing items)
    # NOT bounded by `max_items`, deliberately. Re-gating a subset would
    # leave the rest of the corpus on whatever verdict it last had, so a
    # bounded re-gate is not a cheaper re-gate -- it is a WRONG one. The
    # bound applies to the projection passes (markdown, skills,
    # methodology), which are regenerable artifacts; the gate is the
    # corpus's correctness invariant.
    counts = quality.assess_all(con)
    promoted = counts.get("supported", 0) + counts.get("high_confidence", 0)
    if promoted:
        changes.append(f"re-gated corpus: {promoted} promoted, "
                       f"{counts.get('rejected', 0)} rejected")

    # 5. conflicts surfaced, never silently resolved
    conflicts = retrieval.open_conflicts(con)
    if conflicts:
        lines.append("")
        lines.append("## Open conflicts (unresolved, surfaced)")
        for c in conflicts[:5]:
            lines.append(f"- `{c['class_id']}` {c['topic']}: "
                         f"A: {c['claim_a'][:60]} / B: {c['claim_b'][:60]}")

    # 6-7. normalise: refresh class markdown for every class that has content.
    # A broken class must not kill the cycle, so each write is isolated.
    #
    # MEASURED 2026-10-31: `max_items` was accepted by this function and
    # applied to NOTHING. The markdown loop, the skill generator and the
    # methodology generator each processed every class in the corpus, so a
    # cycle the operator had bounded to 5 items did work proportional to
    # the whole corpus. The bound is now real: it caps the classes each
    # projection pass touches.
    written = []
    markdown_classes = [g for g in gaps if g["n_items"] > 0]
    if max_items is not None and max_items >= 0:
        markdown_classes = markdown_classes[:max_items]
    for g in markdown_classes:
        try:
            # Only count a document that actually changed. Rewriting
            # identical bytes and reporting "regenerated N documents" makes
            # every cycle look productive and hides the cycles that were not.
            if pipeline.write_class_markdown(con, g["class_id"]):
                written.append(g["class_id"])
        except Exception as e:
            lines.append(f"- markdown FAILED for {g['class_id']}: {e}")
    if written:
        changes.append(f"updated class documents: {', '.join(written)}")

    # 7b. skills are projections too; only classes with knowledge get one.
    from . import skillgen
    try:
        skill_res = skillgen.generate_all(con, limit=max_items)
        bumped = [r["class_id"] for r in skill_res if r["changed"]]
        if bumped:
            changes.append(f"updated skills: {', '.join(bumped)}")
    except Exception as e:
        lines.append(f"- skillgen FAILED: {e}")

    # 7c. Methodology is a projection of the same evidence, regenerated in the
    # same step. Left out, the hunting procedure silently drifts from the items
    # that justify it — the exact failure this evidence-derived design exists to
    # prevent.
    from . import methodgen
    try:
        meth_res = methodgen.generate_all(con, limit=max_items)
        if meth_res.get("written"):
            changes.append(f"regenerated methodology: "
                           f"{meth_res['written']} file(s)")
    except Exception as e:
        lines.append(f"- methodgen FAILED: {e}")

    # 8. retrieval index
    retrieval.rebuild_index(con)

    # 9-10. quality checks + evaluation
    m = evalm.metrics(con)
    probe = evalm.retrieval_probe(con)
    lines.append("")
    lines.append("## Quality metrics")
    lines.append(f"- items: {m['items_total']} | promoted: {m['items_promoted']} "
                 f"({m['promotion_rate_pct']}%)")
    lines.append(f"- unsupported-claim rate: {m['unsupported_claim_rate_pct']}%")
    lines.append(f"- duplicate rate: {m['duplicate_rate_pct']}% | "
                 f"stale rate: {m['stale_rate_pct']}%")
    lines.append(f"- items with a disproof clause: {m['disproof_rate_pct']}%")
    lines.append(f"- blocked on single host: {m['blocked_on_single_host']}")
    lines.append(f"- classes mature: {m['classes_mature']}/{m['classes']} "
                 f"({m['class_maturity_pct']}%)")
    lines.append(f"- FP rules: {m['false_positive_rules']} | chains: {m['chains']} "
                 f"| open conflicts: {m['open_conflicts']}")
    lines.append(f"- retrieval probe hit rate: {probe['hit_rate_pct']}% "
                 f"({probe['passed']}/{probe['probes']})")

    # 11. next tasks from the NEW measured gaps
    created = pipeline.next_tasks(con)
    if created:
        changes.append(f"generated {len(created)} follow-up tasks")

    # 12. record what changed
    lines.append("")
    lines.append("## Changed this cycle")
    if changes:
        lines += [f"- {c}" for c in changes]
    else:
        lines.append("- no state change (gap report recorded above is the artifact)")

    remaining = [g["class_id"] for g in gaps if g["state"] != "mature"]
    lines.append("")
    lines.append("## Remaining gaps")
    lines.append(f"- not mature: {', '.join(remaining[:25]) or 'none'}")

    summary = "\n".join(lines)
    metrics_blob = {"metrics": m, "retrieval_probe": probe,
                    "changed": changes, "gaps": gaps}
    store.finish_run(con, run_key, summary, metrics_blob)

    # Machine-readable report (§31)
    out = config.runtime_dir() /  f"{run_key}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics_blob, indent=2, default=str), encoding="utf-8")
    (config.runtime_dir() /  "LATEST.md").write_text(summary, encoding="utf-8")

    if task:
        # MEASURED 2026-10-31: this finished the task with the LEGACY
        # status "doing", which `store.normalise_task_status` maps to
        # "running". A task in `running` is counted as `in_flight` by
        # `orch.scheduler.has_useful_work`, so the orchestrator's stop
        # condition could NEVER fire once a WKS cycle had run -- the
        # unattended loop would keep claiming it had work in flight that
        # was, in fact, finished.
        #
        # The cycle DID complete the task, so it says so: "completed" is
        # the terminal status, and the result records where the artifact
        # is.
        store.finish_task(
            con, task["task_key"], "completed",
            result=f"cycle {run_key} executed; see state/{run_key}.json",
        )
    con.commit()
    return {"run_key": run_key, "summary": summary, "metrics": m,
            "probe": probe, "changed": changes}


def main(max_items: int = 5) -> int:
    con = store.open_db(create=True)
    r = run_cycle(con, max_items=max_items)
    print(r["summary"])
    con.close()
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(int(sys.argv[1]) if len(sys.argv) > 1 else 5))
