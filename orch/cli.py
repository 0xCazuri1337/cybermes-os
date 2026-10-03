"""`python -m orch.cli` — the orchestration surface.

Separate entry point from `wks.cli` on purpose: the knowledge engine and the
orchestrator have different jobs and different invariants, and merging them
would mean a change to research plumbing could take down task scheduling. Both
read and write the same database, so they stay consistent by construction.

Every subcommand prints something a human can act on. A CLI that prints nothing
but "ok" makes an unattended run unobservable, which is the one thing this
system cannot afford.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from wks import config as wks_config

from . import (agents, dag, events, orchestrator, priority, scheduler,
               selfaudit, store, validate, workers)


def _out(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _con():
    con = store.open_db(create=True)
    store.migrate_tasks(con)
    return con


# ---------------------------------------------------------------------------

def cmd_graph(args) -> int:
    con = _con()
    rep = dag.graph_report(con)
    if args.verbose and rep["blocked_detail"]:
        rep["blocked_detail"] = rep["blocked_detail"]
    _out(rep)
    con.close()
    return 1 if rep["cycles"] or rep["dangling_deps"] else 0


def cmd_ready(args) -> int:
    con = _con()
    dag.refresh_readiness(con)
    rows = dag.ready_tasks(con, limit=args.limit)
    print(f"READY TASKS: {len(rows)}")
    for r in rows:
        print(f"  [{r['priority']}] {r['task_key']}: {r['objective'][:70]}")
    con.close()
    return 0


def cmd_priority(args) -> int:
    con = _con()
    dag.refresh_readiness(con)
    ranked = priority.rank(con, limit=args.limit)
    print("RANKED READY WORK")
    for i, t in enumerate(ranked, 1):
        print(f"  {i:2}. {t['score']:.4f}  {t['task_key']} "
              f"(gates {t['unblocks']})")
        print(f"      {t['objective'][:72]}")
    if args.explain and ranked:
        print()
        print(priority.explain(con, ranked[0]["task_key"]))
    con.close()
    return 0


def cmd_decompose(args) -> int:
    con = _con()
    keys = orchestrator.decompose(con, args.goal, prefix=args.prefix,
                                  expected_artifact=args.artifact,
                                  evidence_req=args.evidence)
    print(f"DECOMPOSED '{args.goal}' into {len(keys)} task(s):")
    for k in keys:
        row = store.get_task(con, k)
        print(f"  [{row['status']:8}] {k}")
    _out(dag.graph_report(con)["by_status"])
    con.close()
    return 0


def cmd_run(args) -> int:
    """Execute ready work.

    `--execute` binds the REAL executor (orch/executor.py), which performs
    research and maintenance and produces real artifacts. It is opt-in, never
    the default: without it the run schedules and honestly reports that nothing
    executed, which is the correct behaviour when no executor was asked for.

    `--demo` remains refused without `--sandbox`, and the demo executor is now
    deliberately weaker than the real one — it exists to prove the machinery
    moves, not to fake research.
    """
    con = _con()
    if args.demo:
        if not args.sandbox:
            print("REFUSED: --demo would mark real research tasks completed.\n"
                  "        Re-run with --sandbox to run against a throwaway "
                  "copy of the database.")
            con.close()
            return 2
        con.close()
        return _demo_run(args)

    if args.execute:
        from . import executor as _ex
        # The REAL executor, bound to this connection. Failures are reported
        # per task with their reason; a task that cannot be honestly completed
        # stays incomplete with its retry budget intact.
        report = orchestrator.run(con, executor=_ex.bind(con),
                                  max_tasks=args.max_tasks,
                                  checkpoint_label=args.label)
        print(f"RUN (real executor): {len(report['executed'])} executed, "
              f"stop={report['stop_reason']}")
        for e in report["executed"]:
            # `already_done` means the wave listing was stale and the task was
            # finished by something else — not a failure.
            mark = "skip" if e["status"] == "already_done" else (
                "ok  " if e["status"] == "completed" else "FAIL")
            print(f"  [{mark}] {e['task_key']}")
            if e.get("detail"):
                print(f"         {str(e['detail'])[:110]}")
        # Only genuine failures count against the run; a stale wave entry is not
        # work that failed, it is work someone else already did.
        failed = [e for e in report["executed"]
                  if e["status"] not in ("completed", "already_done")]
        done = len(report["executed"]) - len(failed)
        print(f"\n  completed {done}/{len(report['executed'])}; "
              f"{len(failed)} genuine failure(s) keep their retry budget and "
              f"stay visible in the backlog.")
        path = orchestrator.write_report(con, report, name="run")
        print(f"  report: {path}")
        con.close()
        return 0 if not failed else 1

    # No executor bound: the orchestrator advances nothing and says so.
    report = orchestrator.run(con, executor=None, max_tasks=args.max_tasks,
                              checkpoint_label=args.label)
    print(f"RUN: {len(report['executed'])} dispatched, "
          f"stop={report['stop_reason']}")
    print(f"  orphans recovered : {report['orphans_recovered']}")
    print(f"  cycles repaired   : {len(report['cycles_repaired'])}")
    print("  NOTE: no executor bound. Tasks were scheduled, NOT completed.")
    print("        Use --execute to perform the work for real.")
    for e in report["executed"][:15]:
        print(f"  [{e['status']:12}] {e['task_key']}")
    con.close()
    return 0


def _demo_run(args) -> int:
    """Prove the machinery executes, against a throwaway database only."""
    import shutil
    import tempfile

    tmp = Path(tempfile.mkdtemp(prefix="orch-demo-"))
    # config.db_path() resolves <root>/db/wks.db, so the copy must land in
    # <root>/db/ — copying to <root>/wks.db yields a database that silently
    # does not exist from config's point of view.
    (tmp / "db").mkdir(parents=True, exist_ok=True)
    shutil.copy2(wks_config.db_path(), tmp / "db" / "wks.db")
    os.environ["WKS_ROOT"] = str(tmp)
    try:
        demo_con = store.open_db()

        def executor(row, ctx):
            return {"ok": True, "summary": f"DEMO artifact for {row['task_key']}"}

        report = orchestrator.run(demo_con, executor=executor,
                                  max_tasks=args.max_tasks,
                                  checkpoint_label="demo")
        print(f"DEMO (sandboxed at {tmp}): {len(report['executed'])} executed, "
              f"stop={report['stop_reason']}")
        for e in report["executed"][:15]:
            print(f"  [{e['status']:10}] {e['task_key']}")
        demo_con.close()
    finally:
        os.environ["WKS_ROOT"] = "C:/Users/Administrator/.hermes/cyber"
    print("Real database was NOT modified.")
    return 0


def cmd_audit(args) -> int:
    con = _con()
    result = selfaudit.audit(con)
    print(selfaudit.render(result))
    if args.write:
        out = wks_config.runtime_dir() /  "self-audit.md"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(selfaudit.render(result), encoding="utf-8")
        print(f"\nwritten: {out}")
    con.close()
    return 0 if result["health"] == "healthy" else 1


def cmd_workers(args) -> int:
    con = _con()
    out = workers.run_all(con, args.only)
    for name, r in out.items():
        mark = "ok  " if r.get("ok") else "FAIL"
        print(f"[{mark}] {name}: {str(r.get('result') or r.get('error'))[:100]}")
    print()
    print(workers.heartbeat_report(con))
    if args.schedule:
        print("\nSCHEDULE")
        for s in workers.schedule(con):
            print(f"  every {s['every_minutes']:3}min  {s['worker']:12} "
                  f"({s['why']})")
    con.close()
    return 0 if all(r.get("ok") for r in out.values()) else 1


def cmd_events(args) -> int:
    con = _con()
    if args.add:
        signals = json.loads(args.add)
        _out(events.ingest(con, signals))
    if args.pending is not None:
        pending = events.pending(con, args.pending)
        print(f"PENDING EVENTS (relevance >= {args.pending}): {len(pending)}")
        for e in pending:
            print(f"  {e['relevance']:.3f} [{e['kind']}] {e['event_key']}")
        if args.triage:
            _out(orchestrator.triage_events(con, threshold=args.pending))
    if not args.add and args.pending is None:
        _out(events.pending(con, 0.0))
    con.close()
    return 0


def cmd_validate(args) -> int:
    con = _con()
    if args.finding:
        v = validate.validate_finding(con, args.finding,
                                      reproduced=args.reproduced,
                                      claimant_run=args.claimant,
                                      validator_run=args.validator)
        _out(v)
        if args.apply:
            verdict = validate.apply_validation(con, args.finding, v)
            print(f"applied: {verdict}")
        con.close()
        return 0
    # no specific finding: audit every open candidate
    results = []
    for f in store.findings(con, "candidate"):
        v = validate.validate_finding(con, f["finding_key"])
        results.append({"finding_key": f["finding_key"], "verdict": v["verdict"],
                        "score": v["score"], "failed": v["levels_failed"]})
    _out(results)
    con.close()
    return 0


def cmd_findings(args) -> int:
    con = _con()
    if args.dedupe:
        _out(validate.dedupe(con))
    rows = store.findings(con, args.status)
    print(f"FINDINGS: {len(rows)}")
    for r in rows:
        print(f"  [{r['status']:14}] {r['finding_key']}: {r['title'][:60]}")
    con.close()
    return 0


def cmd_scope(args) -> int:
    con = _con()
    if args.grant:
        store.grant_scope(con, args.key, args.target, args.kind, args.ref,
                          offensive_allowed=args.offensive)
        print(f"granted {args.key}: {args.target} ({args.kind}) "
              f"offensive={args.offensive}")
    if args.check:
        _out(store.check_scope(con, args.check))
    if not args.grant and not args.check:
        for r in con.execute("SELECT * FROM scope_grant"):
            _out(dict(r))
    con.close()
    return 0


def cmd_resume(args) -> int:
    con = _con()
    cp = store.latest_checkpoint(con, args.scope)
    if not cp:
        print(f"no checkpoint for scope {args.scope!r}")
        con.close()
        return 1
    print(f"RESUME {args.scope}/{cp['label']} @ {cp['created_at']}")
    state = cp["state"]
    for k in ("stop_reason", "orphans_recovered"):
        if k in state:
            print(f"  {k}: {state[k]}")
    if "graph" in state:
        g = state["graph"]
        print(f"  nodes {g.get('nodes')} edges {g.get('edges')} "
              f"ready {g.get('ready')}")
    executed = state.get("executed") or []
    if executed:
        print(f"  previously executed: {len(executed)}")
        for e in executed[-10:]:
            print(f"    [{e['status']}] {e['task_key']}")
    con.close()
    return 0


def cmd_supervise(args) -> int:
    """Unattended multi-cycle supervision with a real stop condition."""
    con = _con()
    r = scheduler.supervise(con, max_cycles=args.cycles)
    print(scheduler.render_supervision(r))
    con.close()
    return 0 if r["final_audit"]["health"] == "healthy" else 1


def cmd_stopcheck(args) -> int:
    con = _con()
    sc = scheduler.has_useful_work(con)
    _out(sc)
    con.close()
    return 0


def cmd_gate(args) -> int:
    """Fingerprint, verify or re-baseline the quality gate."""
    from . import gate_guard
    con = _con()
    if args.baseline:
        if not args.reason:
            print("REFUSED: --baseline requires --reason.\n"
                  "        An unexplained hash change is indistinguishable "
                  "from tampering.")
            con.close()
            return 2
        r = gate_guard.baseline(con, reason=args.reason)
        gate_guard.remember_settings(con)
        print(f"baselined {len(r['baselined'])} file(s): "
              f"{', '.join(r['baselined'])}")
        print(f"reason: {r['reason']}")
        if r["archived"]:
            for a in r["archived"]:
                print(f"  archived previous: {a['file']} "
                      f"({a['previous_sha256'][:16]})")
        con.close()
        return 0
    v = gate_guard.verify(con)
    print(gate_guard.render(v))
    con.close()
    return 0 if v["ok"] else 1


def cmd_stats(args) -> int:
    con = _con()
    _out({
        "graph": {k: v for k, v in dag.graph_report(con).items()
                  if k != "blocked_detail"},
        "agents": agents.run_stats(con),
        "events": {r["state"]: r["n"] for r in con.execute(
            "SELECT state, count(*) n FROM event GROUP BY state")},
        "findings": {r["status"]: r["n"] for r in con.execute(
            "SELECT status, count(*) n FROM finding GROUP BY status")},
        "workers": workers.heartbeat_report(con),
        "recovery_attempts": con.execute(
            "SELECT count(*) n FROM recovery_attempt").fetchone()["n"],
        "checkpoints": con.execute(
            "SELECT count(*) n FROM checkpoint").fetchone()["n"],
    })
    con.close()
    return 0


def cmd_overnight(args) -> int:
    """The autonomous entry point.

    Reports what it can honestly report: the graph state, the self-audit, the
    next task, and whether more useful work exists. It does NOT bind a stub
    executor, because a stub makes the overnight report claim progress that no
    research produced — the failure mode invariant I10 exists to prevent.
    """
    con = _con()
    r = orchestrator.overnight(con, executor=None, max_tasks=args.max_tasks)
    print(f"OVERNIGHT: {len(r['cycle']['executed'])} task(s) scheduled "
          f"(NOT completed — no executor bound), stop={r['cycle']['stop_reason']}")
    print(f"  orphans recovered : {r['cycle']['orphans_recovered']}")
    print(f"  audit health      : {r['re_audit']['health']} "
          f"({r['re_audit']['passed']}/{r['re_audit']['total']})")
    for f in r["re_audit"]["failures"]:
        print(f"    FAILED {f['name']}: {f['detail'][:100]}")
    print(f"  weakest classes   : "
          f"{', '.join(w['class_id'] for w in r['weakest_classes']) or 'none'}")
    nt = r["next_task"]
    print(f"  next task         : {nt['task_key'] if nt else 'none'}")
    print(f"  continue          : {r['continue_work']}")
    con.close()
    return 0 if r["re_audit"]["health"] == "healthy" else 1


# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="orch", description="Hermes Cyber OS — orchestration layer")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("graph", help="task DAG report")
    sp.add_argument("-v", "--verbose", action="store_true")
    sp.set_defaults(fn=cmd_graph)

    sp = sub.add_parser("ready", help="tasks ready to run")
    sp.add_argument("--limit", type=int, default=20)
    sp.set_defaults(fn=cmd_ready)

    sp = sub.add_parser("priority", help="ranked ready work")
    sp.add_argument("--limit", type=int, default=15)
    sp.add_argument("--explain", action="store_true")
    sp.set_defaults(fn=cmd_priority)

    sp = sub.add_parser("decompose", help="goal -> dependency-aware tasks")
    sp.add_argument("goal")
    sp.add_argument("--prefix", default="goal")
    sp.add_argument("--artifact", default="")
    sp.add_argument("--evidence", default="")
    sp.set_defaults(fn=cmd_decompose)

    sp = sub.add_parser("run", help="execute ready work")
    sp.add_argument("--max-tasks", type=int, default=25)
    sp.add_argument("--execute", action="store_true",
                    help="bind the REAL executor (research + maintenance)")
    sp.add_argument("--demo", action="store_true",
                    help="smoke-test the machinery (requires --sandbox)")
    sp.add_argument("--sandbox", action="store_true",
                    help="required with --demo: run against a throwaway db copy")
    sp.add_argument("--label", default="manual")
    sp.set_defaults(fn=cmd_run)

    sp = sub.add_parser("audit", help="self-audit (structural/functional/behavioral)")
    sp.add_argument("--write", action="store_true")
    sp.set_defaults(fn=cmd_audit)

    sp = sub.add_parser("workers", help="run background workers")
    sp.add_argument("--only", nargs="*")
    sp.add_argument("--schedule", action="store_true")
    sp.set_defaults(fn=cmd_workers)

    sp = sub.add_parser("events", help="signal intake and triage")
    sp.add_argument("--add", help="JSON array of signals")
    sp.add_argument("--pending", type=float, nargs="?", const=0.0)
    sp.add_argument("--triage", action="store_true")
    sp.set_defaults(fn=cmd_events)

    sp = sub.add_parser("validate", help="L1-L6 validation")
    sp.add_argument("--finding")
    sp.add_argument("--reproduced", action="store_true")
    sp.add_argument("--claimant")
    sp.add_argument("--validator")
    sp.add_argument("--apply", action="store_true")
    sp.set_defaults(fn=cmd_validate)

    sp = sub.add_parser("findings", help="finding register")
    sp.add_argument("--status")
    sp.add_argument("--dedupe", action="store_true")
    sp.set_defaults(fn=cmd_findings)

    sp = sub.add_parser("scope", help="authorization gate")
    sp.add_argument("--grant", action="store_true")
    sp.add_argument("--key")
    sp.add_argument("--target")
    sp.add_argument("--kind", default="lab")
    sp.add_argument("--ref", default="")
    sp.add_argument("--offensive", action="store_true")
    sp.add_argument("--check")
    sp.set_defaults(fn=cmd_scope)

    sp = sub.add_parser("resume", help="last checkpoint for a scope")
    sp.add_argument("--scope", default="system")
    sp.set_defaults(fn=cmd_resume)

    sp = sub.add_parser("stats", help="one-screen orchestrator status")
    sp.set_defaults(fn=cmd_stats)

    sp = sub.add_parser("overnight", help="full autonomous iteration")
    sp.add_argument("--max-tasks", type=int, default=25)
    sp.set_defaults(fn=cmd_overnight)

    sp = sub.add_parser("supervise", help="unattended multi-cycle supervision")
    sp.add_argument("--cycles", type=int, default=3)
    sp.set_defaults(fn=cmd_supervise)

    sp = sub.add_parser("stopcheck", help="is there still useful work?")
    sp.set_defaults(fn=cmd_stopcheck)

    sp = sub.add_parser("gate", help="verify/fingerprint the quality gate")
    sp.add_argument("--baseline", action="store_true")
    sp.add_argument("--reason", default="")
    sp.set_defaults(fn=cmd_gate)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())