"""`python -m orch.omh_cli` -- the OMH entry point into Cyber.

Separate from `orch.cli` and `wks.cli` on purpose. `orch.cli` is the
orchestrator's own surface and `wks.cli` is the knowledge engine's; this one
exists so that OMH can be driven, inspected and audited without being able to
reach the internals of either. Every subcommand is an adapter over
`orch.omh`, and every one of them prints what Cyber actually decided -- never
what OMH hoped would happen.

Subcommands
-----------
  brief TASK                 Cyber -> OMH: build a mission contract
  lanes TASK                 Phase 5: derive parallel lanes from the surface
  authz TARGET               Phase 8: ask the hard gate before any testing
  research CLASS --items F   Phase 3: land a research payload for the gate
  gap CLASS                  what Cyber says is missing for this class
  unknown DESCRIPTION        Phase 9: open both paths for an unknown
  refuted HYP_KEY --why ...  Phase 10: failure -> research
  loop open|iterate|state|stopcheck|stop   Phase 13
  qa FINDING --validator R   Phase 15: adversarial verification
  report                     one screen of what the integration has done
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from wks import config as wks_config

from . import omh, store


def _out(obj: Any) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _con():
    con = store.open_db(create=True)
    store.migrate_tasks(con)
    return con


def _load_items(path: str) -> list[dict[str, Any]]:
    p = Path(path)
    raw = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        return list(raw.get("items") or [])
    if isinstance(raw, list):
        return [i for i in raw if isinstance(i, dict)]
    raise SystemExit(f"REFUSED: {path} is neither an object nor a list")


# ---------------------------------------------------------------------------


def cmd_brief(args) -> int:
    con = _con()
    m = omh.MissionContract(task_key=args.task, objective="",
                            target=args.target or "",
                            workflows=tuple(args.workflow or ()))
    try:
        _out(m.to_payload(con))
    except KeyError as e:
        print(f"REFUSED: {e}")
        return 2
    finally:
        con.close()
    return 0


def cmd_lanes(args) -> int:
    con = _con()
    m = omh.MissionContract(task_key=args.task, objective="",
                            target=args.target or "")
    try:
        _out(omh.plan_lanes(m, con, classes=args.classes))
    except KeyError as e:
        print(f"REFUSED: {e}")
        return 2
    finally:
        con.close()
    return 0


def cmd_authz(args) -> int:
    con = _con()
    gate = omh.AuthorizationGate(
        target=args.target, program=args.program or "",
        action=args.action,
        in_scope_assets=list(args.in_scope or ()),
        out_of_scope_assets=list(args.out_of_scope or ()),
        forbidden_actions=list(args.forbidden or ()))
    v = gate.check(con, action=args.action)
    _out(v)
    con.close()
    return 0 if v["allowed"] else 3


def cmd_gap(args) -> int:
    _out(omh.research_gap(args.class_id))
    return 0


def cmd_research(args) -> int:
    items = _load_items(args.items)
    r = omh.write_research_intake(args.class_id, items,
                                  notes=args.notes or "")
    _out(r)
    return 0 if r.get("ok") else 2


def cmd_unknown(args) -> int:
    con = _con()
    _out(omh.research_during_hunt(
        con, args.hunt_id, description=args.description,
        signals=list(args.signal or ())))
    con.close()
    return 0


def cmd_refuted(args) -> int:
    con = _con()
    _out(omh.failure_to_learning(con, hyp_key=args.hypothesis,
                                 failure_detail=args.why or ""))
    con.close()
    return 0


def cmd_loop_open(args) -> int:
    con = _con()
    key = omh.open_loop(con, mission=args.mission, objective=args.objective,
                        target=args.target or "", hunt_id=args.hunt_id or "",
                        budget=args.budget)
    _out({"loop_key": key, "state": "running", "budget": args.budget})
    con.close()
    return 0


def cmd_loop_iterate(args) -> int:
    con = _con()
    _out(omh.record_iteration(con, args.loop_key, phase=args.phase,
                              objective=args.objective or "",
                              hypothesis=args.hypothesis or "",
                              knowledge_state=args.knowledge_state or ""))
    con.close()
    return 0


def cmd_loop_state(args) -> int:
    con = _con()
    _out(omh.loop_state(con, args.loop_key))
    con.close()
    return 0


def cmd_loop_stopcheck(args) -> int:
    con = _con()
    v = omh.loop_may_continue(con, args.loop_key)
    _out(v)
    con.close()
    return 0 if v["continue"] else 3


def cmd_loop_stop(args) -> int:
    con = _con()
    _out(omh.stop_loop(con, args.loop_key, args.reason))
    con.close()
    return 0


def cmd_qa(args) -> int:
    con = _con()
    v = omh.qa_finding(con, args.finding, validator_run=args.validator,
                       claimant_run=args.claimant,
                       reproduced=args.reproduced)
    _out(v)
    con.close()
    return 0 if v.get("report_ready") else 3


def cmd_report(args) -> int:
    con = _con()
    _out(omh.integration_report(con))
    con.close()
    return 0


# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="orch.omh_cli",
                                description="OMH orchestration over the "
                                            "Cyber authority layer")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("brief", help="Cyber -> OMH mission contract")
    s.add_argument("task")
    s.add_argument("--target", default="")
    s.add_argument("--workflow", action="append")
    s.set_defaults(fn=cmd_brief)

    s = sub.add_parser("lanes", help="derive parallel lanes")
    s.add_argument("task")
    s.add_argument("--target", default="")
    s.add_argument("--class", dest="classes", action="append")
    s.set_defaults(fn=cmd_lanes)

    s = sub.add_parser("authz", help="Phase 8 hard authorization gate")
    s.add_argument("target")
    s.add_argument("--program", default="")
    s.add_argument("--action", default="scan")
    s.add_argument("--in-scope", action="append")
    s.add_argument("--out-of-scope", action="append")
    s.add_argument("--forbidden", action="append")
    s.set_defaults(fn=cmd_authz)

    s = sub.add_parser("gap", help="what is missing for a class")
    s.add_argument("class_id")
    s.set_defaults(fn=cmd_gap)

    s = sub.add_parser("research", help="write a research intake file")
    s.add_argument("class_id")
    s.add_argument("--items", required=True)
    s.add_argument("--notes", default="")
    s.set_defaults(fn=cmd_research)

    s = sub.add_parser("unknown", help="Phase 9: open both paths")
    s.add_argument("description")
    s.add_argument("--hunt-id", default="default")
    s.add_argument("--signal", action="append")
    s.set_defaults(fn=cmd_unknown)

    s = sub.add_parser("refuted", help="Phase 10: failure -> learning")
    s.add_argument("hypothesis")
    s.add_argument("--why", default="")
    s.set_defaults(fn=cmd_refuted)

    s = sub.add_parser("loop", help="Phase 13 loop control")
    ls = s.add_subparsers(dest="lcmd", required=True)
    a = ls.add_parser("open")
    a.add_argument("--mission", required=True)
    a.add_argument("--objective", required=True)
    a.add_argument("--target", default="")
    a.add_argument("--hunt-id", default="")
    a.add_argument("--budget", type=int, default=3)
    a.set_defaults(fn=cmd_loop_open)
    a = ls.add_parser("iterate")
    a.add_argument("loop_key")
    a.add_argument("--phase", required=True)
    a.add_argument("--objective", default="")
    a.add_argument("--hypothesis", default="")
    a.add_argument("--knowledge-state", default="")
    a.set_defaults(fn=cmd_loop_iterate)
    a = ls.add_parser("state")
    a.add_argument("loop_key")
    a.set_defaults(fn=cmd_loop_state)
    a = ls.add_parser("stopcheck")
    a.add_argument("loop_key")
    a.set_defaults(fn=cmd_loop_stopcheck)
    a = ls.add_parser("stop")
    a.add_argument("loop_key")
    a.add_argument("--reason", required=True)
    a.set_defaults(fn=cmd_loop_stop)

    s = sub.add_parser("qa", help="Phase 15 adversarial verification")
    s.add_argument("finding")
    s.add_argument("--validator", required=True)
    s.add_argument("--claimant", default="")
    s.add_argument("--reproduced", action="store_true")
    s.set_defaults(fn=cmd_qa)

    s = sub.add_parser("report", help="integration status")
    s.set_defaults(fn=cmd_report)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())