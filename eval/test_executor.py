"""Executor tests (spec §58 step 5: execute tools, with evidence).

The executor is the component that finally lets the orchestrator DO something,
so its tests are about honesty rather than mechanics:

  * A task must not complete without a real artifact.
  * Work already done must close as `superseded`, not re-fail forever.
  * Knowledge the gate rejected must be reported as rejected, never forced in.
  * A class must not be satisfied by ANOTHER class's evidence.
  * A handler that cannot find its input must refuse, not fabricate.

Every test runs against a sandboxed copy of the repository and database. The
ingest path touches the network, so the network-dependent assertions are
written to accept EITHER a successful ingest OR an explicit, reasoned refusal —
both are correct; silently claiming success is not.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

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


def sandbox() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="orch-exec-"))
    dest = tmp / "cyber"
    shutil.copytree(ROOT, dest, ignore=shutil.ignore_patterns(
        "quarantine", "*.tar.gz", "__pycache__"))
    shutil.copy2(ROOT / "db" / "wks.db", dest / "db" / "wks.db")
    return dest


def main() -> int:
    root = sandbox()
    os.environ["WKS_ROOT"] = str(root)
    sys.path.insert(0, str(root))
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]
    from orch import agents, dag, executor, orchestrator, store, validate

    con = store.open_db()

    print("E1 handler selection is by task shape")
    # Real rows, not a fake object: handlers access them by subscript, so a
    # stand-in with attributes would fail for the wrong reason.
    for key, want in (("research.sqli", "do_research"),
                      ("seed.xsrf.research", "do_research"),
                      ("h.sys.audit", "do_audit"),
                      ("h.misc.audit", "do_audit"),
                      ("h.nightly.report", "do_synthesize"),
                      ("h.random.task", "do_maintenance")):
        store.add_task(con, key, key, expected_artifact="x")
        con.commit()
        row = store.get_task(con, key)
        got = executor.pick_handler(row).__name__
        check(f"{key} -> {want}", got == want, f"got {got}")

    print("\nE2 a class is not satisfied by another class's evidence")
    check("ad_ldap does not satisfy ad_kerberos",
          not executor._belongs("ad_ldap.something", "ad_kerberos"),
          "prefix collision")
    check("ad_kerberos.something does satisfy ad_kerberos",
          executor._belongs("ad_kerberos.something", "ad_kerberos"), "")
    check("exact class id counts as belonging",
          executor._belongs("csrf", "csrf"), "")
    check("a longer id that starts the same is rejected",
          not executor._belongs("csrfzz.x", "csrf"), "prefix collision")

    print("\nE3 non-item intake payloads are not mistaken for items")
    d = root / "research" / "incoming"
    (d / "_t_chains.json").write_text(json.dumps(
        {"chains": [{"chain_key": "x", "name": "n", "goal": "g",
                     "steps": []}]}), encoding="utf-8")
    (d / "_t_items.json").write_text(json.dumps(
        {"items": [{"item_key": "zzz.one", "claim": "c", "kind": "technique",
                    "claim_": "", "sources": []}]}), encoding="utf-8")
    (d / "_t_broken.json").write_text("{not json", encoding="utf-8")
    (d / "_t_bare_list.json").write_text(json.dumps(
        [{"item_key": "yyy.one", "claim": "c"}]), encoding="utf-8")
    check("a chains-only file is not counted as items",
          executor._pending_files("zzz") == [d / "_t_items.json"],
          str([p.name for p in executor._pending_files("zzz")]))
    check("a bare list of items IS read",
          (d / "_t_bare_list.json") in executor._pending_files("yyy"),
          str([p.name for p in executor._pending_files("yyy")]))
    check("a malformed file is skipped, not fatal",
          (d / "_t_broken.json") not in executor._pending_files("zzz"),
          "crash or silent accept")

    print("\nE4 a task with no input is refused, not faked")
    from wks import store as wstore
    wstore.upsert_class(con, "zzempty", "Empty Class", "web")
    con.execute("INSERT OR IGNORE INTO task(task_key, objective, class_id,"
                " priority, status, expected_artifact, created_at, updated_at)"
                " VALUES ('research.zzempty','research it','zzempty',3,'ready',"
                "'an artifact','now','now')")
    con.commit()
    row = store.get_task(con, "research.zzempty")
    try:
        executor.do_research(con, row)
        check("missing input is refused", False, "no error raised")
    except executor.ExecutorError as e:
        check("missing input is refused", True)
        # `zzempty` has no seed sources, so the handler cannot research it
        # either. It must say WHICH route failed and how far it got, not just
        # that something is missing: an operator reading the refusal should be
        # able to tell "no human wrote an intake file" from "the class has no
        # normative sources, so no amount of retrying will help". The two need
        # different fixes, and a single word match cannot tell them apart.
        #
        # The old assertion looked for the literal word "intake", which was
        # correct while the handler could only ingest. It now researches first,
        # so an unresearchable class fails on sources instead, and a message
        # that still said "intake" would be misleading: there is no intake file
        # to write, and retrying will not produce one.
        msg = str(e)
        check("the refusal distinguishes 'no intake' from 'no sources'",
              ("normative" in msg or "seed" in msg) and "source" in msg.lower(),
              msg)

    print("\nE5 bind() matches the orchestrator's (row, ctx) call shape")
    run = executor.bind(con)
    r2 = run(store.get_task(con, "research.zzempty") if
             store.get_task(con, "research.zzempty") else None, {})
    check("bind returns a 2-arg callable", isinstance(r2, dict), str(type(r2)))
    check("bind reports failure instead of raising", r2["ok"] is False, str(r2))
    check("bind names the handler", "handler" in r2, str(r2))

    print("\nE6 maintenance produces a real artifact")
    res = executor.do_maintenance(con, store.get_task(con, "research.zzempty"))
    check("maintenance succeeds", res["ok"], str(res)[:120])
    check("maintenance reports changes", isinstance(res.get("changed"), int),
          str(res.get("changed")))
    check("the summary names real numbers",
          "re-gated" in res["summary"] and "item" in res["summary"],
          res["summary"][:120])

    print("\nE7 synthesize writes a file that exists")
    r3 = executor.do_synthesize(con, store.get_task(con, "research.zzempty"))
    p = Path(r3["artifact_path"])
    check("the artifact path is returned", bool(r3.get("artifact_path")),
          str(r3)[:100])
    check("the artifact file exists", p.exists(), str(p))
    check("the artifact is non-trivial", p.exists() and len(
        p.read_text(encoding="utf-8")) > 100, str(p))

    print("\nE8 an audit task writes a report and reports health honestly")
    r4 = executor.do_audit(con, store.get_task(con, "research.zzempty"))
    check("audit returns a health verdict", "self-audit" in r4["summary"],
          r4["summary"][:120])
    check("the report exists",
          Path(r4["artifact_path"]).exists(), str(r4.get("artifact_path")))

    print("\nE9 'superseded' is distinct from 'completed'")
    # A maintenance task needs the claim to happen first: `bind` alone runs the
    # handler, and the orchestrator's claim/gate path is what sets the state.
    store.add_task(con, "sup.test", "maintenance work",
                   expected_artifact="artifact recorded")
    store.set_status(con, "sup.test", "ready")
    dag.refresh_readiness(con)
    from orch import orchestrator as _orch
    _orch.run(con, executor=executor.bind(con), max_tasks=1,
              checkpoint_label="sup",
              task_filter=lambda r: r["task_key"] == "sup.test")
    check("a maintenance task completes normally",
          store.get_task(con, "sup.test")["status"] == "completed",
          store.get_task(con, "sup.test")["status"])

    # now force the superseded path through agents.complete_run
    store.add_task(con, "sup.two", "already ingested", expected_artifact="x")
    store.set_status(con, "sup.two", "ready")
    dag.refresh_readiness(con)
    store.start_agent_run(con, "run-sup.two", "executor", "x",
                          task_key="sup.two")
    agents.complete_run(con, "run-sup.two",
                       {"ok": True, "superseded": True,
                        "summary": "all 5 entries were already ingested; "
                                   "nothing left to do"},
                       task_key="sup.two")
    check("superseded work is marked superseded, not completed",
          store.get_task(con, "sup.two")["status"] == "superseded",
          store.get_task(con, "sup.two")["status"])

    print("\nE10 an executor failure never completes the task")
    store.add_task(con, "fail.test", "will fail", expected_artifact="x")
    store.set_status(con, "fail.test", "ready")
    dag.refresh_readiness(con)
    store.start_agent_run(con, "run-fail.test", "executor", "x",
                          task_key="fail.test")
    agents.complete_run(con, "run-fail.test",
                       {"ok": False, "error": "no intake file"},
                       task_key="fail.test")
    st = store.get_task(con, "fail.test")["status"]
    check("a failed run leaves the task un-completed",
          st in ("failed", "retrying"), st)

    print("\nE11 a success with no artifact does not complete")
    store.add_task(con, "noart.test", "no artifact", expected_artifact="x")
    store.set_status(con, "noart.test", "ready")
    dag.refresh_readiness(con)
    store.start_agent_run(con, "run-noart.test", "executor", "x",
                          task_key="noart.test")
    agents.complete_run(con, "run-noart.test", {"ok": True},
                        task_key="noart.test")
    st2 = store.get_task(con, "noart.test")["status"]
    check("ok=True without an artifact does NOT complete",
          st2 != "completed", st2)

    print("\nE12 a stale wave entry is NOT reported as a failure")
    # Reproduced in a live run: `pending` is computed once per wave, so a task
    # can reach a terminal state before the loop reaches it. `store.claim`
    # then refuses, and that refusal was printed as FAIL for a task that was
    # really `superseded` with a valid artifact.
    store.add_task(con, "stale.one", "first in wave",
                   expected_artifact="artifact one")
    store.add_task(con, "stale.two", "second in wave",
                   expected_artifact="artifact two")
    con.commit()
    dag.refresh_readiness(con)

    def completes_the_other(row, ctx):
        # Complete BOTH tasks on the first call, so the second is already
        # terminal when the wave reaches it — exactly the race.
        other = ("stale.two" if row["task_key"] == "stale.one" else "stale.one")
        store.set_status(con, other, "completed", result="finished by peer")
        return {"ok": True,
                "summary": f"artifact recorded for {row['task_key']} in wave"}

    _orch.run(con, executor=completes_the_other, max_tasks=4,
              checkpoint_label="stale",
              task_filter=lambda r: r["task_key"].startswith("stale."))
    rep = _orch.run(con, executor=completes_the_other, max_tasks=4,
                    checkpoint_label="stale2",
                    task_filter=lambda r: r["task_key"].startswith("stale."))
    statuses = {e["task_key"]: e["status"] for e in rep["executed"]}
    check("no entry is reported 'failed' for a stale listing",
          all(s != "failed" for s in statuses.values()), str(statuses))
    check("stale entries are reported as already_done or completed",
          all(s in ("already_done", "completed", "no_executor")
              for s in statuses.values()), str(statuses))

    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)

    print()
    if FAILURES:
        print(f"EXECUTOR: {PASSES} passed, {len(FAILURES)} FAILED")
        for f in FAILURES:
            print(f"  - {f}")
        return 1
    print(f"EXECUTOR: ALL {PASSES} CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())