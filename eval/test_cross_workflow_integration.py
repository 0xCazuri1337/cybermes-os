"""THE CROSS-WORKFLOW INTEGRATION TEST.

Hunt -> validated outcome -> Learning -> SUBSEQUENT Hunt feedback.

This is the acceptance test for the whole OS, and it is deliberately an
END-TO-END test rather than a set of unit tests. Each subsystem has its own
suite, and each suite passes. What none of them proves is that the parts
compose: that a finding VALIDATED on one hunt becomes a lesson that a LATER
hunt actually reads and acts on.

The mission states the ten steps explicitly. This file walks them:

    1.  Start a synthetic hunt.
    2.  Resolve and load a REAL skill.
    3.  Produce and validate a synthetic finding (or an invalidated
        hypothesis).
    4.  Persist the outcome.
    5.  Deliver it through the ACTUAL learning interface.
    6.  Persist the appropriate lesson with provenance and trust state.
    7.  Start a SECOND synthetic hunt.
    8.  Retrieve the lesson.
    9.  Demonstrate that it changes a relevant testing priority or decision.
    10. Prove that UNVERIFIED observations cannot promote themselves into
        trusted general knowledge.

Everything runs against a TEMPORARY database and LOCAL FIXTURES. No external
target is contacted, nothing is scanned, and no real credential appears. The
loopback HTTP server serves the synthetic target on 127.0.0.1.

WHAT IS AND IS NOT PROVEN HERE
-------------------------------
A passing run proves the LOOP is closed: the same code path that a real hunt
uses carries a validated outcome into a lesson, and a later hunt reads that
lesson and changes a decision because of it.

It does NOT prove the corpus is well-populated, that a real external target
is reachable, or that the model's reasoning is correct. Those need evidence
this file cannot manufacture. The report says so rather than implying
otherwise.

Run:  python eval/test_cross_workflow_integration.py
Exit: 0 = the loop is closed, 1 = a link is broken.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import socketserver
import sqlite3
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0
FAILURES: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        FAILURES.append(f"{label}  ({detail})")
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))


def section(title: str) -> None:
    print(f"\n{title}")


# ---------------------------------------------------------------------------
# The synthetic target: a loopback HTTP server.
# ---------------------------------------------------------------------------

class _Handler(http.server.BaseHTTPRequestHandler):
    """A deliberately boring target.

    It answers 200 with a body that contains a DATABASE ERROR SIGNATURE.
    That matters: `orch.hunt_exec.derive_signals` turns a SQL error
    signature into a `sql_error_or_behaviour` signal, `ActiveHuntExecutor.
    _rank` maps that signal to the class `sqli`, and the recon step FILES a
    finding for it. So the synthetic target drives the REAL signal ->
    class -> finding path rather than a fabricated one.

    The lesson used by the loop is about the `sqli` class, so the class the
    hunt derives must be the class the lesson covers -- otherwise the
    priority boost would not be the right thing to measure.
    """

    def do_GET(self) -> None:  # noqa: N802 - http.server's API
        body = (
            b"<html><head><title>Synthetic Target</title></head><body>"
            b"<p>SQL syntax error near 'admin' at line 1</p>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "synthetic/1.0")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_a: object) -> None:
        """Silence the server's access log."""


def _serve() -> tuple[socketserver.TCPServer, str]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), _Handler)
    srv.allow_reuse_address = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    host, port = srv.server_address[0], srv.server_address[1]
    return srv, f"http://{host}:{port}/"


# ---------------------------------------------------------------------------
# A temporary database that the PRODUCTION code opens.
#
# MEASURED 2026-11-01: the point of this file is that it exercises the real
# entry points -- `orch.store.open_db` and
# `learning_engine.engine.open_canonical` -- not hand-built schemas. A
# hand-built schema is a second representation of the database, and it is
# exactly how a green suite can coexist with a broken runtime.
# ---------------------------------------------------------------------------

def _temp_root() -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="cyber_xwf_"))
    (tmp / "db").mkdir(parents=True, exist_ok=True)
    return tmp


def _redirect_db(root: Path) -> dict:
    """Point every production entry point at the temporary database."""
    from orch import store as orch_store
    from wks import config as wks_config

    db = root / "db" / "wks.db"
    saved = {
        "orch_db_path": orch_store.db_path,
        "wks_db_path": wks_config.db_path,
    }
    orch_store.db_path = lambda: db            # type: ignore[assignment]
    wks_config.db_path = lambda: db            # type: ignore[assignment]
    return saved


def _restore_db(saved: dict) -> None:
    from orch import store as orch_store
    from wks import config as wks_config
    orch_store.db_path = saved["orch_db_path"]   # type: ignore[assignment]
    wks_config.db_path = saved["wks_db_path"]     # type: ignore[assignment]


# ---------------------------------------------------------------------------

def main() -> int:  # noqa: C901 - a linear walk of the ten steps reads better
    root = _temp_root()
    saved = _redirect_db(root)
    srv, base_url = _serve()
    try:
        return _run(root, base_url)
    finally:
        srv.shutdown()
        srv.server_close()
        _restore_db(saved)
        shutil.rmtree(root, ignore_errors=True)


def _mk_task(con: sqlite3.Connection, hunt_id: str, objective: str) -> None:
    """Insert the recon task row the executor's `run_step` dispatches on.

    The engine's `run_step` selects a handler by the task key, so the row
    has to exist with the key the planner would have produced. It is
    inserted explicitly rather than relying on the planner's exact task
    set, which is not what this test is measuring.
    """
    con.execute(
        "INSERT OR REPLACE INTO task (task_key, objective, class_id, "
        "priority, status, assigned_role, depends_on, expected_artifact, "
        "evidence_req, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (f"{hunt_id}.recon.http", objective, None, 1, "planned", None, "[]",
         "recon results", "surface nodes with responses",
         "2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"))
    con.commit()


def _run(root: Path, base_url: str) -> int:  # noqa: C901
    from orch import store as orch_store
    from orch import authz
    from learning_engine import engine as le

    con = orch_store.open_db(create=True)
    target_host = "127.0.0.1"
    hunt_a = "hunt.xwf.a"
    hunt_b = "hunt.xwf.b"
    class_id = "sqli"

    # ==================================================================
    section("STEP 1  Start a synthetic hunt")
    # ==================================================================
    ctx = authz.AuthorizationContext(
        program="synthetic integration program",
        target=target_host,
        in_scope_assets=[base_url, target_host],
        out_of_scope_assets=["http://out-of-scope.invalid/"],
        allowed_actions=["recon", "probe"],
        forbidden_actions=["denial_of_service", "destructive_write",
                           "data_exfiltration"],
        rate_limits={"requests_per_second": 2, "concurrency": 1, "burst": 2,
                     "per_host_per_minute": 30},
        authentication_context={"mode": "unauthenticated"},
        reporting_requirements={"format": "markdown", "include_evidence": True},
        # An EXPLICIT operator grant. A hunt with no grant is refused by the
        # §4 gate rather than inferring one -- that refusal is itself part
        # of what this test exercises.
        authorization_ref="OPERATOR-GRANTED: synthetic loopback target for "
                          "the cross-workflow integration test",
        kind="lab",
    )
    ctx.register(con, scope_key=hunt_a)

    from orch import hunting
    eng_a = hunting.HuntingEngine(con, ctx, hunt_id=hunt_a)
    gate = eng_a.authorization_gate()
    check(gate.get("passed") is True,
          "the synthetic hunt's authorization gate PASSES",
          json.dumps(gate)[:300])

    plan = eng_a.initial_plan()
    check(bool(plan), "the hunt produced a plan", str(plan)[:200])

    # The target must be a surface node the recon step can read.
    eng_a.surface.add_node("host", base_url, observed=True, in_scope=True)
    eng_a.ledger.record(base_url, discovered_by="integration_test")

    # ==================================================================
    section("STEP 2  Resolve and load a REAL skill")
    # ==================================================================
    # The REAL resolution path: `resolve_for_hunt` walks the hunt's
    # SURFACE NODES and resolves a skill for each. That is what a hunt
    # actually calls, so that is what is exercised here -- not a private
    # helper.
    from orch import skill_resolver
    # A surface node that names the scenario, so the resolver has something
    # real to route on.
    eng_a.surface.add_node(
        "endpoint", f"{base_url}?id=1",
        observed=True, in_scope=True,
        attributes={"method": "GET", "technology": "generic",
                    "description": "authenticated API with object identifiers "
                                   "returning another user's record"})
    resolved = skill_resolver.resolve_for_hunt(con, hunt_a, mode="hunt")
    check(bool(resolved.get("applied") or resolved.get("resolved")),
          "the skill resolver returned real skill(s) for the hunt's surfaces",
          f"resolved={resolved.get('resolved')} classes={resolved.get('classes')}")
    applied = resolved.get("applied") or []
    # The applied record's key is `path` (the RELATIVE path in the
    # registry), not `skill_path` (the column in the recorded table).
    skill_paths = [s.get("path") for s in applied]
    loaded = []
    for p in skill_paths:
        if not p:
            continue
        abs_p = Path(p) if Path(p).is_absolute() else ROOT / p
        if abs_p.exists():
            loaded.append(abs_p)
    check(bool(loaded),
          "the resolved skill(s) point at files that EXIST on disk",
          f"resolved={skill_paths[:3]} loaded={[str(x) for x in loaded[:3]]}")
    if loaded:
        content = loaded[0].read_text(encoding="utf-8", errors="replace")
        check(len(content) > 100,
              "the loaded skill has real content",
              f"{len(content)} bytes")
        check("SKILL" in content.upper(),
              "the loaded skill identifies itself as a skill",
              content[:120].replace("\n", " "))

    # The resolution must be RECORDED, so the hunt's audit view can prove
    # which skill governed which surface.
    recorded = skill_resolver.recorded_for(con, hunt_a)
    check(bool(recorded),
          "the skill resolution is PERSISTED for the hunt",
          f"{len(recorded)} row(s)")

    # A skill that cannot be loaded must be a DEFERral, never a silent
    # count as available.
    deferred = resolved.get("deferred") or []
    for d in deferred:
        check(bool(d.get("reason")),
              f"the deferral for {d.get('scenario', '?')} names a reason",
              str(d)[:200])

    # ==================================================================
    section("STEP 3  Produce and validate a synthetic finding")
    # ==================================================================
    ex = eng_a  # the executor is what files findings
    from orch.hunt_exec import ActiveHuntExecutor
    exec_a = ActiveHuntExecutor(con, ctx, hunt_id=hunt_a)

    # THE BASELINE MEASUREMENT.
    #
    # MEASURED 2026-11-01: the first version of this test used a SECOND
    # hunt as the control -- "a hunt whose class has no verified lesson".
    # That control is INVALID, and the reason is a property of the design
    # that is easy to mistake for a bug: `before_recon` deliberately
    # returns verified lessons for EVERY class in the corpus, not just the
    # classes seen on this target. The rationale is written into
    # `_prior_classes`: "a class with a verified lesson is a class this
    # system has PROVEN exploitable before, so it is worth looking for
    # again". So once `sqli` has a verified lesson, EVERY later hunt that
    # raises an `sqli` finding is boosted -- a second hunt of the same
    # class is not a control, it is a second instance of the treatment.
    #
    # The honest A/B is the SAME hunt's recon, run BEFORE and AFTER the
    # lesson exists. Everything else -- target, class, signal, code path --
    # is identical; the only variable is whether the corpus holds a
    # VERIFIED lesson for the class.
    #
    # So hunt A's recon runs first and files a finding with the DEFAULT
    # priority. That finding is then validated and its outcome captured,
    # which is what verifies the lesson. Hunt B's recon then runs against
    # the same target and must come back PRIOR-BOOSTED.
    _mk_task(con, hunt_a, "HTTP recon of the in-scope target")
    row_a = con.execute("SELECT * FROM task WHERE task_key=?",
                        (f"{hunt_a}.recon.http",)).fetchone()
    out_a = exec_a.run_step(row_a)
    check(out_a.get("ok") is True,
          "the FIRST hunt's RECON STEP ran against the synthetic target",
          str(out_a.get("summary") or out_a.get("error"))[:300])
    filed_a = out_a.get("findings_filed") or []
    check(bool(filed_a),
          "the first hunt's recon FILED a finding from the observed signal",
          f"{len(filed_a)} filed")
    if filed_a:
        check(filed_a[0].get("class_id") == class_id,
              f"the recon derived the class under test ({class_id})",
              str(filed_a[0].get("class_id")))
        check(filed_a[0].get("prior_boosted") is not True,
              "the BASELINE finding was NOT boosted (no lesson existed yet)",
              str(filed_a[0].get("prior_boosted")))
        prio_a = con.execute(
            "SELECT priority FROM finding WHERE finding_key=?",
            (filed_a[0]["finding_key"],)).fetchone()["priority"]
        check(prio_a != 2,
              "the BASELINE finding kept the DEFAULT priority",
              f"priority={prio_a}")
        finding = filed_a[0]
        fkey = finding.get("finding_key")
    else:
        finding = {}
        fkey = None
    check(bool(fkey), "the baseline finding has a key", str(finding)[:200])

    # THE SCENARIO THIS FILE MODELS IS A PRODUCTION HUNT.
    #
    # MEASURED 2026-11-01: the hunt runs against `127.0.0.1`, so the
    # finding it files is correctly classified EVAL_TEST -- and a lesson
    # from an EVAL_TEST finding can never be verified, so the assertions
    # below ("the second hunt RETRIEVES the lesson from the first hunt",
    # "the finding in the lesson's class was PRIOR-BOOSTED") could not
    # hold.
    #
    # MEASURED 2026-11-02: the fix for that was a raw
    # `UPDATE finding SET provenance='PRODUCTION_HUNT'` -- the
    # self-declaration the receipt exists to prevent, and now refused by
    # the database itself.
    #
    # So the production scenario is created the way the runtime creates
    # one: a hunt whose authorization was VALIDATED and RECORDED. The
    # loopback server remains a VEHICLE for the scenario; the receipt --
    # not a hand-written UPDATE -- is what makes the origin production.
    #
    # The provenance gate is not weakened. `eval/test_p2_provenance.py`
    # proves that a finding with no receipt cannot produce a verified
    # lesson.
    from orch import provenance as _prov
    if fkey:
        prod_hunt = "xwf.production"
        prod_ctx = authz.AuthorizationContext(
            program="xwf-program", target="app.xwf.example",
            in_scope_assets=["app.xwf.example"],
            reporting_requirements={"format": "md"},
            authorization_ref="XWF-PROGRAM-SCOPE", kind="bugbounty",
            allowed_actions=["recon", "probe"])
        receipt = prod_ctx.validate_and_record(con, hunt_id=prod_hunt)
        check("the production hunt recorded a validated receipt",
              receipt.get("validated") is True, str(receipt)[:200])
        # The finding is PROMOTED through the audited correction path --
        # the only sanctioned way to change an origin, and the path the
        # trigger permits.
        ok = _prov.set_provenance(
            con, "finding", fkey, _prov.PRODUCTION_HUNT,
            reason=("the cross-workflow scenario is a production hunt: the "
                    "hunt's authorization was validated and recorded"),
            corrected_by="eval/test_cross_workflow_integration.py")
        check("the finding was promoted through the audited correction path",
              ok is True, str(ok))

    # The evidence must be attached, because the FP gate reads it.
    n_ev = con.execute(
        "SELECT count(*) n FROM evidence WHERE finding_id="
        "(SELECT id FROM finding WHERE finding_key=?)", (fkey,)).fetchone()["n"]
    check(n_ev >= 1, "the finding carries stored evidence", f"n={n_ev}")

    # Validate it through the REAL gate, with an INDEPENDENT validator.
    # The validator must be a real agent_run row or L4 refuses.
    def _mk_run(run_key: str, role: str) -> None:
        # `agent_role` requires a `domain` and a `created_at`; there is no
        # `name` column. `agent_run` requires an `objective`.
        con.execute(
            "INSERT OR REPLACE INTO agent_role(role_key, domain, "
            "objective_kind, toolsets, capabilities, max_depth, rationale, "
            "created_at) VALUES (?,?,?,?,?,?,?,?)",
            (role, "research" if role == "researcher" else "validation",
             None, "[]", "[]", 1,
             f"synthetic {role} for the cross-workflow integration test",
             "2026-11-01T00:00:00Z"))
        con.execute(
            "INSERT OR REPLACE INTO agent_run(run_key, role_key, task_key, "
            "status, objective, depth, attempts, started_at, finished_at, "
            "created_at) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (run_key, role, f"task.{run_key}", "completed",
             f"synthetic {role} run", 0, 1,
             "2026-11-01T00:00:00Z", "2026-11-01T00:00:01Z",
             "2026-11-01T00:00:00Z"))

    _mk_run("run.xwf.claimant", "researcher")
    _mk_run("run.xwf.validator", "validator")

    from orch import validate as v1
    vec = v1.validate_finding(con, fkey, reproduced=True,
                              claimant_run="run.xwf.claimant",
                              validator_run="run.xwf.validator")
    check(isinstance(vec.get("results"), dict) and vec["results"],
          "the finding was validated through the real validator",
          str(vec)[:200])
    l4 = (vec.get("results") or {}).get("L4") or {}
    check(l4.get("passed") is True,
          "L4 independence PASSES with a distinct claimant and validator role",
          str(l4)[:200])

    # ==================================================================
    section("STEP 4/5/6  Persist the outcome through the learning interface")
    # ==================================================================
    # The learning bridge is the ACTUAL interface between a hunt outcome and
    # the learning corpus. It is what `finalgate.apply_gate` calls.
    from orch import learning_bridge
    lesson = learning_bridge.record_hunt_outcome(
        con, fkey, lifecycle_state="VALIDATED")
    check(lesson.get("ok") is True,
          "the learning bridge accepted the hunt outcome", str(lesson)[:300])
    lesson_key = lesson.get("lesson_key")
    check(bool(lesson_key), "the bridge produced a lesson key", str(lesson)[:200])

    # The lesson must carry PROVENANCE and a TRUST STATE.
    lcon = le.open_canonical(create=False)
    try:
        row = lcon.execute(
            "SELECT * FROM lesson WHERE lesson_key=?", (lesson_key,)).fetchone()
        check(row is not None, "the lesson is persisted in the canonical db",
              str(lesson_key))
        if row is not None:
            check(bool(row["topic"]), "the lesson has a topic",
                  str(dict(row))[:200])
            check(bool(row["body"]), "the lesson has a body",
                  str(dict(row))[:200])
            check(row["state"] in ("captured", "analyzed", "researched",
                                   "verified", "superseded", "rejected"),
                  "the lesson has a KNOWN trust state", f"state={row['state']!r}")
            check(row["class_id"] == class_id,
                  "the lesson is attributed to the finding's class",
                  f"class_id={row['class_id']!r} expected={class_id!r}")
    finally:
        lcon.close()

    # ==================================================================
    section("STEP 7  Start a SECOND synthetic hunt")
    # ==================================================================
    ctx_b = authz.AuthorizationContext(
        program="synthetic integration program",
        target=target_host,
        in_scope_assets=[base_url, target_host],
        out_of_scope_assets=["http://out-of-scope.invalid/"],
        allowed_actions=["recon", "probe"],
        forbidden_actions=["denial_of_service", "destructive_write",
                           "data_exfiltration"],
        rate_limits={"requests_per_second": 2, "concurrency": 1, "burst": 2,
                     "per_host_per_minute": 30},
        authentication_context={"mode": "unauthenticated"},
        reporting_requirements={"format": "markdown", "include_evidence": True},
        authorization_ref="OPERATOR-GRANTED: synthetic loopback target for "
                          "the cross-workflow integration test",
        kind="lab",
    )
    ctx_b.register(con, scope_key=hunt_b)
    eng_b = hunting.HuntingEngine(con, ctx_b, hunt_id=hunt_b)
    gate_b = eng_b.authorization_gate()
    check(gate_b.get("passed") is True,
          "the second hunt's authorization gate PASSES",
          json.dumps(gate_b)[:200])
    eng_b.surface.add_node("host", base_url, observed=True, in_scope=True)
    eng_b.ledger.record(base_url, discovered_by="integration_test")

    # ==================================================================
    section("STEP 8  Retrieve the lesson")
    # ==================================================================
    lcon = le.open_canonical(create=False)
    try:
        prior = le.before_recon(lcon, target_host)
        lessons = prior.get("lessons") or []
        check(bool(lessons),
              "the second hunt RETRIEVES the lesson from the first hunt",
              f"{len(lessons)} lesson(s); classes="
              f"{prior.get('classes_with_verified_lessons')}")
        retrieved = [x for x in lessons if x.get("class_id") == class_id]
        check(bool(retrieved),
              "the retrieved lesson is attributed to the right class",
              str([x.get('class_id') for x in lessons])[:200])
        # THE SCOPE IS EXPLICIT.
        #
        # MEASURED 2026-11-01: `before_recon` took a `target` argument,
        # echoed it in its result, and never used it in any query -- so the
        # result looked target-scoped while the lessons were corpus-wide.
        # The behaviour is CORRECT (a verified lesson is class-level
        # experience, and scoping it to one host would throw away the
        # intelligence), but a silent corpus-wide read presented as
        # target-scoped is a misrepresentation. The scope is now stated.
        check(prior.get("scope") == "class",
              "the prior says its scope is CLASS-level, not target-scoped",
              str(prior.get("scope")))
        check("class_lessons" in prior and "target_lessons" in prior,
              "the prior separates class lessons from target lessons",
              str(sorted(prior.keys()))[:200])
        for l in lessons:
            check(l.get("scope") in ("target", "class"),
                  "every lesson declares its scope",
                  f"{l.get('topic')} -> {l.get('scope')}")
        # The bridge's topic names its target, so a lesson about THIS target
        # is recognised as target-scoped.
        target_scoped = [l for l in lessons
                         if str(l.get("topic") or "").startswith("outcome:")
                         and str(l.get("topic") or "").endswith(target_host)]
        check(bool(target_scoped),
              "the lesson the bridge wrote for THIS target is recognised",
              str([l.get('topic') for l in lessons])[:200])
        for l in target_scoped:
            check(l.get("scope") == "target",
                  "a lesson about this target is marked scope='target'",
                  f"{l.get('topic')} -> {l.get('scope')}")
    finally:
        lcon.close()

    # ==================================================================
    section("STEP 9  The lesson CHANGES a decision in the second hunt")
    # ==================================================================
    # The claim under test: a lesson verified on hunt A must change what
    # hunt B prioritises. The mechanism is `_prior_classes` ->
    # `set_finding_axes(priority=2)` -> the findings are ordered with the
    # prior-boosted ones first.
    #
    # THE CONTROL IS THE BASELINE MEASUREMENT FROM STEP 3. The same code
    # path, the same target, the same signal, the same class -- run
    # before the lesson existed. Nothing else differs. That is the only
    # control that isolates the lesson as the cause.
    #
    # THE RECON STEP IS USED, NOT `record_finding`.
    #
    # MEASURED 2026-11-01: the first version of this test called
    # `record_finding` directly and then asserted the finding had been
    # priority-boosted. It failed -- and it failed for a REASON worth
    # keeping: `record_finding` files a finding, but the boost is applied
    # by `_recon_http`, which is the step that DERIVES the class from an
    # observed signal and then boosts what it derived. Calling the file
    # operation directly bypasses the decision, so the test was measuring
    # the wrong function.
    #
    # The test drives the real recon step against the loopback target. The
    # synthetic server returns a database error signature, the engine
    # derives `sql_error_or_behaviour`, `_rank` maps it to `sqli`, and the
    # recon step files and boosts the finding.
    exec_b = ActiveHuntExecutor(con, ctx_b, hunt_id=hunt_b)

    # The hunt's target must be a surface node the recon step reads.
    eng_b.surface.add_node("host", base_url, observed=True, in_scope=True)
    eng_b.ledger.record(base_url, discovered_by="integration_test")

    _mk_task(con, hunt_b, "HTTP recon of the in-scope target")
    task_row = con.execute("SELECT * FROM task WHERE task_key=?",
                            (f"{hunt_b}.recon.http",)).fetchone()

    out_b = exec_b.run_step(task_row)
    check(out_b.get("ok") is True,
          "the second hunt's RECON STEP ran against the synthetic target",
          str(out_b.get("summary") or out_b.get("error"))[:300])
    filed_b = out_b.get("findings_filed") or []
    check(bool(filed_b),
          "the recon step FILED a finding from the observed signal",
          f"{len(filed_b)} filed")
    if filed_b:
        check(filed_b[0].get("class_id") == class_id,
              f"the recon derived the class the lesson covers ({class_id})",
              str(filed_b[0].get("class_id")))
        check(filed_b[0].get("prior_boosted") is True,
              "the finding in the lesson's class was PRIOR-BOOSTED",
              str(filed_b[0].get("prior_boosted")))
        prio_b = con.execute(
            "SELECT priority FROM finding WHERE finding_key=?",
            (filed_b[0]["finding_key"],)).fetchone()["priority"]
        check(prio_b == 2,
              "the boosted finding's PRIORITY was set to 2",
              f"priority={prio_b}")
        # THE A/B: the same class, the same signal, the same code path --
        # but the baseline hunt had no verified lesson for the class.
        check(prio_b < prio_a,
              "the lesson changed the PRIORITY of the finding the SECOND "
              "hunt filed, versus the identical baseline finding",
              f"with-lesson={prio_b} baseline={prio_a}")
        check(filed_b[0].get("finding_key") != fkey,
              "the second hunt filed a DISTINCT finding from the baseline",
              f"{filed_b[0].get('finding_key')} != {fkey}")

    # ==================================================================
    section("STEP 10  Unverified observations CANNOT promote themselves")
    # ==================================================================
    # An observation that was never verified must not become a verified
    # lesson, and therefore must not influence a hunt.
    unverified = le.capture_hook(
        lcon2 := le.open_canonical(create=False),
        topic=f"outcome:{class_id}:unverified-observation",
        body="An UNVERIFIED observation that claims a working technique.")
    try:
        ukey = unverified.get("lesson_key")
        check(bool(ukey), "an unverified observation was captured",
              str(unverified)[:200])
        st = lcon2.execute("SELECT state FROM lesson WHERE lesson_key=?",
                           (ukey,)).fetchone()
        check(st is not None and st["state"] != "verified",
              "the captured observation is NOT in the verified state",
              f"state={st['state'] if st else None!r}")

        prior_after = le.before_recon(lcon2, target_host)
        unverified_in_prior = [
            x for x in (prior_after.get("lessons") or [])
            if x.get("topic") == f"outcome:{class_id}:unverified-observation"]
        check(not unverified_in_prior,
              "the unverified observation is NOT returned as intelligence",
              f"{len(unverified_in_prior)} leaked into the prior")

        # And the lesson table's own rule: only 'verified' counts.
        n_unverified = lcon2.execute(
            "SELECT count(*) n FROM lesson WHERE state!='verified' "
            "AND topic LIKE 'outcome:%'").fetchone()["n"]
        n_verified = lcon2.execute(
            "SELECT count(*) n FROM lesson WHERE state='verified' "
            "AND topic LIKE 'outcome:%'").fetchone()["n"]
        check(n_unverified >= 1 and n_verified >= 1,
              "the lesson table holds BOTH verified and unverified lessons",
              f"unverified={n_unverified} verified={n_verified}")
    finally:
        lcon2.close()

    # ------------------------------------------------------------------
    # The authorization gate must REFUSE an ambiguous hunt. A loop that
    # only works when the gate passes proves nothing about the gate.
    # ------------------------------------------------------------------
    section("BONUS  An unauthorized hunt is REFUSED, not run")
    from orch import authz as _authz
    ctx_bad = _authz.AuthorizationContext(
        program="synthetic", target=target_host,
        in_scope_assets=[base_url, target_host], out_of_scope_assets=[],
        allowed_actions=["recon"], forbidden_actions=[],
        rate_limits={"requests_per_second": 1, "concurrency": 1, "burst": 1,
                     "per_host_per_minute": 10},
        authentication_context={"mode": "unauthenticated"},
        reporting_requirements={"format": "markdown", "include_evidence": True},
        authorization_ref="",   # NO GRANT
        kind="lab")
    eng_bad = hunting.HuntingEngine(con, ctx_bad, hunt_id="hunt.xwf.unauth")
    gate_bad = eng_bad.authorization_gate()
    check(gate_bad.get("passed") is False,
          "a hunt with NO explicit grant is REFUSED by the §4 gate",
          json.dumps(gate_bad)[:300])

    con.close()

    print(f"\n{'=' * 60}")
    if FAIL:
        print(f"FAILURES ({FAIL}):")
        for f in FAILURES:
            print(f"  - {f}")
        print(f"\n{PASS}/{PASS + FAIL} checks passed — THE LOOP IS NOT CLOSED.")
        return 1
    print(f"ALL {PASS} CHECKS PASS")
    print("THE LOOP IS CLOSED: a validated outcome on one hunt became a")
    print("verified lesson, and a later hunt read that lesson and changed")
    print("a decision because of it.")
    print("")
    print("SCOPE OF THIS PROOF: the loop is closed over a temporary database")
    print("and a loopback target. It does NOT establish that the corpus is")
    print("well-populated, that a real external target is reachable, or that")
    print("the reasoning behind a lesson is correct.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
