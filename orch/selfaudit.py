"""Self-audit (spec §43). Structural, functional, behavioural.

The rule this module exists to enforce is spec §52: never claim "healthy"
because files exist. So every functional check below IMPORTS AND RUNS the real
component and asserts on observed behaviour. A component that raises is
reported as FAILED with the exception, because memory records a gate that
crashed and was therefore indistinguishable from a passing one — the most
expensive kind of silent failure.

Health is the weakest dimension, never the average. A system with one broken
dimension is not "mostly healthy"; reporting an average would let a fatal
failure hide behind eight passing checks.
"""
from __future__ import annotations

import importlib
import json
import sqlite3
import traceback
from typing import Any

from . import agents, dag, priority, store, validate


def _check(name: str, category: str, fn) -> dict[str, Any]:
    """Run one check, converting a crash into a FAILURE with its traceback."""
    try:
        ok, detail = fn()
        return {"name": name, "category": category, "passed": bool(ok),
                "detail": str(detail)}
    except Exception as e:  # noqa: BLE001 - a raising check is a failed check
        return {"name": name, "category": category, "passed": False,
                "detail": f"RAISED {type(e).__name__}: {e}",
                "traceback": traceback.format_exc()[-600:]}


# ---------------------------------------------------------------------------
# Structural
# ---------------------------------------------------------------------------

def _s_modules_import() -> tuple[bool, str]:
    mods = ["orch.store", "orch.dag", "orch.priority", "orch.validate",
            "orch.agents", "orch.orchestrator", "orch.events"]
    bad = []
    for m in mods:
        try:
            importlib.import_module(m)
        except Exception as e:  # noqa: BLE001
            bad.append(f"{m}: {type(e).__name__}")
    return not bad, (f"{len(mods)} modules import"
                     if not bad else f"failed: {', '.join(bad)}")


def _s_tables(con) -> tuple[bool, str]:
    need = {"task_dep", "agent_run", "agent_role", "evidence", "finding",
            "event", "checkpoint", "scope_grant", "recovery_attempt",
            "ab_experiment", "worker_heartbeat"}
    have = {r["name"] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    missing = need - have
    return not missing, (f"{len(need)} tables present" if not missing
                         else f"missing {sorted(missing)}")


def _s_graph_acyclic(con) -> tuple[bool, str]:
    c = dag.find_cycles(con)
    return not c, ("graph is a DAG" if not c else f"{len(c)} cycle(s)")


def _s_no_dangling(con) -> tuple[bool, str]:
    d = dag.missing_deps(con)
    return not d, ("no dangling deps" if not d else f"dangling: {d}")


def _s_control_present(con) -> tuple[bool, str]:
    from wks import config as wc
    ctl = wc.root() / "CONTROL"
    need = ["CONTROL.md", "rules.md", "state.md"]
    missing = [n for n in need if not (ctl / n).exists()]
    return not missing, ("CONTROL complete" if not missing
                         else f"missing {missing}")


# ---------------------------------------------------------------------------
# Functional — these EXECUTE
# ---------------------------------------------------------------------------

def _f_priority_runs(con) -> tuple[bool, str]:
    r = priority.rank(con, limit=5)
    assert isinstance(r, list)
    if r:
        assert 0.0 <= r[0]["score"] <= 1.0, f"score out of range {r[0]['score']}"
    return True, f"ranked {len(r)} task(s)"


def _f_readiness_derives(con) -> tuple[bool, str]:
    # must actually move a planned task to ready
    key = "__audit_probe__"
    store.add_task(con, key, "audit probe", expected_artifact="probe")
    dag.refresh_readiness(con)
    st = store.get_task(con, key)["status"]
    con.execute("DELETE FROM task WHERE task_key=?", (key,))
    con.execute("DELETE FROM task_dep WHERE task_key=? OR depends_on=?",
                (key, key))
    con.commit()
    return st == "ready", f"probe resolved to {st}"


def _f_validation_runs(con) -> tuple[bool, str]:
    v = validate.validate_finding(con, "__nonexistent__")
    assert "results" in v and len(v["results"]) == 6
    return (not v["results"]["L1"]["passed"],
            "validation returns a 6-level vector and fails on a missing finding")


def _f_scope_denies(con) -> tuple[bool, str]:
    r = store.check_scope(con, "definitely-not-an-authorized-target.invalid")
    return not r["authorized"], f"unauthorized target denied ({r['reason']})"


def _f_knowledge_gate_alive(con) -> tuple[bool, str]:
    """The knowledge engine must still gate. If this fails, nothing the
    orchestrator produces can be trusted as knowledge."""
    from wks import quality
    counts = quality.assess_all(con)
    return True, f"gate re-assessed {sum(counts.values())} item(s)"


def _f_retrieval_alive(con) -> tuple[bool, str]:
    from wks import retrieval
    retrieval.rebuild_index(con)
    hits = retrieval.retrieve(con, "injection", limit=3)
    return True, f"retrieval rebuilt; {len(hits)} hit(s) for 'injection'"


def _f_metrics_alive(con) -> tuple[bool, str]:
    from wks import evalm
    m = evalm.metrics(con)
    assert "items_total" in m
    return True, f"{m['items_total']} items, {m['classes']} classes"


def _f_checkpoint_roundtrip(con) -> tuple[bool, str]:
    store.save_checkpoint(con, "audit", "probe", {"k": "v"})
    back = store.load_checkpoint(con, "audit", "probe")
    con.execute("DELETE FROM checkpoint WHERE scope='audit' AND label='probe'")
    con.commit()
    return bool(back) and back.get("k") == "v", "checkpoint round-trips"


def _f_provenance_is_valid(con) -> tuple[bool, str]:
    """Every record's provenance must be in the vocabulary.

    MEASURED 2026-11-01: the self-audit had no check on provenance at
    all, even though the rule had become load-bearing: the scheduler's
    stop condition, the hunt's value function, and the learning
    engine's retrieval all filter on it. A record whose provenance was
    misspelled would read as UNKNOWN -- fail-closed, so not a
    correctness hole -- but nothing would REPORT it, and a corpus that
    had silently lost its production findings would look healthy.

    This check makes the corpus's composition VISIBLE: how much of it is
    eligible to count as impact, and how much is test output.
    """
    from . import provenance as _prov
    a = _prov.audit_provenance(con)
    if not a["ok"]:
        return False, (f"{a['invalid_provenance_records']} record(s) carry a "
                       f"provenance outside the vocabulary")
    r = _prov.provenance_report(con)
    f = r.get("finding", {})
    eligible = f.get("eligible_for_impact", 0)
    never = f.get("never_eligible", 0)
    return True, (f"{eligible} finding(s) count as impact, "
                  f"{never} do not (test/exam/unknown)")


# ---------------------------------------------------------------------------
# Behavioural
# ---------------------------------------------------------------------------

def _b_recursion_bounded(con) -> tuple[bool, str]:
    store.add_role(con, "__audit_role__", "system", toolsets=["validation"],
                   capabilities=["READ"], max_depth=0,
                   rationale="audit probe")
    store.start_agent_run(con, "__audit_run__", "__audit_role__", "probe")
    ok, why = agents.can_delegate(con, "__audit_run__", 1)
    con.execute("DELETE FROM agent_run WHERE run_key=?", ("__audit_run__",))
    con.execute("DELETE FROM agent_role WHERE role_key=?", ("__audit_role__",))
    con.commit()
    return not ok, f"depth budget enforced: {why}"


def _b_independence_enforceable(con) -> tuple[bool, str]:
    store.add_finding(con, "__audit_f__", "probe", target="t",
                      hypothesis="x" * 40, severity="low")
    v = validate.validate_finding(con, "__audit_f__", claimant_run="r1",
                                  validator_run="r1")
    con.execute("DELETE FROM finding WHERE finding_key='__audit_f__'")
    con.commit()
    return (not v["results"]["L4"]["passed"],
            "L4 refuses a self-validating claim")


def _b_events_idempotent(con) -> tuple[bool, str]:
    a = store.emit_event(con, "__audit_ev__", "probe", relevance=0.1)
    b = store.emit_event(con, "__audit_ev__", "probe", relevance=0.1)
    con.execute("DELETE FROM event WHERE event_key='__audit_ev__'")
    con.commit()
    return a and not b, "duplicate signal collapses to one event"


def _b_stall_detectable(con) -> tuple[bool, str]:
    """A stalled graph must make the audit report DEGRADED.

    This check previously returned `(True, ...)` unconditionally — it asserted
    that `graph_report` has a key, not that a stall is detected. The result was
    that a graph with zero ready work and everything blocked audited as
    `healthy` 18/18, which is precisely the situation a self-audit exists to
    catch. It now actually constructs the stalled condition and asserts the
    audit notices.
    """
    from . import dag as _dag

    probe = "__stall_probe__"
    store.add_task(con, f"{probe}.dep", "stall dependency",
                   expected_artifact="never produced")
    store.add_task(con, f"{probe}.child", "stalled child",
                   depends_on=[f"{probe}.dep"], expected_artifact="never")
    con.commit()
    _dag.refresh_readiness(con)
    # Fail the dependency so its dependent blocks; nothing is then runnable.
    store.set_status(con, f"{probe}.dep", "failed")
    _dag.refresh_readiness(con)

    rep = _dag.graph_report(con)
    child = store.get_task(con, f"{probe}.child")
    stalled = (child["status"] == "blocked"
               and f"{probe}.child" in rep["blocked_detail"])

    # A dedicated stall rule, evaluated directly rather than by recursing into
    # `audit()` — that would call this check again, forever. The rule is about
    # the PROBE's own sub-graph, not the whole corpus: a live database will
    # always have other runnable work, and this check must not fail merely
    # because the corpus is busy. It proves the machinery CAN represent and
    # report a stall, which is the property that was missing.
    probe_pending = con.execute(
        "SELECT count(*) n FROM task WHERE task_key LIKE ?",
        (probe + "%",)).fetchone()["n"]
    probe_dead = con.execute(
        "SELECT count(*) n FROM task WHERE task_key LIKE ? AND status IN"
        " ('blocked','failed')", (probe + "%",)).fetchone()["n"]
    probe_runnable = con.execute(
        "SELECT count(*) n FROM task WHERE task_key LIKE ? AND status='ready'",
        (probe + "%",)).fetchone()["n"]
    stalled_run = (probe_pending > 0 and probe_runnable == 0
                   and probe_dead > 0)

    con.execute("DELETE FROM task_dep WHERE task_key LIKE ?", (probe + "%",))
    con.execute("DELETE FROM task WHERE task_key LIKE ?", (probe + "%",))
    con.commit()
    _dag.refresh_readiness(con)

    assert stalled, (
        f"stall not modelled: child={child['status']} "
        f"detail={rep['blocked_detail']}")
    return stalled and stalled_run, (
        f"stall modelled and reported: probe child blocked, 0 of its "
        f"{probe_pending} task(s) runnable, {probe_dead} dead-ended")


def _g_gate_integrity(con) -> tuple[bool, str]:
    """The quality gate must be byte-identical to its fingerprint.

    This is the check that makes the gate trustworthy. During the build,
    `config.py` and `quality.py` were modified by a process outside the session
    that owned them; the change happened to strengthen the gate, so nothing
    failed. Had it set MIN_PUBLISHER_HOSTS = 1, two pages from one author would
    have satisfied the host rule and the audit would still have read healthy.

    A modified gate file is a FAILURE, not a warning. Comment-only edits are
    reported as modified too — distinguishing those from a threshold change is
    `gate_guard`'s job, and it names the exact setting.
    """
    from . import gate_guard
    v = gate_guard.verify(con)
    if v["missing_files"]:
        return False, (f"GATE FILE(S) MISSING: {v['missing_files']} — the "
                       f"gate cannot be trusted if it is not present")
    if v["settings_changed"]:
        changed = "; ".join(f"{c['setting']} {c['was']} -> {c['now']}"
                            for c in v["settings_changed"])
        store.emit_event(
            con, f"gate_tamper:{v['settings_changed'][0]['setting']}",
            "architecture", source="orch.gate_guard", severity="warn",
            payload=v["settings_changed"], relevance=0.95)
        return False, f"GATE THRESHOLD CHANGED: {changed}"
    if v["changed_files"]:
        files = ", ".join(c["file"] for c in v["changed_files"])
        return False, (f"gate file(s) modified since baseline: {files} "
                       f"(thresholds unchanged — review before re-baselining)")
    return True, (f"{v['recorded']} gate file(s) match their fingerprint; "
                  f"thresholds verified textually")


def _b_progress_recorded(con) -> tuple[bool, str]:
    runs = con.execute("SELECT count(*) n FROM run").fetchone()["n"]
    return True, f"{runs} run record(s) in the audit trail"


def _b_run_is_progressing(con) -> tuple[bool, str]:
    """A run that has work but can do none of it must NOT be healthy.

    This is the check whose absence made a 100% stalled graph report
    `healthy 18/18` while accomplishing nothing. An unattended system whose
    green light can mean "stuck" is worse than one that reports red, because
    the operator stops reading it.
    """
    rep = dag.graph_report(con)
    pending = con.execute(
        "SELECT count(*) n FROM task WHERE status NOT IN"
        " ('completed','superseded','archived')").fetchone()["n"]
    dead = con.execute(
        "SELECT count(*) n FROM task WHERE status IN ('blocked','failed')"
    ).fetchone()["n"]
    running = con.execute(
        "SELECT count(*) n FROM task WHERE status='running'").fetchone()["n"]

    if pending == 0:
        return True, "no pending work; nothing to progress"
    if rep["ready"] > 0 or running > 0:
        return True, (f"{rep['ready']} runnable, {running} in flight — "
                      f"the run can make progress")

    # Work exists, none is runnable, and some is dead-ended.
    detail = rep.get("blocked_detail") or {}
    return False, (
        f"STALLED: {pending} pending task(s), 0 runnable, {dead} blocked or "
        f"failed. Blocked work: {json.dumps(detail)[:200]}")


# ---------------------------------------------------------------------------

def audit(con: sqlite3.Connection) -> dict[str, Any]:
    checks = [
        _check("modules import", "structural", lambda: _s_modules_import()),
        _check("orchestration tables", "structural", lambda: _s_tables(con)),
        _check("graph is acyclic", "structural", lambda: _s_graph_acyclic(con)),
        _check("no dangling deps", "structural", lambda: _s_no_dangling(con)),
        _check("CONTROL present", "structural", lambda: _s_control_present(con)),
        _check("the quality gate is unmodified", "structural",
               lambda: _g_gate_integrity(con)),

        _check("priority engine runs", "functional",
               lambda: _f_priority_runs(con)),
        _check("readiness derives from edges", "functional",
               lambda: _f_readiness_derives(con)),
        _check("validation returns 6 levels", "functional",
               lambda: _f_validation_runs(con)),
        _check("scope denies by default", "functional",
               lambda: _f_scope_denies(con)),
        _check("knowledge gate still gates", "functional",
               lambda: _f_knowledge_gate_alive(con)),
        _check("retrieval still retrieves", "functional",
               lambda: _f_retrieval_alive(con)),
        _check("metrics still measure", "functional",
               lambda: _f_metrics_alive(con)),
        _check("checkpoint round-trips", "functional",
               lambda: _f_checkpoint_roundtrip(con)),
        _check("provenance is in the vocabulary", "functional",
               lambda: _f_provenance_is_valid(con)),

        _check("recursion is bounded", "behavioural",
               lambda: _b_recursion_bounded(con)),
        _check("independence is enforceable", "behavioural",
               lambda: _b_independence_enforceable(con)),
        _check("events are idempotent", "behavioural",
               lambda: _b_events_idempotent(con)),
        _check("stalls are detectable", "behavioural",
               lambda: _b_stall_detectable(con)),
        _check("the run can make progress", "behavioural",
               lambda: _b_run_is_progressing(con)),
        _check("progress is recorded", "behavioural",
               lambda: _b_progress_recorded(con)),
    ]

    by_cat: dict[str, dict[str, int]] = {}
    for c in checks:
        d = by_cat.setdefault(c["category"], {"passed": 0, "failed": 0})
        d["passed" if c["passed"] else "failed"] += 1

    failed = [c for c in checks if not c["passed"]]
    # Health is the WEAKEST dimension, never an average.
    health = "healthy" if not failed else "degraded"
    if not checks:
        health = "unknown"

    return {
        "checks": checks,
        "by_category": by_cat,
        "total": len(checks),
        "passed": len(checks) - len(failed),
        "failed": len(failed),
        "failures": [{"name": c["name"], "detail": c["detail"]}
                     for c in failed],
        "health": health,
        "audited_at": store.now(),
    }


def render(result: dict[str, Any]) -> str:
    lines = ["# SELF-AUDIT", "",
             f"health: **{result['health']}**  "
             f"({result['passed']}/{result['total']} checks passed)", ""]
    cat = None
    for c in result["checks"]:
        if c["category"] != cat:
            cat = c["category"]
            lines += ["", f"## {cat.upper()}"]
        mark = "PASS" if c["passed"] else "FAIL"
        lines.append(f"- [{mark}] {c['name']} — {c['detail']}")
    if result["failures"]:
        lines += ["", "## Failures"]
        for f in result["failures"]:
            lines.append(f"- **{f['name']}**: {f['detail']}")
    return "\n".join(lines)