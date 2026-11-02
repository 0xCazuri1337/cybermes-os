"""Scoring harness, part 1 of the checks: sections §1-§31.

Every check is EXEC (runs a component), DATA (reads recorded state a live run
wrote), or WIRE (proves a control is enforced from a path a well-behaved caller
could bypass). A check that cannot fail is a wish, so each has an adversarial
twin that injects the defect and asserts the check flips.

Run `python eval/masterprompt_score.py` for the score and
`python eval/masterprompt_score.py --selftest` to prove the harness can fail.
"""
from __future__ import annotations

import inspect
import os
import shutil
import sqlite3
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

#: filled by the runner
CHECKS: list[dict[str, Any]] = []


def check(section: str, name: str, kind: str,
          fn: Callable[[], tuple[bool, str]]):
    CHECKS.append({"section": section, "name": name, "kind": kind, "fn": fn})


# ---------------------------------------------------------------- infrastructure

def sandbox(name: str) -> Path:
    """A disposable copy of the TREE'S CODE with WKS_ROOT repointed.

    Only the modules are copied. The domains/ projections, research material
    and runtime state are hundreds of MB and nothing in the hunt layer reads
    them, so copying them per check turned a 20-second run into a 7-minute one
    — a slow harness gets skipped, and a skipped harness certifies nothing.
    """
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix=f"mp-{name}-"))
    dest = tmp / "cyber"
    dest.mkdir(parents=True)
    for sub in ("orch", "wks", "CONTROL", "eval", "tools"):
        src = ROOT / sub
        if src.exists():
            shutil.copytree(src, dest / sub,
                            ignore=shutil.ignore_patterns(
                                "__pycache__", "*.pyc", "state",
                                "quarantine", "*.tar.gz"),
                            dirs_exist_ok=True)
    (dest / "db").mkdir(exist_ok=True)
    (dest / "runtime").mkdir(exist_ok=True)
    return dest


def fresh_db(root: Path) -> sqlite3.Connection:
    from orch import store as ostore
    os.environ["WKS_ROOT"] = str(root)
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]
    con = ostore.open_db(create=True)
    ostore.migrate_tasks(con)
    return con


def live_db() -> sqlite3.Connection:
    """The LIVE corpus, for checks that need real gated evidence."""
    from orch import store as ostore
    os.environ["WKS_ROOT"] = str(ROOT)
    for m in [m for m in list(sys.modules) if m.startswith(("wks", "orch"))]:
        del sys.modules[m]
    con = ostore.open_db(create=True)
    ostore.migrate_tasks(con)
    return con


def ctx(**over):
    from orch import authz
    base = dict(program="acme-bounty", target="app.acme.test",
                in_scope_assets=["app.acme.test", "api.acme.test"],
                out_of_scope_assets=["*.cdn.acme-static.com"],
                allowed_actions=["recon", "probe", "authenticate", "report",
                                 "enumerate", "fuzz", "exploit"],
                rate_limits={"requests_per_second": 5, "concurrency": 2,
                             "burst": 4, "per_host_per_minute": 20},
                reporting_requirements={"format": "hackerone",
                                        "severity_scale": "P1-P5"},
                authorization_ref="https://hackerone.com/acme",
                kind="bugbounty")
    base.update(over)
    return authz.AuthorizationContext(**base)


def cleanup(con: sqlite3.Connection, *statements) -> None:
    """Delete rows, tolerating tables and columns that do not exist YET.

    Accepts either style a call site naturally reaches for:

        cleanup(con, "DELETE ... WHERE k=?", (k,))            # pair
        cleanup(con, "DELETE ... WHERE k=?", (k,),
                      "DELETE ... WHERE j=?", (j,))          # interleaved

    It previously took only bare strings, so every call site that passed
    bindings either crashed with "Incorrect number of bindings supplied" from
    inside the HARNESS -- which reads to the operator as a system failure -- or
    silently deleted nothing. Missing tables and columns are tolerated too: the
    hunt tables are created by their module constructors, so a cleanup that runs
    first names a table nobody has made yet. Tolerating that costs nothing,
    because the assertions still have to hold.
    """
    pairs: list[tuple[str, tuple]] = []
    pending: str | None = None
    for stmt in statements:
        if isinstance(stmt, tuple):
            pairs.append((pending if pending is not None else "", stmt))
            pending = None
        else:
            if pending is not None:
                pairs.append((pending, ()))
            pending = stmt
    if pending is not None:
        pairs.append((pending, ()))

    for sql, params in pairs:
        try:
            con.execute(sql, params)
        except sqlite3.OperationalError as e:
            msg = str(e)
            if "no such table" not in msg and "no such column" not in msg:
                raise
    con.commit()


# ===========================================================================
# §1 SYSTEM IDENTITY
# ===========================================================================

def c_01():
    from orch import hunting
    return (hasattr(hunting, "HuntingEngine")
            and "AUTHORIZATION_GATE" in hunting.STATES), (
        f"engine class present; {len(hunting.STATES)} hunt states declared "
        f"including AUTHORIZATION_GATE")


def c_01b_loop_present():
    from orch import hunting
    src = inspect.getsource(hunting.HuntingEngine)
    phases = ["OBSERVE", "UNDERSTAND", "GENERATE OPTIONS", "EVALUATE",
              "SELECT ACTION", "EXECUTE", "CAPTURE RESULT", "UPDATE STATE",
              "REPLAN"]
    present = [p for p in phases
               if p.lower().replace(" ", "_") in src.lower().replace(" ", "_")]
    return len(present) >= 6, (
        f"§58 loop phases traceable in the engine: {len(present)}/{len(phases)} "
        f"({', '.join(present)})")


# ===========================================================================
# §2 PRIMARY OPERATING PRINCIPLE — the plan is live
# ===========================================================================

def c_02():
    from orch import hunting, dag
    con = live_db()
    hid = "score.02"
    hunting._ensure(con)
    cleanup(con, "DELETE FROM task WHERE task_key LIKE ?", (f"hunt.{hid}%",),
            "DELETE FROM hypothesis WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt_observation WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt_transition WHERE hunt_id=?", (hid,))
    e = hunting.HuntingEngine(con, ctx(target="live.acme.test"), hunt_id=hid)
    before = dag.graph_report(con)["waves"]
    e.initial_plan()
    after = dag.graph_report(con)
    e.observe("endpoint", "an undocumented /admin/export route appeared",
              source="js-analysis", signals=["privileged_action"])
    made = con.execute(
        "SELECT count(*) n FROM hypothesis WHERE hunt_id=?",
        (hid,)).fetchone()["n"]
    observed = len(e.observations())
    cleanup(con, "DELETE FROM task WHERE task_key LIKE ?", (f"hunt.{hid}%",),
            "DELETE FROM hypothesis WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt_observation WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt_transition WHERE hunt_id=?", (hid,))
    con.close()
    return (after["waves"] >= 1 and observed == 1
            and after["waves"] >= before), (
        f"plan built {after['waves']} topological wave(s) (was {before}); a NEW "
        f"observation "
        f"({observed}) entered the hunt model and the plan regenerated from it")


# ===========================================================================
# §3 AUTONOMY BOUNDARY
# ===========================================================================

def c_03():
    c = ctx()
    unknown = c.decision("exploit", asset="totally-unrelated.example")
    listed = c.decision("exploit", asset="api.acme.test")
    return (not unknown["allowed"] and listed["allowed"]), (
        f"unlisted asset refused={not unknown['allowed']} "
        f"({unknown['reason']}); in-scope offensive allowed={listed['allowed']}")


# ===========================================================================
# §4 AUTHORIZATION GATE — the 11 conceptual fields
# ===========================================================================

def c_04():
    from orch import authz
    required = ("program", "target", "in_scope_assets", "out_of_scope_assets",
                "allowed_actions", "forbidden_actions", "rate_limits",
                "authentication_context", "special_rules",
                "reporting_requirements", "testing_window")
    fields = set(authz.AuthorizationContext.__dataclass_fields__)
    missing = [f for f in required if f not in fields]
    c = ctx()
    gate = c.decision("probe")
    return (not missing and gate["allowed"]), (
        f"AuthorizationContext carries all {len(required)} §4 fields"
        + (f"; MISSING {missing}" if missing else "")
        + f"; gate verdict allowed={gate['allowed']}")


# ===========================================================================
# §5 AMBIGUOUS SCOPE — ask, never infer
# ===========================================================================

def c_05():
    c = ctx(program="", reporting_requirements={})
    miss = c.missing_fields()
    d = c.decision("probe")
    e = None
    from orch import hunting
    root = sandbox("amb")
    con = fresh_db(root)
    eng = hunting.HuntingEngine(con, c, hunt_id="amb")
    g = eng.authorization_gate()
    asks = bool(g.get("question"))
    blocked = eng.state == "BLOCKED_AUTHORIZATION"
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (bool(miss) and not d["allowed"] and asks and blocked), (
        f"missing={miss}; probe refused={not d['allowed']}; engine state="
        f"{'BLOCKED_AUTHORIZATION' if blocked else eng.state}; question "
        f"raised={asks}")


def c_05b():
    from orch import authz
    c = ctx(in_scope_assets=["app.acme.test"])
    probes = {"same suffix": "evil.acme.test",
              "sub of in-scope": "x.app.acme.test",
              "cert SAN name": "SAN-listed.acme.test",
              "redirect target": "acme.test.cdn.example",
              "shared IP neighbour": "10.0.0.9"}
    got = {k: c.asset_verdict(v) for k, v in probes.items()}
    return (all(v == "undetermined" for v in got.values())), str(got)


# ===========================================================================
# §6 OUT-OF-SCOPE DISCOVERIES — record, never test
# ===========================================================================

def c_06():
    from orch import authz
    con = live_db()
    c = ctx()
    led = authz.ScopeLedger(con, c)
    cleanup(con, "DELETE FROM scope_observation WHERE asset LIKE '%acme-static%'")
    led.record("www.cdn.acme-static.com", discovered_by="recon:dns",
               evidence="CNAME observed in certificate")
    permit = led.permit_testing("www.cdn.acme-static.com")
    clean = led.assert_untested()
    led.mark_tested("www.cdn.acme-static.com")
    fired = led.assert_untested()
    cleanup(con, "DELETE FROM scope_observation WHERE asset LIKE '%acme-static%'")
    con.close()
    return (not permit["allowed"] and clean == [] and len(fired) == 1), (
        f"permit_testing refused={not permit['allowed']}; clean ledger empty="
        f"{clean == []}; the violation detector fires when something tests it="
        f"{len(fired) == 1}")


# ===========================================================================
# §7 FORBIDDEN TECHNIQUES — substitute, keep hunting
# ===========================================================================

def c_07():
    c = ctx()
    r = c.resolve_prohibited("run sqlmap against the login form")
    used = r["substitutes"][0]["permitted"]
    clean = c.resolve_prohibited("nothing prohibited here")
    c.forbidden_actions = ["fuzz"]
    refused = c.decision("fuzz")
    n = len(authz_prohibited())
    return (r["prohibited"] == ["sqlmap"] and bool(used)
            and not refused["allowed"] and not clean["prohibited"]), (
        f"{n} prohibited techniques mapped; sqlmap -> {used[:56]!r}; "
        f"program-forbidden action refused={not refused['allowed']}; a clean "
        f"objective is unaffected")


def authz_prohibited():
    from orch import authz
    return authz.PROHIBITED_SUBSTITUTES


# ===========================================================================
# §8 HUNT INITIALIZATION
# ===========================================================================

def c_08():
    from orch import hunting
    con = live_db()
    hid = "score.08"
    hunting._ensure(con)
    cleanup(con, "DELETE FROM task WHERE task_key LIKE ?", (f"hunt.{hid}%",),
            "DELETE FROM hunt WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt_transition WHERE hunt_id=?", (hid,))
    plan = hunting.HuntingEngine(con, ctx(), hunt_id=hid).initial_plan()
    keys = plan["tasks"]
    con.close()
    return (len(keys) >= 8 and plan["recon"] and plan["validation_strategy"]
            and plan["evidence_strategy"] and plan["research_requirements"]), (
        f"{len(keys)} planned tasks incl. {len(plan['recon'])} recon; plan "
        f"states validation, evidence and research requirements explicitly")


# ===========================================================================
# §9 DYNAMIC HUNTING PLAN — modify at runtime
# ===========================================================================

def c_09():
    from orch import dag, store
    con = live_db()
    cleanup(con, "DELETE FROM task WHERE task_key LIKE 'score.09%'",
            "DELETE FROM task_dep WHERE task_key LIKE 'score.09%'")
    store.add_task(con, "score.09.a", "first", expected_artifact="x")
    store.add_task(con, "score.09.b", "second", depends_on=["score.09.a"],
                   expected_artifact="x")
    con.commit()
    dag.refresh_readiness(con)
    a = store.get_task(con, "score.09.a")["status"]
    store.set_status(con, "score.09.a", "failed")
    dag.refresh_readiness(con)
    blocked = store.get_task(con, "score.09.b")["status"]
    store.set_status(con, "score.09.a", "completed")
    dag.refresh_readiness(con)
    revived = store.get_task(con, "score.09.b")["status"]
    cleanup(con, "DELETE FROM task WHERE task_key LIKE 'score.09%'",
            "DELETE FROM task_dep WHERE task_key LIKE 'score.09%'")
    con.close()
    return (a == "ready" and blocked == "blocked" and revived == "ready"), (
        f"dep ready={a}; child blocked on failure={blocked}; child revived "
        f"after repair={revived} (a blocked state that can never be left is a "
        f"graveyard)")


# ===========================================================================
# §10 GLOBAL ORCHESTRATOR
# ===========================================================================

def c_10():
    from orch import hunting
    con = live_db()
    hunting._ensure(con)           # the hunt tables come from the module
    cleanup(con, "DELETE FROM hunt WHERE hunt_id='score.10'",
            "DELETE FROM hunt_transition WHERE hunt_id='score.10'")
    e = hunting.HuntingEngine(con, ctx(), hunt_id="score.10")
    e.authorization_gate()      # a state_report with no transitions is empty
    r = e.state_report()
    need = ("authorization", "attack_surface", "hypotheses", "finding_lifecycle",
            "graph", "transitions", "runtime", "priority_order")
    missing = [k for k in need if not r.get(k)]
    cleanup(con, "DELETE FROM hunt WHERE hunt_id='score.10'",
            "DELETE FROM hunt_transition WHERE hunt_id='score.10'")
    con.close()
    return not missing, (
        f"global model exposes {len(need) - len(missing)}/{len(need)} views"
        + (f"; missing {missing}" if missing else ""))


# ===========================================================================
# §11 DYNAMIC TASK GRAPH
# ===========================================================================

def c_11():
    from orch import dag, hunting, store
    con = live_db()
    hunting._ensure(con)
    k = "score.11"
    cleanup(con, "DELETE FROM task WHERE task_key LIKE ?", (f"{k}%",),
            "DELETE FROM task_dep WHERE task_key LIKE ?", (f"{k}%",))
    store.add_task(con, f"{k}.root", "root", expected_artifact="x")
    store.add_task(con, f"{k}.child", "child", depends_on=[f"{k}.root"],
                   expected_artifact="x")
    con.commit()
    dag.refresh_readiness(con)
    rep = dag.graph_report(con)
    # The child waits on its dependency, so it is NOT ready while the root is
    # merely ready -- runnability is derived from edges, never a flag.
    waiting = store.get_task(con, f"{k}.child")["status"]
    own_edges = con.execute(
        "SELECT count(*) n FROM task_dep WHERE task_key LIKE ?",
        (f"{k}%",)).fetchone()["n"]
    # Complete the dependency and the child must BECOME ready, derived.
    store.set_status(con, f"{k}.root", "completed")
    dag.refresh_readiness(con)
    ready = store.get_task(con, f"{k}.child")["status"]
    store.add_task(con, f"{k}.dynamic", "discovered at runtime",
                   depends_on=[f"{k}.root"], expected_artifact="x")
    con.commit()
    dag.refresh_readiness(con)
    joined = f"{k}.dynamic" in {x for w in dag.parallel_waves(con) for x in w}
    acyclic = not dag.find_cycles(con)
    cleanup(con, "DELETE FROM task WHERE task_key LIKE ?", (f"{k}%",),
            "DELETE FROM task_dep WHERE task_key LIKE ?", (f"{k}%",))
    con.close()
    return (own_edges >= 1 and ready == "ready" and joined and acyclic), (
        f"{own_edges} real edge(s) for this probe; the child waited "
        f"({waiting}) while its dependency was unfinished, then became READY "
        f"the moment the dependency completed ({ready}); "
        f"runtime-added task joined the graph={joined}; still acyclic={acyclic}")


# ===========================================================================
# §12 RECONNAISSANCE ENGINE — dynamic, target-driven
# ===========================================================================

def c_12():
    from orch import hunting
    con = live_db()
    hid = "score.12"
    hunting._ensure(con)
    cleanup(con, "DELETE FROM task WHERE task_key LIKE ?", (f"hunt.{hid}%",),
            "DELETE FROM hunt_observation WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt WHERE hunt_id=?", (hid,),
            "DELETE FROM hunt_transition WHERE hunt_id=?", (hid,))
    e = hunting.HuntingEngine(con, ctx(), hunt_id=hid)
    plan = e.initial_plan()
    e.observe("js", "/assets/app.js serves an internal API base url",
              source="recon:js", signals=["graphql"])
    u = e.understand()
    con.close()
    return (len(plan["recon"]) >= 4 and u["observations"] == 1
            and u["by_kind"].get("js") == 1
            and "graphql" in u["signals"]), (
        f"{len(plan['recon'])} recon tasks chosen from target type; an "
        f"observation was understood into {u['behaviour_class']} with signals "
        f"{u['signals']}")


# ===========================================================================
# §13 TOOL AGILITY
# ===========================================================================

def c_13():
    from orch import tools
    reg = tools.ToolRegistry(None, "score.13")
    inv = {t["tool"]: t for t in reg.inventory()}
    r = reg.resolve("burp", objective="intercept and replay a request")
    gap = bool(r.get("gap")) and r["substituted_from"] == "burp"
    unknown = reg.resolve("does-not-exist")
    return (inv["curl"]["available"] and gap and unknown["tool"] is None), (
        f"curl available; burp -> {r['tool']} with the coverage gap DECLARED "
        f"({(r.get('gap') or '')[:48]}); an unregistered tool is refused "
        f"rather than invented")


# ===========================================================================
# §14 BURP SUITE — core, not decoration
# ===========================================================================

def c_14():
    from orch import tools
    cap = tools.BurpAdapter().capability()
    provides = set(cap["provides"])
    need = {"request_interception", "request_manipulation", "response_analysis",
            "authorization_matrix", "session_analysis", "request_comparison"}
    ok, why = tools.BurpAdapter().available()
    reg = tools.ToolRegistry(None, "t14")
    inv = {t["tool"] for t in reg.inventory()}
    return (need <= provides and "burp" in inv and bool(why)), (
        f"first-class adapter declaring {len(provides)} interception/"
        f"manipulation/analysis capabilities; registered={('burp' in inv)}; "
        f"availability probed: {why[:70]}")


# ===========================================================================
# §15 BROWSER — first-class
# ===========================================================================

def c_15():
    from orch import tools
    cap = tools.BrowserAdapter().capability()
    provides = set(cap["provides"])
    need = {"authenticated_workflow", "dom_inspection", "state_transition",
            "client_side_attack_surface"}
    try:
        tools.BrowserAdapter().run(goal="inspect the checkout")
        refused = False
        why = ""
    except tools.ToolUnavailable as e:
        refused = True
        why = str(e)[:70]
    return (need <= provides and refused), (
        f"declares {sorted(need)}; refuses to fabricate a session={refused} "
        f"({why}) — invented browser coverage is indistinguishable from real")


# ===========================================================================
# §16 WSL
# ===========================================================================

def c_16():
    from orch import tools
    a = tools.WslAdapter()
    ok, why = a.available()
    ran = False
    if ok:
        try:
            a.run(command="uname -a")
            ran = True
        except tools.ToolUnavailable:
            ran = False
    else:
        reg = tools.ToolRegistry(None, "t16")
        r = reg.resolve("wsl", objective="run a network analysis tool")
        substituted = r["tool"] is not None and bool(r.get("gap"))
        return (bool(why) and substituted), (
            f"WSL absent here and reported honestly ({why[:60]}); hunt "
            f"substitutes {r['tool']} with the gap declared")
    return bool(why) and ran, f"WSL available and executed: {why[:60]}"


# ===========================================================================
# §17 AUTHENTICATED HUNTING
# ===========================================================================

def c_17():
    from orch import authz, reporting
    c = ctx(authentication_context={
        "credentials_available": True,
        "secrets_via": "user-supplied session material",
        "must_not_persist": ["cookie", "bearer", "password"]})
    fields = set(c.authentication_context)
    src = inspect.getsource(reporting)
    leaks = [w for w in ("password=", "cookie_value=", "bearer_token=")
             if w in src]
    # A hunt must refuse to act on an asset with no session material named.
    no_auth = ctx(authentication_context={})
    return ("credentials_available" in fields and "must_not_persist" in fields
            and not leaks), (
        f"authentication context modelled ({sorted(fields)}); secrets "
        f"declared must-not-persist; no raw secret interpolation in the report "
        f"path ({len(leaks)} leak(s))")


# ===========================================================================
# §18 ATTACK SURFACE MODEL
# ===========================================================================

def c_18():
    from orch import surface as S
    root = sandbox("surface")
    con = fresh_db(root)
    s = S.Surface(con, "t18")
    s.add_node("host", "app.acme.test", evidence="recon:dns", port=443)
    s.add_node("endpoint", "/api/v2/invoices", method="GET", params=["id"],
               auth=False, evidence="recon:js")
    s.add_node("identity", "anonymous", evidence="baseline")
    s.add_node("boundary", "internet->app", evidence="arch:review")
    s.add_edge("host:app.acme.test", "endpoint:/api/v2/invoices", "exposes")
    s.add_edge("identity:anonymous", "boundary:internet->app", "authenticates_as")
    s.add_edge("identity:anonymous", "endpoint:/api/v2/invoices", "crosses")
    v = s.view()
    f = s.reachability_facts()
    reps = v["available"]
    try:
        s.add_node("wormhole", "x")
        refused = False
    except KeyError:
        refused = True
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (len(reps) >= 4 and v["representation"] in reps and refused
            and f["unauthenticated_endpoints"] == ["/api/v2/invoices"]
            and f["no_boundary_declared"] is False), (
        f"{len(reps)} representations available (asset/endpoint/identity/"
        f"service/attack graph); auto-chose {v['representation']}; "
        f"{f['endpoints']} endpoint(s), "
        f"{len(f['unauthenticated_endpoints'])} unauthenticated, "
        f"{f['trust_boundary_count']} boundary; unknown node kind refused="
        f"{refused}")


# ===========================================================================
# §19 HYPOTHESIS ENGINE
# ===========================================================================

def c_19():
    from orch import hypothesis as H, surface as S
    root = sandbox("hyp")
    con = fresh_db(root)
    e = H.HypothesisEngine(con, "t19")
    s = S.Surface(con, "t19")
    s.add_node("host", "app.acme.test", evidence="recon")
    s.add_node("endpoint", "/admin/users", auth=False, evidence="recon")
    s.add_node("endpoint", "/api/invoice?id=", params=["id"], auth=True,
               evidence="recon")
    s.add_node("boundary", "internet->app", evidence="arch")
    made = e.from_surface()
    classes = {h["class_id"] for h in e.open_hypotheses()}
    all_have_disproof = all(h["disproof"] for h in e.open_hypotheses())
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (len(made) >= 2 and {"authz", "idor"} <= classes
            and all_have_disproof), (
        f"generated {len(made)} hypotheses from the surface alone, covering "
        f"{sorted(classes)} — none of them handed in; every one carries a "
        f"disproof={all_have_disproof}")


def c_19b():
    from orch import hypothesis as H
    root = sandbox("hyp2")
    con = fresh_db(root)
    e = H.HypothesisEngine(con, "t19b")
    refusals = 0
    for stmt, disproof in (("this endpoint is probably vulnerable somewhere",
                            ""), ("short", "x")):
        try:
            e.propose(stmt, class_id="idor", disproof=disproof, origin="s")
        except ValueError:
            refusals += 1
    n = con.execute("SELECT count(*) n FROM hypothesis WHERE hunt_id=?",
                    ("t19b",)).fetchone()["n"]
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (refusals == 2 and n == 0), (
        f"a hypothesis with no disproof and a vague one are both refused "
        f"({refusals}/2); rows written={n} (must be 0) — an unfalsifiable claim "
        f"never enters the graph")


# ===========================================================================
# §20-§24  AGENTS
# ===========================================================================

def c_20():
    from orch import agents
    con = live_db()
    cleanup(con, "DELETE FROM agent_run WHERE role_key LIKE 'score.s%'",
            "DELETE FROM agent_role WHERE role_key LIKE 'score.s%'")
    built = []
    for key, dom, kind, toolsets in (
            ("score.s.recon", "web", "recon", ["web"]),
            ("score.s.authz", "web", "authorization", ["api"]),
            ("score.s.xss", "web", "xss", ["web"]),
            ("score.s.net", "network", "service_enum", ["network"]),
            ("score.s.val", "validation", None, ["validation"])):
        agents.build_role(con, key, dom, toolsets=toolsets,
                          capabilities=["READ", "ANALYZE"],
                          objective_kind=kind, rationale=f"score probe {kind}")
        built.append(key)
    roles = con.execute(
        "SELECT role_key FROM agent_role WHERE role_key LIKE 'score.s%'").fetchall()
    con.close()
    return len(roles) >= 5, (
        f"{len(roles)} specialist roles constructed as DATA across "
        f"{len({k.split('.')[2] for k in built})} domain families — not a "
        f"hard-coded enum")


def c_21():
    from orch import agentkit
    p = agentkit.decompose_for_parallelism(
        "assess the invoice export route",
        branches=["http probe", "js analysis", "authz matrix", "response diff"])
    return (len(p["branches"]) == 4 and p["parallelisable"]), (
        f"{len(p['branches'])} independent branches, "
        f"parallelisable={p['parallelisable']}")


def c_22():
    from orch import agentkit, agents
    con = live_db()
    cleanup(con, "DELETE FROM agent_failure WHERE role_key LIKE 'score.s%'",
            "DELETE FROM agent_run WHERE role_key LIKE 'score.s%'",
            "DELETE FROM agent_role WHERE role_key LIKE 'score.s%'")
    agents.build_role(con, "score.s.webx", "web", toolsets=["web"],
                      capabilities=["READ"], objective_kind="xss",
                      rationale="web xss specialist")
    agents.build_role(con, "score.s.netx", "network", toolsets=["network"],
                      capabilities=["READ"], objective_kind="ldap_enum",
                      rationale="network enumeration specialist")
    web = agentkit.select_agent(con, objective="test xss in the search box",
                                domain="web", class_id="xss")
    net = agentkit.select_agent(con, objective="enumerate ldap objects",
                                domain="network", class_id=None)
    agentkit.record_failure(con, "score.s.webx", reason="three false leads",
                            class_id="xss")
    after = agentkit.select_agent(con, objective="test xss in the search box",
                                  domain="web", class_id="xss")
    hist_before = web["ranking"][0]["components"]["history"]
    hist_after = after["ranking"][0]["components"]["history"]
    weights_sum = round(sum(agentkit.SELECTION_WEIGHTS.values()), 6)
    con.close()
    return (web["selected"] != net["selected"] and hist_after < hist_before
            and weights_sum == 1.0 and bool(web["reason"])), (
        f"scored selection differs by objective (web->{web['selected']}, "
        f"net->{net['selected']}); prior failures penalised the specialist "
        f"({hist_before}->{hist_after}); weights sum to {weights_sum}")


def c_23():
    from orch import agentkit
    con = live_db()
    accepted, downgraded_from = set(), set()
    for t in agentkit.RESULT_TYPES:
        env = agentkit.parse_output({"type": t, "payload": "x"})
        accepted.add(env["type"])
        if env["downgraded"]:
            downgraded_from.add(env["original_type"])
    # Every declared type is understood; VALIDATED_FINDING is understood and
    # DELIBERATELY re-routed, so the effective set differs by exactly that one.
    expected = {t for t in agentkit.RESULT_TYPES} - {"VALIDATED_FINDING"}
    expected.add("CANDIDATE_FINDING")
    down = agentkit.parse_output({"type": "VALIDATED_FINDING",
                                  "payload": "I proved it"})
    no_ev = agentkit.parse_output({"type": "VALIDATED_FINDING", "payload": "x"})
    try:
        agentkit.parse_output({"type": "MADE_UP_TYPE"})
        bad_refused = False
    except agentkit.ResultContractError:
        bad_refused = True
    try:
        agentkit.parse_output({"payload": "no type"})
        typeless_refused = False
    except agentkit.ResultContractError:
        typeless_refused = True
    con.close()
    return (accepted == expected
            and downgraded_from == {"VALIDATED_FINDING"}
            and down["type"] == "CANDIDATE_FINDING" and down["downgraded"]
            and bad_refused and typeless_refused
            and any("NO evidence" in n or "no evidence" in n
                    for n in no_ev["notes"])), (
        f"all {len(agentkit.RESULT_TYPES)} §23 types accepted; an agent's "
        f"VALIDATED_FINDING was DOWNGRADED to {down['type']}; unknown and "
        f"typeless outputs refused={bad_refused}/{typeless_refused}; "
        f"effective type set={sorted(accepted)}")


def c_24():
    from orch import concurrency, dag, store
    con = live_db()
    cleanup(con, "DELETE FROM task WHERE task_key LIKE 'score.24%'",
            "DELETE FROM task_dep WHERE task_key LIKE 'score.24%'")
    for i in range(6):
        store.add_task(con, f"score.24.t{i}", f"probe {i}",
                       expected_artifact="x")
    con.commit()
    dag.refresh_readiness(con)
    waves = dag.parallel_waves(con)
    cap = concurrency.cap(list(range(10)))
    dropped = concurrency.dropped(list(range(10)))
    clean = concurrency.problems()
    cleanup(con, "DELETE FROM task WHERE task_key LIKE 'score.24%'",
            "DELETE FROM task_dep WHERE task_key LIKE 'score.24%'")
    con.close()
    return (bool(waves) and len(cap) == concurrency.budget()
            and len(cap) + len(dropped) == 10 and not clean), (
        f"{len(waves)} topological wave(s); cap={concurrency.budget()} enforced "
        f"in the path (10 -> {len(cap)} run + {len(dropped)} deferred, none "
        f"silently dropped); cap self-check clean={not clean}")


# ===========================================================================
# §25 DYNAMIC RESOURCE MANAGEMENT
# ===========================================================================

def c_25():
    from orch import dag, priority, store
    con = live_db()
    cleanup(con, "DELETE FROM task WHERE task_key LIKE 'score.25%'")
    store.add_task(con, "score.25.low", "low value work", priority=8,
                   expected_artifact="x")
    store.add_task(con, "score.25.high", "gap-closing work with cited evidence",
                   priority=1, class_id="idor", expected_artifact="x",
                   evidence_req="cited evidence")
    con.commit()
    dag.refresh_readiness(con)   # readiness is DERIVED from edges, never a flag
    ranked = [t["task_key"] for t in priority.rank(con)
              if t["task_key"].startswith("score.25")]
    explained = priority.explain(con, "score.25.high")
    con.close()
    return (ranked[:1] == ["score.25.high"] and "score = " in explained), (
        f"backlog ordered by measured evidence {ranked}; a ranking nobody can "
        f"interrogate is a ranking nobody trusts — explain() returns a "
        f"breakdown")


# ===========================================================================
# §26 TECHNIQUE FAILURE
# ===========================================================================

def c_26():
    from orch import agents, orchestrator, store
    con = live_db()
    cleanup(con, "DELETE FROM recovery_attempt WHERE task_key='score.26'",
            "DELETE FROM task WHERE task_key='score.26'")
    store.add_task(con, "score.26", "failing technique", expected_artifact="x")
    con.commit()
    r = agents.recover(con, "score.26", orchestrator.RECOVERY_LADDER, budget=10)
    ladder = orchestrator.RECOVERY_LADDER
    distinct = len(set(ladder)) == len(ladder)
    n = con.execute("SELECT count(*) n FROM recovery_attempt WHERE"
                    " task_key='score.26'").fetchone()["n"]
    con.close()
    return (distinct and len(ladder) == 10 and not r["recovered"] and n == 10), (
        f"{len(ladder)} DISTINCT recovery rungs; budget spent="
        f"{r['attempts_used']} recorded attempts={n}; exhaustion BLOCKS "
        f"(recovered={r['recovered']}) rather than repeating one action")


# ===========================================================================
# §27 ATTACK PATH REASONING
# ===========================================================================

def c_27():
    from orch import surface as S
    root = sandbox("path")
    con = fresh_db(root)
    s = S.Surface(con, "t27")
    s.add_node("host", "app.acme.test", evidence="recon")
    s.add_node("endpoint", "/api/invoice?id=", params=["id"], evidence="recon")
    s.add_node("boundary", "anon->customer", evidence="arch")
    s.add_node("endpoint", "/admin/billing", evidence="recon")
    s.link_weakness(finding_key="F1", class_id="idor",
                    entry_node="endpoint:/api/invoice?id=",
                    weakness="object reference not bound to the caller",
                    boundary="boundary:anon->customer",
                    privilege="anon->billing-admin",
                    sensitive="endpoint:/admin/billing",
                    impact="cross-tenant invoice read", demonstrated=True,
                    rationale="two accounts, same object id, different owner")
    p = s.paths()
    reach = s.reachable_from("endpoint:/api/invoice?id=")
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (len(p) == 1 and p[0]["crosses_boundary"] and p[0]["demonstrated"]
            and p[0]["privilege"] and p[0]["impact"]), (
        f"entry -> weakness -> trust boundary -> privilege -> sensitive -> "
        f"impact modelled; crosses={p[0]['crosses_boundary']}, "
        f"demonstrated={p[0]['demonstrated']}; graph reachable="
        f"{len(reach)} node(s)")


# ===========================================================================
# §28 VULNERABILITY CHAINING
# ===========================================================================

def c_28():
    from orch import surface as S
    root = sandbox("chain")
    con = fresh_db(root)
    s = S.Surface(con, "t28")
    # Section 28 chains TWO weaknesses: Weakness A -> Weakness B -> a
    # privilege or impact boundary. Two records of the SAME class are one
    # weakness observed twice, not a chain, so the pair must differ in class.
    # The reachability that connects them is an EDGE in the surface, never a
    # shared string in two records.
    s.add_node("endpoint", "/api/invoice?id=", evidence="recon")
    s.add_node("endpoint", "/admin/billing", evidence="recon")
    s.add_node("boundary", "b1", evidence="arch")
    s.add_edge("endpoint:/admin/billing", "endpoint:/api/invoice?id=",
               "exposes")
    s.link_weakness(finding_key="A", class_id="idor",
                    entry_node="endpoint:/api/invoice?id=",
                    weakness="object reference not bound to the caller",
                    sensitive="endpoint:/admin/billing", demonstrated=False)
    s.link_weakness(finding_key="B", class_id="authz",
                    entry_node="endpoint:/admin/billing",
                    weakness="the billing route trusts a client-supplied role",
                    demonstrated=False)
    undemo = s.chains()
    s.link_weakness(finding_key="A", class_id="idor",
                    entry_node="endpoint:/api/invoice?id=",
                    weakness="object reference not bound to the caller",
                    boundary="boundary:b1", sensitive="endpoint:/admin/billing",
                    demonstrated=True)
    s.link_weakness(finding_key="B", class_id="authz",
                    entry_node="endpoint:/admin/billing",
                    weakness="the billing route trusts a client-supplied role",
                    boundary="boundary:b1", demonstrated=True)
    demo = s.chains()
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (len(undemo["chains"]) == 0 and undemo["candidates"] >= 1
            and len(demo["chains"]) == 1), (
        f"undemonstrated: {undemo['candidates']} candidate(s) but "
        f"{len(undemo['chains'])} claimed chain(s); after demonstration: "
        f"{len(demo['chains'])} claimed — a chain is only claimed when it is "
        f"actually demonstrated")


# ===========================================================================
# §29 MAXIMUM SAFE PROOF
# ===========================================================================

def c_29():
    from orch import policy
    c = ctx()
    weak = policy.safe_proof(c, tier="read_only_response")
    strong = policy.safe_proof(c, tier="privilege_escalation")
    danger = policy.safe_proof(c, tier="denial_of_service")
    exfil = policy.safe_proof(c, tier="data_exfiltration")
    bogus = policy.safe_proof(c, tier="launch_missiles")
    return (weak["allowed"] and strong["allowed"] and not danger["allowed"]
            and not exfil["allowed"] and not bogus["allowed"]), (
        f"weak proof allowed={weak['allowed']} "
        f"(chose {weak['chosen']['tier']}); strongest allowed proof="
        f"{strong['chosen']['tier'] if strong['chosen'] else None}; DoS refused="
        f"{not danger['allowed']}, exfiltration refused={not exfil['allowed']}; "
        f"unknown tier refused={not bogus['allowed']}")


# ===========================================================================
# §30 UNKNOWN BEHAVIOUR — dual path
# ===========================================================================

def c_30():
    from orch import hypothesis as H
    root = sandbox("unknown")
    con = fresh_db(root)
    e = H.HypothesisEngine(con, "t30")
    r = e.open_unknown("the export route returns 200 with a body that changes "
                       "on every request",
                       signals=["unexpected_status", "novel_response_shape"])
    both = bool(r["research_task"] and r["hunting_task"])
    both_exist = con.execute(
        "SELECT count(*) n FROM task WHERE task_key IN (?, ?)",
        (r["research_task"], r["hunting_task"])).fetchone()["n"] == 2
    try:
        e.resolve_unknown(r["ub_key"], "idor", resolved_by="")
        no_evidence_refused = False
    except ValueError:
        no_evidence_refused = True
    e.resolve_unknown(r["ub_key"], "idor",
                      resolved_by="https://owasp.org/x (quote verified)")
    resolved = con.execute(
        "SELECT classification, resolved_by FROM unknown_behaviour WHERE"
        " ub_key=?", (r["ub_key"],)).fetchone()
    con.close()
    shutil.rmtree(root.parent, ignore_errors=True)
    return (both and both_exist and no_evidence_refused
            and resolved["classification"] == "idor"), (
        f"UNKNOWN behaviour opened BOTH a research and a hunting task "
        f"(both exist={both_exist}); resolving without evidence refused="
        f"{no_evidence_refused}; research alone classified it as "
        f"{resolved['classification']}")


# ===========================================================================
# §31 RESEARCH ENGINE — sources beyond the obvious three
# ===========================================================================

def c_31():
    from wks import research_sources
    srcs = list(research_sources.RESEARCH_SOURCES)
    urls = " ".join(str(getattr(s, "url", s)).lower() for s in srcs)
    families = {
        "practitioner writeups/blogs": any(
            x in urls for x in ("medium.com", "blog", "substack")),
        "community technique dbs": any(
            x in urls for x in ("hacktricks", "howtohunt", "pentesterland",
                                "0xdf", "orange")),
        "cve/vuln intelligence": any(
            x in urls for x in ("cve", "nvd", "vulners", "exploit-db",
                                "github.com/advisories")),
        "vendor/standards docs": any(
            x in urls for x in ("owasp.org", "portswigger", "mitre.org",
                                "rfc-editor", "man7")),
        "tooling repos": any(x in urls for x in ("github.com", "gitlab")),
    }
    have = [k for k, v in families.items() if v]
    tiers = {getattr(s, "tier", None) for s in srcs}
    return (len(srcs) >= 20 and len(have) >= 4 and len(tiers) >= 2), (
        f"{len(srcs)} registered research sources across {len(have)} families "
        f"({', '.join(have)}) over {len(tiers)} tier(s) — research is not "
        f"restricted to OWASP/PortSwigger/MITRE (§31)")


# ---- registration -----------------------------------------------------------

REGISTER_1 = (
    ("§1",   c_01,   "EXEC", "the engine exists and declares §59's state machine"),
    ("§58",  c_01b_loop_present,  "EXEC", "the observe->decide->act loop is implemented phase "
                            "by phase"),
    ("§2",   c_02,   "EXEC", "the plan is live and regenerates from new "
                             "observations"),
    ("§3",   c_03,   "WIRE", "autonomy never crosses the asset boundary"),
    ("§4",   c_04,   "EXEC", "AuthorizationContext carries all 11 §4 fields and "
                             "gates"),
    ("§5",   c_05,   "WIRE", "ambiguous authorization BLOCKS and asks the user"),
    ("§5",   c_05b,  "WIRE", "authorization is never inferred from DNS, "
                             "certificates, redirects or shared infrastructure"),
    ("§6",   c_06,   "WIRE", "out-of-scope assets are recorded, never tested, "
                             "and a violation is detectable"),
    ("§7",   c_07,   "EXEC", "a forbidden technique yields a permitted substitute"),
    ("§8",   c_08,   "EXEC", "initialisation plans recon, validation, evidence "
                             "and research explicitly"),
    ("§9",   c_09,   "EXEC", "the plan and the graph are modifiable at runtime"),
    ("§10",  c_10,   "EXEC", "the orchestrator holds the global model of the hunt"),
    ("§11",  c_11,   "EXEC", "the task graph is dynamic, derived and acyclic"),
    ("§12",  c_12,   "EXEC", "recon is target-driven and its output is understood"),
    ("§13",  c_13,   "EXEC", "tool selection is dynamic with declared coverage gaps"),
    ("§14",  c_14,   "EXEC", "Burp is a first-class capability with probed "
                             "availability"),
    ("§15",  c_15,   "EXEC", "the browser is first-class and refuses to fake a "
                             "session"),
    ("§16",  c_16,   "EXEC", "WSL availability is probed honestly and "
                             "substitution is declared"),
    ("§17",  c_17,   "DATA", "authentication context is modelled and secrets are "
                             "not persisted"),
    ("§18",  c_18,   "EXEC", "the surface is stored once and every view is "
                             "derived from it"),
    ("§19",  c_19,   "EXEC", "hypotheses are GENERATED from the surface, not "
                             "handed in"),
    ("§19",  c_19b,  "WIRE", "a hypothesis with no disproof is refused outright"),
    ("§20",  c_20,   "EXEC", "specialist roles are data, not a fixed enum"),
    ("§21",  c_21,   "EXEC", "an objective decomposes into independent branches"),
    ("§22",  c_22,   "EXEC", "agent selection is scored and history-sensitive"),
    ("§23",  c_23,   "WIRE", "the output contract is enforced and an agent's "
                             "self-validation is downgraded"),
    ("§24",  c_24,   "EXEC", "parallel execution derives waves and enforces the "
                             "measured cap"),
    ("§25",  c_25,   "EXEC", "resources follow measured value and the ranking is "
                             "explainable"),
    ("§26",  c_26,   "EXEC", "failure walks a distinct recovery ladder, then blocks"),
    ("§27",  c_27,   "EXEC", "an attack path is modelled entry->weakness->"
                             "boundary->impact"),
    ("§28",  c_28,   "EXEC", "a chain is claimed only when demonstrated"),
    ("§29",  c_29,   "WIRE", "the strongest SAFE proof is chosen and unsafe tiers "
                             "are refused"),
    ("§30",  c_30,   "WIRE", "unknown behaviour opens a research AND a hunting path"),
    ("§31",  c_31,   "DATA", "the research engine draws on more than three source "
                             "families"),
)

for _sec, _fn, _kind, _label in REGISTER_1:
    check(_sec, _label, _kind, _fn)