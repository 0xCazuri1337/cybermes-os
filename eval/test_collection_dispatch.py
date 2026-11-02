"""Integration test for the collection-agent dispatch layer.

MEASURED CONTEXT: before this test existed, the five collection roles
(recon, dorking, js, fuzzing, understand) existed only as prose in
`runtime/opencode/manifest.md` and `runtime/opencode/ORCHESTRATION.md`. The
registry listed only `["validator", "exploit-builder"]`. `agents/` held no
briefing files for them. `orch/agents.py` had no collection role, no
concurrency cap, no endpoint-conflict rule and no WAF gate.

Each test below drives a rule that was previously unwritten, and each has a
negative control: a check that cannot go red certifies nothing.

The tests use a scratch database built from the project's own schema, so the
live `db/wks.db` is never touched.
"""
from __future__ import annotations

import shutil
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = 0
FAIL = 0

# Every check in a test appends its failure here, and the test fails if the
# list is non-empty at teardown. Without this, `check()` only PRINTED a
# failure — the suite reported "OK" while a rule had been violated, which is
# exactly the kind of green that certifies nothing.
_CURRENT: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        _CURRENT.append(f"{label}  ({detail})")
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))


class CollectionDispatchTests(unittest.TestCase):
    def setUp(self):
        _CURRENT.clear()
        self.tmp = tempfile.mkdtemp(prefix="collection_")
        self.addCleanup(shutil.rmtree, self.tmp, True)

        # THE REAL CONNECTION, WITH THE AUTHORIZER INSTALLED.
        #
        # MEASURED 2026-11-01: this test built its sandbox with a bare
        # `sqlite3.connect`, so the ownership authorizer was NEVER
        # exercised. That is how the collection layer stayed green while
        # `collection_waf_status` and `collection_deferral` were OWNERLESS
        # tables -- every real write to them was refused with "not
        # authorized" the moment the authorizer was installed by default.
        # The suite reported PASS; the runtime was broken. This is the
        # project's own I33 lesson recurring, and the fix is to open the
        # database the way production does.
        #
        # `orch.store.open_db` applies BOTH schema scripts (so the
        # collection layer's own tables exist) and then installs the ORCH
        # authorizer, so a cross-owner write in this test fails exactly as
        # it would in a real hunt.
        from orch import store as orch_store
        from wks import config as wks_config
        from wks import store as wks_store

        self.db = Path(self.tmp) / "wks.db"
        _real_db_path = orch_store.db_path
        orch_store.db_path = lambda: self.db  # type: ignore[assignment]
        try:
            self.con = orch_store.open_db(create=True)
        finally:
            orch_store.db_path = _real_db_path  # type: ignore[assignment]
        self.orch_store = orch_store
        self.wks_store = wks_store
        self.wks_config = wks_config

        from orch import collection
        self.collection = collection
        collection.build_all_collection_roles(self.con)

        # A scope grant so the authorization gate can pass for an offensive
        # role — used to prove the COLLECTION refusal is what blocks, not the
        # scope gate.
        orch_store.grant_scope(self.con, "scope-test", "example.test",
                                "bugbounty", "TEST-AUTH-1",
                                offensive_allowed=True)

    def tearDown(self):
        self.con.close()
        if _CURRENT:
            self.fail("rule violations:\n  - " + "\n  - ".join(_CURRENT))

    # ------------------------------------------------------------------
    def test_all_five_roles_are_declared_and_reachable(self):
        print("\nC1  THE FIVE COLLECTION ROLES ARE DECLARED")
        from orch import collection
        expected = {"recon-agent", "dorking-agent", "understand-agent",
                    "js-agent", "fuzzing-agent"}
        check("five roles are declared", set(collection.COLLECTION_ROLES) == expected,
              str(set(collection.COLLECTION_ROLES)))
        rows = self.con.execute(
            "SELECT role_key, capabilities FROM agent_role").fetchall()
        declared = {r["role_key"] for r in rows}
        check("every role exists in agent_role",
              expected.issubset(declared), str(declared))

    def test_a_collection_role_cannot_hold_offensive_capability(self):
        print("\nC2  A COLLECTION ROLE CANNOT BE AN EXPLOITER")
        from orch import collection
        from orch import agents
        raised = False
        try:
            collection.assert_not_exploiter("recon-agent", ["READ", "EXECUTE"])
        except collection.CollectionPolicyError:
            raised = True
        check("declaring EXECUTE is refused", raised)

        # And the refusal is structural: a role built through the normal path
        # can never end up with EXECUTE.
        for role_key, spec in collection.COLLECTION_ROLES.items():
            row = self.con.execute(
                "SELECT capabilities FROM agent_role WHERE role_key=?",
                (role_key,)).fetchone()
            caps = {c.upper() for c in __import__("json").loads(
                row["capabilities"] or "[]")}
            check(f"{role_key} holds no offensive capability",
                  not (caps & collection.OFFENSIVE_CAPABILITIES), str(caps))

        # A role whose agent_role row was WIDENED directly in the database
        # must still be refused at dispatch time — the check is not
        # construction-only.
        self.con.execute(
            "UPDATE agent_role SET capabilities=? WHERE role_key='recon-agent'",
            ('["READ","ANALYZE","EXECUTE"]',))
        self.con.commit()
        res = self.collection.dispatch_collection(
            self.con, "recon-agent", target="example.test",
            objective="collect hosts", endpoint=None)
        check("a widened role is refused at DISPATCH", not res["dispatched"],
              str(res))
        check("the refusal names the offensive capability",
              "EXECUTE" in res.get("reason", ""), str(res))

    def test_concurrency_cap_of_three_is_enforced(self):
        print("\nC3  THE CONCURRENCY CAP OF 3 IS ENFORCED")
        # Three TARGET-CONTACTING roles, each on its own endpoint. The
        # passive role is not used here: it may not hold a target-scoped
        # endpoint at all, which is a different rule (C6) and would mask the
        # cap being tested here.
        for i, role_key in enumerate(("recon-agent", "js-agent",
                                       "understand-agent")):
            res = self.collection.dispatch_collection(
                self.con, role_key, target="example.test",
                objective=f"collect {i}",
                endpoint=f"https://example.test/path{i}")
            check(f"dispatch {i + 1} succeeds", res["dispatched"], str(res))
        res = self.collection.dispatch_collection(
            self.con, "dorking-agent", target="example.test",
            objective="collect 4", endpoint=None)
        check("the FOURTH concurrent collection agent is refused",
              not res["dispatched"], str(res))
        check("the refusal names the cap",
              "cap" in res.get("reason", ""), str(res))

        active = self.collection.active_collection_runs(self.con)
        check("exactly 3 collection runs are active", len(active) == 3,
              f"n={len(active)}")

    def test_two_agents_cannot_work_the_same_endpoint(self):
        print("\nC4  TWO COLLECTION AGENTS CANNOT SHARE AN ENDPOINT")
        endpoint = "https://example.test/api/users"
        first = self.collection.dispatch_collection(
            self.con, "recon-agent", target="example.test",
            objective=f"recon {endpoint}", endpoint=endpoint)
        check("the first agent on the endpoint is dispatched",
              first["dispatched"], str(first))
        second = self.collection.dispatch_collection(
            self.con, "js-agent", target="example.test",
            objective=f"js {endpoint}", endpoint=endpoint)
        check("a second agent on the SAME endpoint is refused",
              not second["dispatched"], str(second))
        check("the refusal names the endpoint",
              endpoint in second.get("reason", ""), str(second))

        other = self.collection.dispatch_collection(
            self.con, "js-agent", target="example.test",
            objective="js /other", endpoint="https://example.test/api/other")
        check("a DIFFERENT endpoint is allowed", other["dispatched"], str(other))

    def test_fuzzing_role_is_waf_gated(self):
        print("\nC5  THE FUZZING ROLE IS WAF-GATED")
        res = self.collection.dispatch_collection(
            self.con, "fuzzing-agent", target="example.test",
            objective="discover endpoints", endpoint="https://example.test/x")
        check("fuzzing is refused when WAF status is UNKNOWN",
              not res["dispatched"], str(res))
        check("the refusal says the gate is closed",
              res.get("waf_gate") == "closed", str(res))

        # Recording 'unknown' explicitly is still not a measurement.
        self.collection.record_waf_status(self.con, "example.test", "unknown",
                                          evidence="not measured yet")
        res2 = self.collection.dispatch_collection(
            self.con, "fuzzing-agent", target="example.test",
            objective="discover endpoints", endpoint="https://example.test/x")
        check("an explicit 'unknown' still keeps the gate closed",
              not res2["dispatched"], str(res2))

        self.collection.record_waf_status(
            self.con, "example.test", "detected",
            evidence="cf-ray header present", recorded_by="recon-agent")
        res3 = self.collection.dispatch_collection(
            self.con, "fuzzing-agent", target="example.test",
            objective="discover endpoints", endpoint="https://example.test/x")
        check("fuzzing dispatches once a WAF status is MEASURED",
              res3["dispatched"], str(res3))

        # And 'none' also opens it — the gate wants a measurement, not a
        # particular verdict.
        self.con.execute("UPDATE agent_run SET status='completed'")
        self.con.commit()
        self.collection.record_waf_status(self.con, "example.test", "none",
                                          evidence="no CDN headers",
                                          recorded_by="recon-agent")
        res4 = self.collection.dispatch_collection(
            self.con, "fuzzing-agent", target="example.test",
            objective="discover endpoints", endpoint="https://example.test/y")
        check("a measured 'none' also opens the gate", res4["dispatched"],
              str(res4))

    def test_passive_role_may_not_be_given_a_target_endpoint(self):
        print("\nC6  A PASSIVE ROLE MAY NOT BE GIVEN A TARGET ENDPOINT")
        res = self.collection.dispatch_collection(
            self.con, "dorking-agent", target="example.test",
            objective="osint on the target",
            endpoint="https://example.test/robots.txt")
        check("a passive role given a target endpoint is refused",
              not res["dispatched"], str(res))
        check("the refusal names the passive rule",
              "passive" in res.get("reason", "").lower(), str(res))

        ok = self.collection.dispatch_collection(
            self.con, "dorking-agent", target="example.test",
            objective="osint on public sources", endpoint=None)
        check("the passive role dispatches for pure OSINT", ok["dispatched"],
              str(ok))

    def test_deferrals_are_recorded_with_reasons(self):
        print("\nC7  DEFERRALS ARE RECORDED, NOT FORGOTTEN")
        self.collection.dispatch_collection(
            self.con, "fuzzing-agent", target="example.test",
            objective="discover endpoints", endpoint="https://example.test/x")
        rows = self.collection.deferrals(self.con)
        check("a deferral row exists", len(rows) == 1, f"n={len(rows)}")
        check("the deferral names the role",
              rows[0]["role_key"] == "fuzzing-agent", rows[0]["role_key"])
        check("the deferral carries a reason",
              bool(rows[0]["reason"]), str(rows[0]["reason"]))

    def test_dispatch_all_defers_what_it_cannot_run(self):
        print("\nC8  DISPATCH_ALL DEFERS WHAT IT CANNOT RUN")
        result = self.collection.dispatch_all(self.con, target="example.test")
        check("dispatch_all returns a count", "dispatched_count" in result,
              str(result.keys()))
        check("the WAF-gated role was deferred",
              any(d["role_key"] == "fuzzing-agent"
                  for d in result["deferred"]), str(result["deferred"]))
        # The cap is 3 and there are 5 roles, so exactly 3 go out.
        check("exactly 3 roles were dispatched (the cap)",
              result["dispatched_count"] == 3, str(result["dispatched_count"]))
        check("the remaining roles were deferred",
              result["deferred_count"] == 2, str(result["deferred_count"]))
        check("a deferral names the concurrency cap or the WAF gate",
              all(("cap" in d.get("reason", "")) or ("waf" in d.get("reason", "").lower())
                  for d in result["deferred"]),
              str([d.get("reason") for d in result["deferred"]]))

    def test_a_refused_dispatch_writes_no_agent_run(self):
        print("\nC9  A REFUSED DISPATCH LEAVES NO RUNNING AGENT")
        before = self.con.execute(
            "SELECT count(*) n FROM agent_run").fetchone()["n"]
        self.collection.dispatch_collection(
            self.con, "fuzzing-agent", target="example.test",
            objective="discover endpoints", endpoint="https://example.test/x")
        after = self.con.execute(
            "SELECT count(*) n FROM agent_run").fetchone()["n"]
        check("no agent_run row was created by a refusal", after == before,
              f"{before} -> {after}")

    def test_dispatch_uses_the_real_authorization_gate(self):
        print("\nC10  DISPATCH USES THE REAL AUTHORIZATION GATE")
        # Remove the scope grant: the collection role must then be refused,
        # proving dispatch consults the gate rather than assuming permission.
        #
        # MEASURED: before the fix in `orch/collection.py`, this dispatch
        # SUCCEEDED with `scope_ok: False` — `orch/agents.py` gates the scope
        # check only for EXECUTE/DESTRUCTIVE roles, so a READ-only role was
        # authorized against a target nobody had authorized.
        self.con.execute("DELETE FROM scope_grant WHERE scope_key='scope-test'")
        self.con.commit()
        res = self.collection.dispatch_collection(
            self.con, "recon-agent", target="example.test",
            objective="collect hosts", endpoint=None)
        check("without a scope grant the dispatch is refused",
              not res["dispatched"], str(res))
        check("the refusal names the missing scope grant",
              "scope grant" in res.get("reason", ""), str(res))

        # A PASSIVE role is a different case: it contacts no target, so it
        # needs no grant — but it also must not be handed a target endpoint.
        passive = self.collection.dispatch_collection(
            self.con, "dorking-agent", target="example.test",
            objective="public osint", endpoint=None)
        check("a passive role dispatches without a scope grant",
              passive["dispatched"], str(passive))


if __name__ == "__main__":
    unittest.main(verbosity=2)
