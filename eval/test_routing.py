"""Phase 7 routing tests (74 scenarios)."""
import os, tempfile, sqlite3, sys
from pathlib import Path
_SANDBOX=Path(tempfile.mkdtemp(prefix="routing_test_"))
os.environ["WKS_ROOT"]=str(_SANDBOX)
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import unittest
from wks import config, store, routing

def make_db():
    import tempfile
    d=tempfile.mkdtemp(prefix="rt_")
    db=Path(d)/"wks.db"
    con=store.open_db(path=db,create=True)
    return con

def cand(**kw):
    base={"id":"c1","claim":"sql injection via param","class_id":"sqli","kind":"technique"}
    base.update(kw)
    return base

class TestRouting(unittest.TestCase):
    def setUp(self):
        import os
        self.con=make_db()

    # 1-10 constants
    def test_01_update_kinds_count(self):
        self.assertEqual(len(routing.UPDATE_KINDS),7)
    def test_02_update_kinds_contains(self):
        for k in ["KNOWLEDGE","ATTACK_CHAIN","FP_RULE","SKILL_PROCEDURE","NO_CHANGE","CONFLICT","UNROUTED"]:
            self.assertIn(k,routing.UPDATE_KINDS)
    def test_03_exec_statuses(self):
        self.assertIn("AWAITING_APPROVAL",routing.EXEC_STATUSES)
    def test_04_routing_statuses(self):
        self.assertIn("POLICY_BLOCKED",routing.ROUTING_STATUSES)
    def test_05_candidate_hash_stable(self):
        self.assertEqual(routing.candidate_hash(cand()),routing.candidate_hash(cand()))
    def test_06_candidate_hash_diff(self):
        self.assertNotEqual(routing.candidate_hash(cand(claim="a")),routing.candidate_hash(cand(claim="b")))
    def test_07_decision_key_stable(self):
        self.assertEqual(routing.decision_key_for(cand()),routing.decision_key_for(cand()))
    def test_08_classify_returns_dict(self):
        r=routing.classify_update_kind(cand())
        self.assertIsInstance(r,dict)
    def test_09_classify_has_kind(self):
        r=routing.classify_update_kind(cand())
        self.assertIn("kind",r)
    def test_10_classify_confidence_range(self):
        r=routing.classify_update_kind(cand())
        self.assertGreaterEqual(r["confidence"],0.0)
        self.assertLessEqual(r["confidence"],1.0)

    # 11-20 knowledge/fp/chain/skill
    def test_11_knowledge_default(self):
        self.assertEqual(routing.classify_update_kind(cand())["kind"],"KNOWLEDGE")
    def test_12_fp_rule(self):
        self.assertEqual(routing.classify_update_kind(cand(kind="fp"))["kind"],"FP_RULE")
    def test_13_attack_chain(self):
        self.assertEqual(routing.classify_update_kind(cand(kind="chain"))["kind"],"ATTACK_CHAIN")
    def test_14_skill_procedure(self):
        self.assertEqual(routing.classify_update_kind(cand(kind="skill"))["kind"],"SKILL_PROCEDURE")
    def test_15_explicit_override(self):
        self.assertEqual(routing.classify_update_kind(cand(update_kind="FP_RULE"))["kind"],"FP_RULE")
    def test_16_false_positive_text(self):
        self.assertEqual(routing.classify_update_kind(cand(claim="false positive rule"))["kind"],"FP_RULE")
    def test_17_procedure_text(self):
        self.assertEqual(routing.classify_update_kind(cand(claim="skill procedure update"))["kind"],"SKILL_PROCEDURE")
    def test_18_chain_text(self):
        self.assertEqual(routing.classify_update_kind(cand(claim="attack chain step"))["kind"],"ATTACK_CHAIN")
    def test_19_unrouted_empty(self):
        self.assertEqual(routing.classify_update_kind(cand(claim=""))["kind"],"UNROUTED")
    def test_20_unrouted_none(self):
        self.assertEqual(routing.classify_update_kind(cand(claim=None))["kind"],"UNROUTED")

    # 21-30 conflict/nochange
    def test_21_conflict_flag(self):
        self.assertEqual(routing.classify_update_kind(cand(conflict=True))["kind"],"CONFLICT")
    def test_22_no_change_flag(self):
        self.assertEqual(routing.classify_update_kind(cand(duplicate=True))["kind"],"NO_CHANGE")
    def test_23_conflict_context(self):
        self.assertEqual(routing.classify_update_kind(cand(),context={"conflicts":["x"]})["kind"],"CONFLICT")
    def test_24_no_change_context(self):
        self.assertEqual(routing.classify_update_kind(cand(),context={"existing":[{"claim":"sql injection via param"}]})["kind"],"NO_CHANGE")
    def test_25_contradict_text(self):
        self.assertEqual(routing.classify_update_kind(cand(claim="this contradicts prior"))["kind"],"CONFLICT")
    def test_26_reasons_list(self):
        r=routing.classify_update_kind(cand())
        self.assertIsInstance(r["reasons"],list)
    def test_27_alternatives_list(self):
        r=routing.classify_update_kind(cand())
        self.assertIsInstance(r["alternatives"],list)
    def test_28_reason_string(self):
        r=routing.classify_update_kind(cand())
        self.assertIsInstance(r["reason"],str)
    def test_29_no_change_reason(self):
        r=routing.classify_update_kind(cand(duplicate=True))
        self.assertIn("no-change",r["reason"].lower().replace("_","-") or r["reason"].lower())
    def test_30_conflict_reason(self):
        r=routing.classify_update_kind(cand(conflict=True))
        self.assertTrue(len(r["reason"])>0)

    # 31-40 AI advisory
    def test_31_ai_fn_called(self):
        calls=[]
        def ai(c,ctx):
            calls.append(1)
            return {"kind":"FP_RULE","confidence":0.9,"reason":"ai"}
        routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertEqual(len(calls),1)
    def test_32_ai_does_not_override(self):
        def ai(c,ctx):
            return {"kind":"FP_RULE","confidence":0.99,"reason":"ai"}
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertEqual(r["kind"],"KNOWLEDGE")
    def test_33_ai_alternative_recorded(self):
        def ai(c,ctx):
            return {"kind":"FP_RULE","confidence":0.9,"reason":"ai"}
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertTrue(any(a["kind"]=="FP_RULE" for a in r["alternatives"]))
    def test_34_ai_advisory_stored(self):
        def ai(c,ctx):
            return {"kind":"KNOWLEDGE","confidence":0.9,"reason":"agree"}
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertIsNotNone(r["ai_advisory"])
    def test_35_ai_error_handled(self):
        def ai(c,ctx):
            raise ValueError("boom")
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertEqual(r["kind"],"KNOWLEDGE")
    def test_36_ai_never_authorizes_even_high_conf(self):
        def ai(c,ctx):
            return {"kind":"CONFLICT","confidence":1.0,"reason":"ai"}
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertNotEqual(r["kind"],"CONFLICT")
    def test_37_mockable_default_none(self):
        r=routing.classify_update_kind(cand(),ai_fn=None)
        self.assertIsNone(r["ai_advisory"])
    def test_38_ai_same_kind_reinforces(self):
        def ai(c,ctx):
            return {"kind":"KNOWLEDGE","confidence":0.9,"reason":"agree"}
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertGreaterEqual(r["confidence"],0.85)
    def test_39_ai_alternative_has_source(self):
        def ai(c,ctx):
            return {"kind":"FP_RULE","confidence":0.9,"reason":"ai"}
        r=routing.classify_update_kind(cand(),ai_fn=ai)
        self.assertEqual(r["alternatives"][0]["source"],"ai_advisory")
    def test_40_policy_blocked_flag(self):
        r=routing.classify_update_kind(cand(policy_blocked=True))
        self.assertTrue(r.get("policy_blocked"))

    # 41-50 preliminary
    def test_41_preliminary_creates_decision(self):
        d=routing.preliminary_route(self.con,cand())
        self.assertIsNotNone(d["id"])
    def test_42_preliminary_status(self):
        d=routing.preliminary_route(self.con,cand())
        self.assertEqual(d["status"],"PRELIMINARY")
    def test_43_preliminary_has_routes(self):
        d=routing.preliminary_route(self.con,cand())
        self.assertGreaterEqual(len(d["routes"]),1)
    def test_44_idempotent_same_candidate(self):
        d1=routing.preliminary_route(self.con,cand())
        d2=routing.preliminary_route(self.con,cand())
        self.assertEqual(d1["id"],d2["id"])
    def test_45_no_duplicate_decisions(self):
        routing.preliminary_route(self.con,cand())
        routing.preliminary_route(self.con,cand())
        n=self.con.execute("SELECT COUNT(*) FROM routing_decision").fetchone()[0]
        self.assertEqual(n,1)
    def test_46_before_hash_present(self):
        d=routing.preliminary_route(self.con,cand())
        self.assertIsNotNone(d["before_hash"])
    def test_47_candidate_hash_present(self):
        d=routing.preliminary_route(self.con,cand())
        self.assertEqual(d["candidate_hash"],routing.candidate_hash(cand()))
    def test_48_decision_key_present(self):
        d=routing.preliminary_route(self.con,cand())
        self.assertTrue(d["decision_key"].startswith("rd."))
    def test_49_routes_not_started(self):
        d=routing.preliminary_route(self.con,cand())
        for r in d["routes"]:
            self.assertEqual(r["execution_status"],"NOT_STARTED")
    def test_50_multi_label_routes(self):
        def ai(c,ctx):
            return {"kind":"FP_RULE","confidence":0.9,"reason":"ai"}
        d=routing.preliminary_route(self.con,cand(),ai_fn=ai)
        kinds={r["update_kind"] for r in d["routes"]}
        self.assertIn("KNOWLEDGE",kinds)
        self.assertIn("FP_RULE",kinds)

    # 51-60 finalize
    def test_51_finalize_status(self):
        d=routing.preliminary_route(self.con,cand())
        f=routing.finalize_route(self.con,d)
        self.assertEqual(f["status"],"FINAL")
    def test_52_finalize_after_hash(self):
        d=routing.preliminary_route(self.con,cand())
        f=routing.finalize_route(self.con,d)
        self.assertIsNotNone(f["after_hash"])
    def test_53_finalize_idempotent(self):
        d=routing.preliminary_route(self.con,cand())
        f1=routing.finalize_route(self.con,d)
        f2=routing.finalize_route(self.con,d["id"])
        self.assertEqual(f1["id"],f2["id"])
    def test_54_skill_route_awaiting_approval(self):
        c=cand(kind="skill")
        d=routing.preliminary_route(self.con,c)
        f=routing.finalize_route(self.con,d)
        rts=f["routes"]
        self.assertTrue(any(r["execution_status"]=="AWAITING_APPROVAL" for r in rts))
    def test_55_finalize_by_candidate(self):
        c=cand(claim="another")
        routing.preliminary_route(self.con,c)
        f=routing.finalize_route(self.con,c)
        self.assertEqual(f["status"],"FINAL")
    def test_56_finalized_at_present(self):
        d=routing.preliminary_route(self.con,cand())
        f=routing.finalize_route(self.con,d)
        self.assertIsNotNone(f["finalized_at"])
    def test_57_list_decisions(self):
        routing.preliminary_route(self.con,cand())
        lst=routing.list_decisions(self.con)
        self.assertGreaterEqual(len(lst),1)
    def test_58_filter_status(self):
        routing.preliminary_route(self.con,cand())
        lst=routing.list_decisions(self.con,status="PRELIMINARY")
        self.assertGreaterEqual(len(lst),1)
    def test_59_get_decision(self):
        d=routing.preliminary_route(self.con,cand())
        g=routing.get_decision(self.con,decision_id=d["id"])
        self.assertEqual(g["id"],d["id"])
    def test_60_audit_returns_list(self):
        routing.preliminary_route(self.con,cand())
        a=routing.audit(self.con)
        self.assertIsInstance(a,list)

    # 61-70 execution
    def test_61_execute_knowledge_applied(self):
        d=routing.preliminary_route(self.con,cand())
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid)
        self.assertTrue(res["ok"])
        self.assertEqual(res["status"],"APPLIED")
    def test_62_execute_skill_requires_approval(self):
        c=cand(kind="skill")
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid)
        self.assertFalse(res["ok"])
        self.assertEqual(res["status"],"AWAITING_APPROVAL")
    def test_63_execute_skill_approved(self):
        c=cand(kind="skill")
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d,approved=True)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid,approved=True)
        self.assertTrue(res["ok"])
    def test_64_no_change_no_mutation(self):
        c=cand(duplicate=True)
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid)
        self.assertFalse(res["ok"])
    def test_65_conflict_no_mutation(self):
        c=cand(conflict=True)
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid)
        self.assertFalse(res["ok"])
    def test_66_unrouted_no_mutation(self):
        c=cand(claim="")
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid)
        self.assertFalse(res["ok"])
    def test_67_idempotent_execute(self):
        d=routing.preliminary_route(self.con,cand())
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        routing.execute_route(self.con,rid)
        res2=routing.execute_route(self.con,rid)
        self.assertTrue(res2.get("idempotent"))
    def test_68_review_approve(self):
        c=cand(kind="skill")
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        r=routing.review_route(self.con,rid,approved=True)
        self.assertTrue(r["ok"])
    def test_69_pending_routes(self):
        d=routing.preliminary_route(self.con,cand())
        routing.finalize_route(self.con,d)
        pr=routing.pending_routes(self.con)
        self.assertGreaterEqual(len(pr),1)
    def test_70_unrouted_decisions(self):
        routing.preliminary_route(self.con,cand(claim=""))
        u=routing.unrouted_decisions(self.con)
        self.assertGreaterEqual(len(u),1)

    # 71-74 metrics/conflicts/history
    def test_71_conflict_decisions(self):
        routing.preliminary_route(self.con,cand(conflict=True))
        c=routing.conflict_decisions(self.con)
        self.assertGreaterEqual(len(c),1)
    def test_72_metrics(self):
        routing.preliminary_route(self.con,cand())
        m=routing.metrics(self.con)
        self.assertIn("decisions",m)
    def test_73_history(self):
        routing.preliminary_route(self.con,cand())
        h=routing.history(self.con,cand())
        self.assertGreaterEqual(len(h),1)
    def test_74_fp_execute_validated(self):
        c=cand(kind="fp")
        d=routing.preliminary_route(self.con,c)
        routing.finalize_route(self.con,d)
        rid=d["routes"][0]["id"]
        res=routing.execute_route(self.con,rid)
        self.assertTrue(res["ok"])

if __name__=="__main__":
    unittest.main()
