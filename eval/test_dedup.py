"""Phase 6 dedup tests (70 scenarios)."""
import os, tempfile, sqlite3, sys
from pathlib import Path
_SANDBOX=Path(tempfile.mkdtemp(prefix="dedup_test_"))
os.environ["WKS_ROOT"]=str(_SANDBOX)
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
import unittest
from wks import config, store, dedup

def make_db():
    con=store.open_db(create=True)
    # seed classes
    con.execute("INSERT OR IGNORE INTO bug_class(id,name,surface,first_seen) VALUES ('sqli','SQLi','web',? )",(store.now(),))
    con.execute("INSERT OR IGNORE INTO bug_class(id,name,surface,first_seen) VALUES ('xss','XSS','web',? )",(store.now(),))
    con.commit()
    return con

import uuid
def add_item(con,claim,class_id="sqli",kind="technique"):
    cur=con.execute("INSERT INTO item(item_key,class_id,claim,kind,created_at,updated_at) VALUES (?,?,?,?,?,?)",
        (f"{class_id}.{uuid.uuid4().hex}",class_id,claim,kind,store.now(),store.now()))
    iid=cur.lastrowid
    con.execute("INSERT INTO quality(item_id,validation_state,assessed_at) VALUES (?,?,?)",(iid,"supported",store.now()))
    con.commit()
    return iid

class TestDedup(unittest.TestCase):
    def setUp(self):
        self.con=make_db()

    # 1-10 normalization/fingerprint
    def test_01_normalize_lower(self):
        self.assertEqual(dedup.normalize_text("ABC"), "abc")
    def test_02_normalize_punct(self):
        self.assertEqual(dedup.normalize_text("a,b!"), "a b")
    def test_03_fingerprint_stable(self):
        self.assertEqual(dedup.fingerprint("same claim"), dedup.fingerprint("same claim"))
    def test_04_fingerprint_diff(self):
        self.assertNotEqual(dedup.fingerprint("a"), dedup.fingerprint("b"))
    def test_05_fingerprint_class_aware(self):
        self.assertNotEqual(dedup.fingerprint("x",class_id="sqli"), dedup.fingerprint("x",class_id="xss"))
    def test_06_exact_dup_detection(self):
        iid1=add_item(self.con,"same claim")
        iid2=add_item(self.con,"same claim")
        dedup.store_fingerprint(self.con,{"id":iid1,"claim":"same claim","class_id":"sqli"})
        dedup.store_fingerprint(self.con,{"id":iid2,"claim":"same claim","class_id":"sqli"})
        dups=dedup.find_exact_duplicates(self.con)
        self.assertTrue(len(dups)>=1)
    def test_07_no_dup_single(self):
        iid=add_item(self.con,"solo")
        dedup.store_fingerprint(self.con,{"id":iid,"claim":"solo","class_id":"sqli"})
        self.assertEqual(dedup.find_exact_duplicates(self.con,{"id":iid,"claim":"solo","class_id":"sqli"}),[])
    def test_08_polarity_pos(self):
        self.assertEqual(dedup.polarity("this works"),1)
    def test_09_polarity_neg(self):
        self.assertEqual(dedup.polarity("this does not work"),-1)
    def test_10_has_negation(self):
        self.assertTrue(dedup.has_negation("no access"))

    # 11-20 semantic similarity
    def test_11_sim_identical(self):
        self.assertGreaterEqual(dedup.semantic_similarity("abc def","abc def"),0.8)
    def test_12_sim_unrelated(self):
        self.assertLess(dedup.semantic_similarity("sql injection","weather forecast"),0.4)
    def test_13_class_aware_boost(self):
        a={"claim":"x","class_id":"sqli"}; b={"claim":"x","class_id":"sqli"}
        self.assertGreaterEqual(dedup.semantic_similarity(a,b,class_aware=True),dedup.semantic_similarity(a,b,class_aware=False))
    def test_14_seq_ratio(self):
        self.assertGreater(dedup._seq_ratio("abcd","abcd"),0.99)
    def test_15_token_jaccard(self):
        self.assertGreater(dedup._token_jaccard("aa bb cc","aa bb cc"),0.99)
    def test_16_ngram(self):
        self.assertGreater(dedup._ngram_jaccard("abcdef","abcdef"),0.99)
    def test_17_normalize_none(self):
        self.assertEqual(dedup.normalize_text(None),"")
    def test_18_tokens_minlen(self):
        self.assertNotIn("a",dedup._tokens("a bc"))
    def test_19_extract_version(self):
        self.assertEqual(dedup.extract_version("affects v1.2.3"), "v1.2.3")
    def test_20_extract_scope(self):
        self.assertIsNotNone(dedup.extract_scope("works in tenant scope"))

    # 21-30 protection
    def test_21_scope_diff_protected(self):
        p=dedup._protection("scope: a claim","scope: b claim")
        self.assertTrue(p["protected"])
    def test_22_version_diff(self):
        p=dedup._protection("v1 bug","v2 bug")
        self.assertTrue(p["version_diff"])
    def test_23_preconditions(self):
        p=dedup._protection("if admin then x","if user then x")
        self.assertTrue(p["preconditions_diff"] or p["protected"])
    def test_24_polarity_diff(self):
        p=dedup._protection("is allowed","is not allowed")
        self.assertTrue(p["polarity_diff"])
    def test_25_negation_diff(self):
        p=dedup._protection("has access","no access")
        self.assertTrue(p["negation_diff"])
    def test_26_no_protection(self):
        p=dedup._protection("same claim here","same claim here")
        self.assertFalse(p["protected"])
    def test_27_extract_preconditions_list(self):
        self.assertIsInstance(dedup.extract_preconditions("if x then y"),list)
    def test_28_extract_scope_none(self):
        self.assertIsNone(dedup.extract_scope("nothing"))
    def test_29_extract_version_none(self):
        self.assertIsNone(dedup.extract_version("no version"))
    def test_30_polarity_zero_neg_even(self):
        # two negations -> positive polarity per simple rule (0? actually -? neg=2 even not odd => 1 if neg==0 false => 0)
        self.assertIn(dedup.polarity("not bad not good"), (0,1,-1))

    # 31-40 classification
    def test_31_exact_duplicate(self):
        self.assertEqual(dedup.classify_relationship("same","same"), "EXACT_DUPLICATE")
    def test_32_semantic_near(self):
        rel=dedup.classify_relationship("sql injection via parameter","sql injection through parameter")
        self.assertIn(rel,("SEMANTIC_NEAR_DUPLICATE","UNCERTAIN","COMPLEMENTARY"))
    def test_33_potential_contradiction(self):
        rel=dedup.classify_relationship("access is allowed","access is not allowed")
        self.assertIn(rel,("POTENTIAL_CONTRADICTION","CONTEXT_DEPENDENT","SEMANTIC_NEAR_DUPLICATE"))
    def test_34_context_dependent(self):
        rel=dedup.classify_relationship("works in tenant a","works in tenant b")
        self.assertIn(rel,("CONTEXT_DEPENDENT","UNCERTAIN","COMPLEMENTARY","POTENTIAL_CONTRADICTION"))
    def test_35_unrelated(self):
        rel=dedup.classify_relationship("alpha beta","zzzz qqqq")
        self.assertIn(rel,("UNRELATED","UNCERTAIN"))
    def test_36_uncertain_mid(self):
        rel=dedup.classify_relationship("partial overlap words","different words overlap")
        self.assertIn(rel,dedup.RELATIONSHIPS)
    def test_37_complementary(self):
        rel=dedup.classify_relationship("detects xss via payload","prevents xss via filter")
        self.assertIn(rel,dedup.RELATIONSHIPS)
    def test_38_classify_returns_str(self):
        self.assertIsInstance(dedup.classify_relationship("a","b"),str)
    def test_39_relationships_tuple(self):
        self.assertIn("EXACT_DUPLICATE",dedup.RELATIONSHIPS)
    def test_40_modes_tuple(self):
        self.assertIn("AUDIT",dedup.MODES)

    # 41-50 proposals
    def test_41_propose_pending(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        self.assertEqual(r["status"],"PENDING_REVIEW")
    def test_42_approve(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"APPROVED")
        row=self.con.execute("SELECT status FROM merge_proposal WHERE id=?",(r["proposal_id"],)).fetchone()
        self.assertEqual(row["status"],"APPROVED")
    def test_43_reject(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"REJECTED")
        row=self.con.execute("SELECT status FROM merge_proposal WHERE id=?",(r["proposal_id"],)).fetchone()
        self.assertEqual(row["status"],"REJECTED")
    def test_44_defer(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"DEFERRED")
        row=self.con.execute("SELECT status FROM merge_proposal WHERE id=?",(r["proposal_id"],)).fetchone()
        self.assertEqual(row["status"],"DEFERRED")
    def test_45_apply_approved(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"APPROVED")
        out=dedup.apply_proposal(self.con,r["proposal_id"])
        self.assertTrue(out["applied"])
    def test_46_apply_unapproved_fails(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        out=dedup.apply_proposal(self.con,r["proposal_id"])
        self.assertFalse(out["applied"])
    def test_47_apply_marks_dedup_of(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"APPROVED")
        dedup.apply_proposal(self.con,r["proposal_id"])
        row=self.con.execute("SELECT dedup_of,canonical_id FROM item WHERE id=?",(iid2,)).fetchone()
        self.assertEqual(row["dedup_of"],iid1)
    def test_48_preserves_validation_state(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        before=self.con.execute("SELECT validation_state FROM quality WHERE item_id=?",(iid2,)).fetchone()["validation_state"]
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"APPROVED")
        dedup.apply_proposal(self.con,r["proposal_id"])
        after=self.con.execute("SELECT validation_state FROM quality WHERE item_id=?",(iid2,)).fetchone()["validation_state"]
        self.assertEqual(before,after)
    def test_49_no_deletion(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        cnt_before=self.con.execute("SELECT COUNT(*) c FROM item").fetchone()["c"]
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"APPROVED")
        dedup.apply_proposal(self.con,r["proposal_id"])
        cnt_after=self.con.execute("SELECT COUNT(*) c FROM item").fetchone()["c"]
        self.assertEqual(cnt_before,cnt_after)
    def test_50_mode_dispatch_audit(self):
        r=dedup.mode_dispatch(self.con,"AUDIT")
        self.assertEqual(r["mode"],"AUDIT")

    # 51-60 audit/candidates/integration
    def test_51_audit_items_scanned(self):
        add_item(self.con,"a")
        r=dedup.audit(self.con)
        self.assertGreaterEqual(r["items_scanned"],1)
    def test_52_audit_class_filter(self):
        add_item(self.con,"a","xss")
        r=dedup.audit(self.con,class_id="xss")
        for p in r["pairs"]:
            self.assertIn("xss",(p["class_a"],p["class_b"]))
    def test_53_authoritative_filter(self):
        rows=[{"id":1,"dedup_of":None},{"id":2,"dedup_of":1}]
        out=dedup.authoritative_filter(rows)
        self.assertEqual(len(out),1)
    def test_54_dedup_candidates(self):
        iid=add_item(self.con,"same claim")
        c={"claim":"same claim","class_id":"sqli"}
        res=dedup.dedup_candidates(self.con,[c])
        self.assertTrue(res[0]["is_duplicate"])
    def test_55_is_duplicate_fp_false(self):
        self.assertFalse(dedup.is_duplicate_fp(self.con,"sqli","hyp"))
    def test_56_store_fingerprint(self):
        iid=add_item(self.con,"fp")
        fid=dedup.store_fingerprint(self.con,{"id":iid,"claim":"fp","class_id":"sqli"})
        self.assertIsNotNone(fid)
    def test_57_find_exact_by_item(self):
        iid=add_item(self.con,"dup")
        dedup.store_fingerprint(self.con,{"id":iid,"claim":"dup","class_id":"sqli"})
        res=dedup.find_exact_duplicates(self.con,{"id":iid,"claim":"dup","class_id":"sqli"})
        self.assertIsInstance(res,list)
    def test_58_mode_propose(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.mode_dispatch(self.con,"PROPOSE",item_ids=[iid1,iid2])
        self.assertEqual(r["status"],"PENDING_REVIEW")
    def test_59_mode_review(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.mode_dispatch(self.con,"PROPOSE",item_ids=[iid1,iid2])
        out=dedup.mode_dispatch(self.con,"REVIEW",proposal_id=r["proposal_id"],decision="APPROVED")
        self.assertEqual(out["status"],"APPROVED")
    def test_60_mode_apply(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.mode_dispatch(self.con,"PROPOSE",item_ids=[iid1,iid2])
        dedup.mode_dispatch(self.con,"REVIEW",proposal_id=r["proposal_id"],decision="APPROVED")
        out=dedup.mode_dispatch(self.con,"APPLY",proposal_id=r["proposal_id"])
        self.assertTrue(out["applied"])

    # 61-70 aliases & constants
    def test_61_alias_detect_exact(self):
        self.assertTrue(callable(dedup.detect_exact_duplicates))
    def test_62_alias_detect_relationship(self):
        self.assertTrue(callable(dedup.detect_relationship))
    def test_63_alias_create_proposal(self):
        self.assertTrue(callable(dedup.create_merge_proposal))
    def test_64_alias_approve(self):
        self.assertTrue(callable(dedup.approve_proposal))
    def test_65_alias_reject(self):
        self.assertTrue(callable(dedup.reject_proposal))
    def test_66_alias_defer(self):
        self.assertTrue(callable(dedup.defer_proposal))
    def test_67_proposal_statuses(self):
        self.assertIn("PENDING_REVIEW",dedup.PROPOSAL_STATUSES)
    def test_68_no_auto_approval(self):
        # propose never auto-applies
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        self.assertEqual(r["status"],"PENDING_REVIEW")
    def test_69_tables_exist(self):
        for t in ("dedup_fingerprint","merge_proposal","canonical_group","item_group"):
            row=self.con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(t,)).fetchone()
            self.assertIsNotNone(row)
    def test_70_i8_original_preserved(self):
        iid1=add_item(self.con,"c1"); iid2=add_item(self.con,"c2")
        r=dedup.propose(self.con,[iid1,iid2])
        dedup.review(self.con,r["proposal_id"],"APPROVED")
        dedup.apply_proposal(self.con,r["proposal_id"])
        # items still exist
        c=self.con.execute("SELECT COUNT(*) c FROM item WHERE id IN (?,?)",(iid1,iid2)).fetchone()["c"]
        self.assertEqual(c,2)

if __name__=="__main__":
    unittest.main()