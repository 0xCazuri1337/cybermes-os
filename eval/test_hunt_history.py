import os, tempfile, unittest, json
from pathlib import Path
os.environ.setdefault("HUNT_EVIDENCE_KEY", "a" * 32)
# point WKS_ROOT to repo root for imports
ROOT = Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0, str(ROOT))
os.environ.setdefault("WKS_ROOT", str(ROOT))
from orch import hunt_history as hh

class TestHuntHistory(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        os.environ["HUNTS_ROOT"] = str(Path(self.td.name) / "hunts")
        self.s = hh.create_session("example.com", authorization={"kind":"lab"}, scope={"in":["example.com"]})

    def test_session_files(self):
        p = self.s.root
        self.assertTrue((p/"session.json").exists())
        self.assertTrue((p/"authorization.json").exists())

    def test_evidence_encrypt_decrypt(self):
        m = hh.HuntHistory(self.s).add_evidence("ev1", b"secret raw", sanitized={"h":"v"}, metadata={"x":1})
        self.assertTrue((self.s.paths()["evidence_raw"]/"ev1.enc").exists())
        v = hh.HuntHistory(self.s).verify_evidence("ev1")
        self.assertTrue(v["ok"])
        # raw file should not contain plaintext
        raw_text = (self.s.paths()["evidence_raw"]/"ev1.enc").read_text()
        self.assertNotIn("secret raw", raw_text)

    def test_no_key_fail_closed(self):
        old = os.environ.pop("HUNT_EVIDENCE_KEY", None)
        try:
            with self.assertRaises(RuntimeError):
                hh.encrypt_raw(b"x")
        finally:
            if old is not None:
                os.environ["HUNT_EVIDENCE_KEY"] = old

    def test_sanitize(self):
        out = hh.sanitize_evidence({"headers":{"Authorization":"Bearer abc","Cookie":"sid=1"}, "q":"?token=xyz"})
        self.assertEqual(out["headers"]["Authorization"], "[REDACTED]")

    def test_outcome_taxonomy(self):
        hs = hh.HuntHistory(self.s)
        r = hs.close("POSITIVE_SIGNAL")
        self.assertEqual(r["outcome"], "POSITIVE_SIGNAL")
        with self.assertRaises(ValueError):
            hs2 = hh.HuntHistory(hh.create_session("t2"))
            hs2.close("NOPE")

    def test_timeline_hypotheses_results(self):
        hs = hh.HuntHistory(self.s)
        hs.add_hypothesis({"statement":"h1"})
        hs.add_result({"status":"ok"})
        hs.add_negative_result({"reason":"none"})
        hs.add_dead_end({"why":"x"})
        hs.add_finding({"title":"f"})
        self.assertEqual(len(hs._read("hypotheses")),1)
        self.assertEqual(len(hs._read("results")),1)
        self.assertEqual(len(hs._read("negative_results")),1)
        self.assertEqual(len(hs._read("dead_ends")),1)
        self.assertEqual(len(hs._read("findings")),1)
        self.assertGreater(len(hs.timeline()),0)

    def test_search(self):
        hs = hh.HuntHistory(self.s)
        hs.add_finding({"title":"unique_marker_xyz"})
        hits = hs.search("unique_marker_xyz")
        self.assertTrue(len(hits)>0)

    def test_recovery(self):
        s2 = hh.create_session("t3")
        hs = hh.HuntHistory(s2)
        self.assertTrue(hs.is_interrupted())
        hs.recover()
        self.assertTrue(s2.recovered)

    def test_rebuild_index_export(self):
        hh.rebuild_index()
        self.assertTrue((Path(os.environ["HUNTS_ROOT"])/"index.json").exists())
        out = hh.export_session(self.s.session_id, self.s.target)
        self.assertTrue(Path(out).exists())

    def test_candidate_extraction_and_fp(self):
        hs = hh.HuntHistory(self.s)
        hs.add_finding({"finding_key":"fk1","class_id":"idor","title":"f"})
        cands = hs.extract_candidates()
        self.assertTrue(len(cands)>0)
        self.assertEqual(cands[0]["origin"],"HUNT")

if __name__ == "__main__":
    unittest.main()
