"""FM test: can quality.maturity() read 'mature' on a class made ENTIRELY of
filler / misfiled / duplicate prose?

Runs against a THROWAWAY copy of the db (WKS_ROOT points at a temp tree).
Never touches the canonical corpus.
"""
import json
import os
import sqlite3
import subprocess
import sys

SB = open(sys.argv[1]).read().strip()
os.environ["WKS_ROOT"] = SB
sys.path.insert(0, SB)

from wks import config, quality, store  # noqa: E402

assert os.path.normcase(str(config.root())) == os.path.normcase(SB), f"refusing: {config.root()} != {SB}"

con = store.open_db(create=False)
con.row_factory = sqlite3.Row
DB = os.path.join(SB, "db", "wks.db")
raw = sqlite3.connect(DB)
raw.row_factory = sqlite3.Row

CID = "idor"


def n(sql, *a):
    return raw.execute(sql, a).fetchone()[0]


print("=" * 72)
print("FM-04  CAN A CLASS READ 'mature' ON FILLER ALONE?")
print("=" * 72)
print(f"sandbox: {SB}")
print(f"thresholds: MATURITY_MIN_ITEMS={config.MATURITY_MIN_ITEMS} "
      f"MATURITY_MIN_HIGH_CONF={config.MATURITY_MIN_HIGH_CONF} "
      f"MATURITY_MIN_FP_RULES={config.MATURITY_MIN_FP_RULES} "
      f"MATURITY_MIN_CHAINS={config.MATURITY_MIN_CHAINS}")
print()

# Wipe the class down, then rebuild it from the WORST prose in the corpus --
# module filler, an off-topic XSS sentence, and a repeated duplicate.
raw.execute("DELETE FROM item_source WHERE item_id IN (SELECT id FROM item WHERE class_id=?)", (CID,))
raw.execute("DELETE FROM quality WHERE item_id IN (SELECT id FROM item WHERE class_id=?)", (CID,))
raw.execute("DELETE FROM item WHERE class_id=?", (CID,))
raw.commit()
print(f"wiped {CID}: items now = {n('select count(*) from item where class_id=?', CID)}")

FILLER = [
    # (a) MODULE_FILLER -- relevance.py's own regex matches this shape and
    #     yet TERMINAL_STATES does not include it, so it is never held
    "We will cover how to identify, exploit, and prevent each of them through various methods",
    # (b) off-topic: filed under idor, is about XSS. Two real publishers cite it.
    "An XSS vulnerability may allow an attacker to execute arbitrary JavaScript code within the target's browser",
    # (c) filler again, different wording
    "This module covers the most common attacks and vulnerabilities that can affect web application sessions",
    # (d) off-topic: cookie prose, filed under idor
    "Session cookies should set the HttpOnly and Secure flags to prevent theft through script access",
    # (e) generic, says nothing testable at all
    "Security is important for every organisation that operates systems connected to a network",
]

hosts = ["cheatsheetseries.owasp.org", "portswigger.net", "owasp.org",
         "cwe.mitre.org", "learn.microsoft.com"]
ids = []
for i, claim in enumerate(FILLER):
    cur = raw.execute(
        "INSERT INTO item (item_key,class_id,claim,kind,hunting_value,body,disproof,"
        "status,created_at,updated_at) VALUES (?,?,?,?,?,?,?,'active',datetime('now'),datetime('now'))",
        (f"{CID}.technique.filler{i:02d}", CID, claim + " " + "detail " * 40,
         "technique", 3, "body " * 60, "This is not true when the endpoint is patched"))
    iid = cur.lastrowid
    ids.append(iid)
    for h in hosts[:2]:
        sid = raw.execute(
            "INSERT OR IGNORE INTO source (url,host,title,publisher,source_type,authority,"
            "retrieved_at,http_status,content_hash,access_state) "
            "VALUES (?,?,?,?,?,?,date('now'),200,?,'ACTIVE')",
            (f"https://{h}/filler/{i}", h, "t", h, "docs", 2,
             "%064d" % i)).lastrowid
        raw.execute("INSERT INTO item_source (item_id,source_id) VALUES (?,?)", (iid, sid))
    # Re-gate through the REAL assessor so the state is earned, not asserted.
    raw.commit()
    v = quality.assess(raw, iid)
    store.set_state(raw, iid, v["state"], v["score"], v["reasons"])
    print(f"  item {iid} -> state={v['state']:16} score={v['score']:.3f} "
          f"tags={v['tags']}")
raw.commit()

# fp_case + a chain so fp_rules and chain checks pass; methodology + skill so
# those pass too. These are exactly the things a research cycle can emit
# cheaply.
for n_, hyp, inv, rule in [
    (1, "IDOR is suspected", "the object is owner-scoped", "check the owner field before reporting"),
    (2, "BOLA is suspected", "the route filters by session", "compare two sessions"),
]:
    raw.execute("INSERT INTO fp_case (fp_key,class_id,hypothesis,looked_vulnerable_because,"
                "test_performed,invalidated_by,rejection_rule,created_at) "
                "VALUES (?,?,?,?,?,?,?,datetime('now'))",
                (f"{CID}-fp{n_}", CID, hyp, "it returned another record",
                 "fetched the object as a second user", inv, rule))
raw.execute("INSERT INTO chain (chain_key,name,goal,created_at,updated_at) "
            "VALUES (?,?,?,datetime('now'),datetime('now'))",
            (f"{CID}-auto-01", "auto chain", "walk the class"))
_chid = raw.execute("select id from chain where chain_key=?", (f"{CID}-auto-01",)).fetchone()[0]
raw.execute("INSERT INTO chain_step (chain_id,ord,class_id,action,why) VALUES (?,1,?,?,?)",
            (_chid, CID, "step one", "because"))
raw.execute("UPDATE bug_class SET methodology='x', skill_path='y' WHERE id=?", (CID,))
raw.commit()

m = quality.maturity(raw, CID)
print()
print("maturity() verdict on a class built ONLY from filler + misfiled prose:")
print(json.dumps(m, indent=2))
print()
print(f"ASSERTION: state == 'mature' ?  -> {m['state'] == 'mature'}")
print(f"ASSERTION: missing == [] ?       -> {m['missing'] == []}")

# And the gate: does quality.assess hold any of these five?
held = 0
for iid in ids:
    v = quality.assess(raw, iid)
    if "relevance" in " ".join(v["tags"]).lower():
        held += 1
print()
print(f"items held by the PROMOTION GATE for being off-topic: {held}/{len(ids)}")

# And relevance.py, the module that exists to catch this, if it were wired:
sys.path.insert(0, SB)
from wks import relevance as R  # noqa: E402
rholds = 0
for iid in ids:
    r = raw.execute("select class_id,claim from item where id=?", (iid,)).fetchone()
    v = R.assess(r["class_id"], r["claim"])
    if v and v.holds:
        rholds += 1
        print(f"  relevance.py WOULD hold item {iid}: {v.reason()}")
print(f"items relevance.py would hold (but is never called by the gate): {rholds}/{len(ids)}")

print()
print(f"metrics-visible effect: items_total unchanged={n(chr(115)+chr(101)+'lect count(*) from item where status=' + chr(39) + 'active' + chr(39))}"
      f"  classes_mature unchanged (gap_report)")
gr = {g["class_id"]: g for g in quality.gap_report(raw)}
print(f"gap_report says {CID}: state={gr[CID]['state']} missing={gr[CID]['missing']} "
      f"n_items={gr[CID]['n_items']} n_supported={gr[CID]['n_supported']}")
print()
print("RESULT:", "FILLER CLASS REPORTS MATURE" if m["state"] == "mature"
      else "class did not reach mature")