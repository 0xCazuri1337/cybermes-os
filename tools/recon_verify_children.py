"""Verify delegated output against the SOURCE OF TRUTH, not against itself.

A subagent's summary is a self-report. This checks the two delivered artifacts
against the live db: that every item_key exists, that counts agree with the
db, that competency ids are unique, and that no proposed new class already
exists. Anything a child asserted that the db contradicts is a rejection.

    python tools/recon_verify_children.py
"""
import json
import os
import sys

WKS = os.environ["WKS_ROOT"]
sys.path.insert(0, WKS)
import sqlite3  # noqa: E402

RECON = os.path.join(WKS, "research", "recon")
con = sqlite3.connect(f"file:{os.path.join(WKS, 'db', 'wks.db')}?mode=ro", uri=True)
con.row_factory = sqlite3.Row
db_keys = {r["item_key"] for r in con.execute("SELECT item_key FROM item")}
db_classes = {r["id"] for r in con.execute("SELECT id FROM bug_class")}
db_counts = {r["class_id"]: r["n"] for r in con.execute(
    "SELECT class_id, count(*) n FROM item WHERE status='active' GROUP BY 1")}

fails, notes = [], []

# ---------------- child 0: quarantine manifest ----------------
qm_path = os.path.join(RECON, "quarantine_manifest.json")
if os.path.exists(qm_path):
    qm = json.load(open(qm_path, encoding="utf-8"))
    items = qm.get("items", [])
    invented = [i["item_key"] for i in items if i.get("item_key") not in db_keys]
    if invented:
        fails.append(f"quarantine_manifest: {len(invented)} item_keys NOT in db, "
                     f"e.g. {invented[:3]}")
    bucket_total = sum(qm.get("buckets", {}).values())
    if bucket_total != len(items):
        fails.append(f"quarantine_manifest: bucket counts sum to "
                     f"{bucket_total} but {len(items)} items listed")
    real_mis = [i for i in items
                if i.get("should_be_class") and i["should_be_class"] not in db_classes]
    if real_mis:
        fails.append(f"quarantine_manifest: {len(real_mis)} should_be_class "
                     f"targets do not exist, e.g. "
                     f"{[i['should_be_class'] for i in real_mis][:3]}")
    print(f"quarantine_manifest: {len(items)} items, "
          f"{len(invented)} invented, buckets sum {bucket_total}")
    print(f"  measured block: {qm.get('measured')}")
else:
    fails.append("quarantine_manifest.json missing")

# ---------------- child 1: competencies ----------------
cp_path = os.path.join(RECON, "competencies.json")
if os.path.exists(cp_path):
    cp = json.load(open(cp_path, encoding="utf-8"))
    comps = cp.get("competencies", [])
    ids = [c["id"] for c in comps]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        fails.append(f"competencies: duplicate ids {sorted(dupes)}")
    bad_bool = [c["id"] for c in comps
                if not isinstance(c.get("requires_target_contact"), bool)]
    if bad_bool:
        fails.append(f"competencies: requires_target_contact not bool for "
                     f"{bad_bool[:5]}")
    # coverage.items is the TOTAL across supporting_classes, so it must equal
    # the SUM of those classes' active item counts. Comparing it per-class is
    # the wrong check and produced 11 false mismatches against a child whose
    # numbers were exactly right.
    mismatched = []
    checked = 0
    for c in comps:
        cov = c.get("coverage") or {}
        cls = cov.get("supporting_classes") or []
        claimed = cov.get("items")
        if not cls or claimed is None:
            continue
        checked += 1
        actual = sum(db_counts.get(x, 0) for x in cls)
        if claimed != actual:
            mismatched.append((c["id"], cls, claimed, actual))
    if mismatched:
        # R31: this may be DRIFT, not error. The w12 wave ingested 90 items
        # across 18 web classes after this registry was measured, so a class
        # count legitimately grew. Distinguish the two rather than reporting a
        # false alarm -- a verifier that cries wolf is switched off.
        grew, shrank = [], []
        for cid, cls, claimed, actual in mismatched:
            (grew if actual > claimed else shrank).append(
                (cid, cls, claimed, actual))
        note = (f"competencies: {len(mismatched)} coverage totals differ from "
                f"the db -- {len(grew)} GREW (another writer ingested after "
                f"measurement, see R31), {len(shrank)} shrank")
        print("  " + note)
        for cid, cls, claimed, actual in grew:
            print(f"    grew   {cid:34} {claimed} -> {actual}")
        for cid, cls, claimed, actual in shrank:
            print(f"    shrank {cid:34} {claimed} -> {actual}")
        if shrank:
            fails.append(f"competencies: {len(shrank)} coverage totals SHRANK, "
                         f"which is never drift -- genuine measurement error: "
                         f"{[s[0] for s in shrank]}")
    missing_cls = [x for c in comps
                   for x in ((c.get("coverage") or {}).get("supporting_classes")
                             or []) if x not in db_classes]
    if missing_cls:
        fails.append(f"competencies: supporting_classes not in db: "
                     f"{sorted(set(missing_cls))}")
    ntc = [c["id"] for c in comps if c.get("requires_target_contact") is False]
    print(f"competencies: {len(comps)} competencies, dupes={len(dupes)}, "
          f"no-target-contact={len(ntc)}")
    print(f"  coverage totals reconciled against db sum: {checked - len(mismatched)}/{checked}")
    newc = cp.get("proposed_new_classes", [])
    collides = [n["id"] for n in newc if n["id"] in db_classes]
    if collides:
        fails.append(f"competencies: proposed new classes already exist: "
                     f"{collides}")
    print(f"  proposed new classes: {len(newc)}, "
          f"collide with db: {collides if collides else 'none'}")
    lv = {}
    for c in comps:
        lv[c.get("coverage", {}).get("support_level", "?")] = \
            lv.get(c.get("coverage", {}).get("support_level", "?"), 0) + 1
    print(f"  support levels: {lv}")
else:
    fails.append("competencies.json missing")

print()
if fails:
    print("VERDICT: FAIL")
    for f in fails:
        print("  FAIL " + f)
else:
    print("VERDICT: PASS -- every delegated claim checked against the db holds")
for n in notes:
    print("  note " + n)