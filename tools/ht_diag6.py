"""Why are 17 promoted items missing from their class page?

MEASURED DRIFT: 72 promoted HackTricks items, 55 rendered into skills/. The
generator is a projection over the db, so a promoted row that is absent from the
page is a BUG in the projection, not a gate verdict. This finds the cause per
missing item by testing every filter the generator could plausibly apply.

Candidate causes, each testable:
  A  the item's KIND is not one the page has a section for
  B  the item's claim duplicates another claim in the same class (dedupe)
  C  the claim is too short for the section threshold
  D  the section is capped at N items per class
  E  the item's disproof is empty
  F  the page renders the claim only when a linked section exists
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import domains, store  # noqa: E402

con = store.connect()

rows = list(con.execute(
    "SELECT i.id, i.class_id, i.kind, i.claim, i.body, i.disproof,"
    "       q.validation_state"
    "  FROM item i JOIN quality q ON q.item_id=i.id"
    " WHERE i.status='active' AND i.item_key GLOB '*.ht_*'"
    "   AND q.validation_state='high_confidence'"))
print("promoted HackTricks items: %d" % len(rows))

pages = {}
for cid, in con.execute("SELECT id FROM bug_class"):
    p = os.path.join(domains.class_rel(cid), "CLASS.md")
    if os.path.exists(p):
        pages[cid] = open(p, encoding="utf-8").read()

missing = []
for r in rows:
    txt = pages.get(r["class_id"], "")
    if r["claim"][:70] not in txt:
        missing.append(r)

print("missing from their page: %d" % len(missing))
print()

import collections
print("by kind      :", dict(collections.Counter(r["kind"] for r in missing)))
print("by class     :", dict(collections.Counter(r["class_id"] for r in missing)))
print()

# D: is there a per-section cap?
for cid in sorted({r["class_id"] for r in missing}):
    same = [x for x in rows if x["class_id"] == cid]
    miss_here = [x for x in missing if x["class_id"] == cid]
    print("=" * 74)
    print("%s: %d promoted, %d missing" % (cid, len(same), len(miss_here)))
    txt = pages.get(cid, "")
    for r in miss_here:
        # count items of the same KIND that DID render -> a cap would show here
        samekind = [x for x in same if x["kind"] == r["kind"]]
        rend = sum(1 for x in samekind if x["claim"][:70] in txt)
        print("   kind=%-12s rendered_of_this_kind=%d/%d  claim_chars=%d  "
              "has_disproof=%s"
              % (r["kind"], rend, len(samekind), len(r["claim"] or ""),
                 bool(r["disproof"])))
        print("      %s" % (r["claim"] or "")[:112])
        body = (r["body"] or "")
        # does the page carry the body instead of the claim?
        if body and body[:70] in txt:
            print("      -> page carries the BODY, not the claim "
                  "(generator prefers body when present)")