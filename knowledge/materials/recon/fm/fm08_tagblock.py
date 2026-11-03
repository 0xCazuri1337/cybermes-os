"""FM-08  Does the newly-wired relevance gate actually BLOCK, or does it
append a tag that is not in _BLOCKING_TAGS so the item still promotes?

quality.assess() does:
    rel = relevance.assess(item["class_id"], claim)
    if rel is not None and rel.holds:
        reasons.append(rel.state)          # <-- appends the STATE NAME

and then decides on:
    tags & _REJECT_TAGS / tags & _BLOCKING_TAGS

If relevance's state names are not members of those sets, the tag is recorded
in gate_reasons and the item promotes anyway -- a gate that writes down its
verdict and does not act on it.

READ-ONLY: assesses, never writes.
"""
import os
import sys

SB = open(sys.argv[1]).read().strip()
os.environ["WKS_ROOT"] = SB
sys.path.insert(0, SB)

from wks import config, quality, relevance, store  # noqa: E402

print("=" * 74)
print("FM-08  DOES THE RELEVANCE GATE BLOCK, OR ONLY ANNOTATE?")
print("=" * 74)
print()
print("relevance state names    :", sorted({v for k, v in vars(relevance).items()
                                            if k.isupper() and isinstance(v, str)}))
print("relevance TERMINAL_STATES:", relevance.TERMINAL_STATES)
print("quality._BLOCKING_TAGS   :", sorted(quality._BLOCKING_TAGS))
print("quality._REJECT_TAGS     :", sorted(quality._REJECT_TAGS))
print()

term = set(relevance.TERMINAL_STATES)
block = quality._BLOCKING_TAGS | quality._REJECT_TAGS
print("terminal states that BLOCK:", sorted(term & block))
print("terminal states MISSING from the blocking sets:",
      sorted(term - block) or "(none)")
print()

# The two measured real defects, verbatim from the corpus.
CASES = [
    ("exposed_rmm", "Screening passwords against blocklists helps prevent users "
                    "from selecting passwords that are commonly used"),
    ("dns_enum", "An XSS vulnerability may allow an attacker to execute arbitrary "
                 "JavaScript code within the target's browser"),
    ("authn", "We will cover how to identify, exploit, and prevent each of these "
              "vulnerabilities through various methods"),
]
print("--- the tag the gate records vs the tag that blocks ---")
for cid, claim in CASES:
    v = relevance.assess(cid, claim)
    state = v.state if v else None
    holds = bool(v and v.holds)
    would_block = state in block
    print(f"  [{cid}]")
    print(f"     claim        : {claim[:78]!r}")
    print(f"     rel.state    : {state}")
    print(f"     rel.holds    : {holds}")
    print(f"     tag recorded : reasons.append({state!r})")
    print(f"     tag BLOCKS?  : {would_block}"
          f"   <-- {'BLOCKS' if would_block else 'ANNOTATES ONLY, ITEM STILL PROMOTES'}")
    print()

# End-to-end through assess() on a throwaway copy of one REAL promoted item.
import shutil
import sqlite3
import tempfile

tmp = tempfile.mkdtemp(prefix="fm08_")
shutil.copy(os.path.join(SB, "db", "wks.db"), os.path.join(tmp, "probe.db"))
con = sqlite3.connect(os.path.join(tmp, "probe.db"))
con.row_factory = sqlite3.Row

print("--- end-to-end quality.assess() on real promoted items that relevance holds ---")
rows = con.execute("""SELECT i.id,i.item_key,i.class_id,i.claim,q.validation_state
                      FROM item i JOIN quality q ON q.item_id=i.id
                      WHERE i.status='active' LIMIT 400""").fetchall()
promoted_despite_hold = 0
checked = 0
examples = []
for r in rows:
    v = relevance.assess(r["class_id"], r["claim"])
    if not (v and v.holds):
        continue
    checked += 1
    res = quality.assess(con, int(r["id"]))
    if res["state"] in ("supported", "high_confidence"):
        promoted_despite_hold += 1
        if len(examples) < 5:
            examples.append((r["item_key"], r["class_id"], v.state,
                             res["state"], res["tags"]))
print(f"  items relevance.assess() HOLDS (in the first 400): {checked}")
print(f"  ...of those, STILL reported promoted by quality.assess(): "
      f"{promoted_despite_hold}")
for k, c, st, res_state, tags in examples:
    print(f"    {k[:40]:40} rel={st:14} -> state={res_state:16} tags={tags}")
print()
print("RESULT:", "THE GATE ANNOTATES BUT DOES NOT BLOCK"
      if promoted_despite_hold else "the gate blocks as intended")