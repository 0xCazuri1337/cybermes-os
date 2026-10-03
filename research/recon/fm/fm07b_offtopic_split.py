"""FM-07b  the OFF-TOPIC count, split by whether the measurement is trustworthy.

The naive count ("filed class's vocabulary does not appear") conflates two
different things, and only one of them is a defect:

  MISFILED   the filed class's vocabulary is absent AND the same sentence is
             filed verbatim under a class whose vocabulary DOES match.
             A different home explains it strictly better. This is a defect.

  NO_VOCAB   the filed class has NO registered vocabulary in the relevance
             registry, so nothing can be concluded. Absence of evidence is not
             evidence of misfiling. EXCLUDED from the headline.

  UNEXPLAINED the filed class HAS vocabulary, none of it matched, and no
             sibling item explains it. Ambiguous -- could be a well-worded
             technique. Reported separately, never counted as misfiled.

READ-ONLY.
"""
import json
import os
import re
import sqlite3
import sys
from collections import defaultdict

SB = open(sys.argv[1]).read().strip()
os.environ["WKS_ROOT"] = SB
sys.path.insert(0, SB)
from wks import relevance as R  # noqa: E402

con = sqlite3.connect(f"file:{os.path.join(SB,'db','wks.db')}?mode=ro", uri=True)
con.row_factory = sqlite3.Row

vocab = {}
for r in con.execute("SELECT id,aliases,cwe FROM bug_class"):
    terms = set(R.CLASS_VOCAB.get(r["id"], []))
    try:
        for a in json.loads(r["aliases"] or "[]"):
            terms.add(str(a).lower())
    except Exception:
        pass
    if r["cwe"]:
        terms.add(str(r["cwe"]).lower())
    vocab[r["id"]] = sorted(t for t in terms if t and len(t) >= 4)

REGISTERED = {k for k in vocab if vocab.get(k)}
_WORD = re.compile(r"[a-z0-9]+")


def hits(text, terms):
    out = []
    for t in terms:
        pat = r"[^a-z0-9]".join(re.escape(w) for w in _WORD.findall(t))
        if pat and re.search(r"(?<![a-z0-9])" + pat + r"(?![a-z0-9])", text):
            out.append(t)
    return out


rows = con.execute("""SELECT i.id,i.item_key,i.class_id,i.claim,i.body,
                             q.validation_state FROM item i
                      JOIN quality q ON q.item_id=i.id
                      WHERE i.status='active'""").fetchall()


def norm(s):
    return re.sub(r"\s+", " ", (s or "").lower()).strip()


by_claim = defaultdict(list)
for r in rows:
    by_claim[norm(r["claim"])].append(r)

misfiled, unexplained, no_vocab = [], [], []
for r in rows:
    terms = vocab.get(r["class_id"], [])
    text = norm((r["claim"] or "") + " " + (r["body"] or ""))
    if hits(text, terms):
        continue
    entry = {"item_key": r["item_key"], "class_id": r["class_id"],
             "claim": (r["claim"] or "")[:120]}
    if not terms:
        no_vocab.append(entry)
        continue
    sibs = {x["class_id"] for x in by_claim[norm(r["claim"])]
            if x["class_id"] != r["class_id"]}
    better = [(c, len(hits(text, vocab.get(c, []))))
              for c in sibs if len(hits(text, vocab.get(c, []))) >= R.MISFILED_SCORE]
    if better:
        entry["better_homes"] = sorted(better, key=lambda t: -t[1])
        misfiled.append(entry)
    else:
        unexplained.append(entry)

print("=" * 74)
print(f"FM-07b  OFF-TOPIC, SPLIT BY MEASUREMENT TRUSTWORTHINESS  (of {len(rows)} promoted)")
print("=" * 74)
print()
print(f"  MISFILED    (another class explains it strictly better):  {len(misfiled):4}"
      f"   ({100*len(misfiled)/len(rows):.1f}%)   <- DEFECT")
print(f"  UNEXPLAINED (class has vocab, none matched, no better home): {len(unexplained):4}"
      f"   ({100*len(unexplained)/len(rows):.1f}%)   <- ambiguous, NOT counted")
print(f"  NO_VOCAB    (class has no registered vocabulary at all):      {len(no_vocab):4}"
      f"   ({100*len(no_vocab)/len(rows):.1f}%)   <- unmeasurable")
print()
probeable = len(rows) - len(no_vocab)
print(f"  denominator of measurable items: {probeable}")
print(f"  MISFILED as a share of MEASURABLE: "
      f"{100*len(misfiled)/probeable:.1f}%")
print()

print("--- per class, MISFILED only (class HAS vocabulary) ---")
tot = defaultdict(int)
for r in rows:
    tot[r["class_id"]] += 1
bym = defaultdict(int)
for x in misfiled:
    bym[x["class_id"]] += 1
print(f"  {'class':30} {'misfiled':>9} {'of items':>9} {'pct':>7}")
for cid, n in sorted(bym.items(), key=lambda kv: -kv[1] / tot[kv[0]]):
    print(f"  {cid:30} {n:9} {tot[cid]:9} {100*n/tot[cid]:6.1f}%")

print()
print("--- 10 misfiled examples ---")
for x in misfiled[:10]:
    bh = ", ".join(f"{c}({n})" for c, n in x["better_homes"][:3])
    print(f"  filed [{x['class_id']:20}] -> better home: {bh}")
    print(f"      {x['claim'][:104]}")

print()
print("--- MODULE FILLER in the promoted corpus ---")
_MODULE_FILLER_RE = R.MODULE_FILLER
if isinstance(_MODULE_FILLER_RE, str):
    # Newer revision: MODULE_FILLER is a STATE NAME, not the regex. Find the regex.
    import re as _re2
    _MODULE_FILLER_RE = _re2.compile(r"^\s*(we (will|are going to|discuss|cover|be covering)"
                                    r"|this (module|course|section|chapter) (covers|outlines|discusses)"
                                    r"|(identify|exploit),? and prevent"
                                    r"|in this (module|course|section)"
                                    r"|this (module|section) (discusses|covers))", _re2.I)
print("MODULE_FILLER symbol is a", type(R.MODULE_FILLER).__name__,
      "->", repr(R.MODULE_FILLER)[:70])
filler = [r for r in rows if _MODULE_FILLER_RE.match(norm(r["claim"]))]
print(f"  promoted items whose claim is a COURSE/MODULE description: {len(filler)}")
print(f"  of those, module_filler=True per relevance.assess: "
      f"{sum(1 for r in filler if (v:=R.assess(r['class_id'], r['claim'])) and v.module_filler)}")
print(f"  of those, HELD (module_filler in TERMINAL_STATES): "
      f"{sum(1 for r in filler if (v:=R.assess(r['class_id'], r['claim'])) and v.holds)}")
print(f"  TERMINAL_STATES = {R.TERMINAL_STATES}")
for r in filler[:4]:
    v = R.assess(r["class_id"], r["claim"])
    print(f"    [{r['class_id']:22}] state={v.state:12} holds={v.holds} "
          f"filler={v.module_filler}  {r['claim'][:64]!r}")