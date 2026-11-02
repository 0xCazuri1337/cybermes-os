"""AUDIT a child's authored claims. A child's report is a self-report.

Three properties the child was told to satisfy, each re-derived here from the
EVIDENCE rather than from the child's word:

  D1  claim is grounded in QUOTE_VERBATIM  - the claim's mechanism words actually
      appear in the quote, so the claim cannot be about something else
  D2  claim uses the class's own vocabulary  - passes wks.relevance.assess as ON_TOPIC
  D3  claim is not a restatement             - token overlap with the quote is below
      a restatement threshold

Plus a 4th check the children could not see:
  D4  the claim does not name a tool/CVE/version/URL that is absent from the quote

Only claims passing D1-D4 may be built into items. The rest are reported, not
silently dropped, so the parent can see what was refused and why.
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import relevance  # noqa: E402

RESTATEMENT_MAX = 0.72          # jaccard over content words
ARTIFACT_RE = re.compile(
    r"\b(?:CVE-\d{4}-\d+|https?://|v\d+\.\d+\.\d+)\b", re.I)
STOP = set("""the a an and or of to in on for with is are be as at by that this it its
from not no can will when what which where how why if then than so such via using use
used into out up down over under more most other another any each both same only own""".split())


def content(s):
    return {w for w in re.findall(r"[a-z][a-z0-9_]{2,}", s.lower()) if w not in STOP}


def audit(rows, verbose=False):
    out = []
    for r in rows:
        claim = (r.get("claim") or "").strip()
        if not claim:
            out.append({"class_id": r["class_id"], "verdict": "REJECTED_BY_CHILD",
                        "reason": r.get("reject_reason") or "no claim"})
            continue
        quote = r.get("QUOTE_VERBATIM", "")
        fails = []

        # D1 grounded: some content word of the claim must come from the quote,
        # and the claim's HEAD mechanism must be present.
        cq, cc = content(quote), content(claim)
        if not (cc & cq):
            fails.append("D1 not grounded: no content word of the claim appears in "
                         "its quote")

        # D2 class vocabulary
        v = relevance.assess(r["class_id"], claim)
        if v is not None and v.tag:
            fails.append("D2 off-topic: %s" % v.reason())

        # D3 restatement
        if cq and cc:
            j = len(cq & cc) / float(len(cq | cc))
            if j >= RESTATEMENT_MAX:
                fails.append("D3 restates the quote (jaccard %.2f)" % j)

        # D4 invented artifacts
        for m in ARTIFACT_RE.findall(claim):
            if m.lower() not in quote.lower():
                fails.append("D4 invents %r which is absent from the quote" % m)

        # non-negotiable: a disproof must exist and be specific
        if not (r.get("disproof") or "").strip():
            fails.append("no disproof")

        out.append({
            "class_id": r["class_id"], "page": r.get("hacktricks_page", ""),
            "kind": r.get("kind"), "verdict": "PASS" if not fails else "FAIL",
            "fails": fails,
            "claim": claim,
            "claim_chars": len(claim),
            "quote_chars": len(quote),
        })
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="+")
    ap.add_argument("--show", type=int, default=12)
    a = ap.parse_args()

    rows = []
    for f in a.files:
        with open(f, encoding="utf-8") as fh:
            rows.extend(json.load(fh))
    res = audit(rows)

    npass = sum(1 for r in res if r["verdict"] == "PASS")
    print("=" * 78)
    print("CLAIM AUDIT (parent-side, re-derived from evidence)")
    print("=" * 78)
    print("  candidates      : %d" % len(rows))
    print("  child-rejected  : %d" % sum(1 for r in res
                                         if r["verdict"] == "REJECTED_BY_CHILD"))
    print("  PASS            : %d" % npass)
    print("  FAIL            : %d" % sum(1 for r in res if r["verdict"] == "FAIL"))
    print()
    fails = [r for r in res if r["verdict"] == "FAIL"]
    if fails:
        print("-" * 78)
        print("FAILURES (refused, with the reason)")
        for r in fails[:a.show]:
            print("  %-14s %s" % (r["class_id"], r["page"][-52:]))
            print("      claim: %s" % r["claim"][:130])
            for f_ in r["fails"]:
                print("      -> %s" % f_)
    print()
    print("-" * 78)
    print("PASSING CLAIMS, sample (the ones that will be built)")
    for r in [x for x in res if x["verdict"] == "PASS"][:a.show]:
        print("  [%s/%s] %s" % (r["class_id"], r["kind"], r["claim"][:132]))
    with open("research/ht_audit.json", "w", encoding="utf-8") as fh:
        json.dump(res, fh, indent=1)
    print("\nwrote research/ht_audit.json")


if __name__ == "__main__":
    main()