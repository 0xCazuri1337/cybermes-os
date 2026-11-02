"""Per-term blast radius: which CANDIDATE term misfiles the OTHER classes?

`w12_relevance_blast.py` proved the union of candidates frees 4 api_trust items
and misfiles 3 items elsewhere.  This narrows it to the individual term so the
edit can be minimal, and names the exact claim each term captures -- a term
whose only victim is generic prose is a term to drop, not to ship.

PERFORMANCE (measured: the naive full re-score timed out at 400s -- 10 terms x
~1800 items x a registry sweep each).  Adding a term to CLASS_VOCAB[cid] can
only change an item whose normalised text CONTAINS that term, because
`assess()` short-circuits on own_vocabulary for the filed class and any other
class only becomes relevant when it matches.  So prefiltering on the term
pattern is EXACT, not an approximation, and turns the sweep into ~10 short
lists.  `--full` re-runs the slow exhaustive way to prove the prefilter sound.

Run:  python tools/w12_term_by_term.py [--full]
"""
import os
import re
import sys

WKS = os.environ.get("WKS_ROOT", "C:/Users/Administrator/.hermes/cyber")
sys.path.insert(0, WKS)

from wks import relevance, store  # noqa: E402

CANDIDATES = [
    "audience claim", "audience validation", "token audience", "resource server",
    "service account", "service credential", "client credential", "api gateway",
    "per-application", "cross-audience",
    # proxy/edge trust vocabulary -- candidates for the 5th held item, whose
    # only current hit is host_header's 'x-forwarded-host'.
    "forwarding header", "trusted proxy", "proxy header", "edge proxy",
]


def all_items(con):
    rows = con.execute(
        """SELECT i.class_id cid, i.item_key ik, i.claim cl
           FROM item i JOIN quality q ON q.item_id=i.id
           WHERE q.validation_state IN ('under_review','high_confidence')"""
    ).fetchall()
    return [(r["cid"], r["ik"], r["cl"]) for r in rows]


def has_term(text_norm: str, term: str) -> bool:
    pat = relevance._term_pattern(term)
    return bool(pat) and bool(re.search(r"(?<![a-z0-9])" + pat + r"(?![a-z0-9])",
                                        text_norm))


def main():
    full = "--full" in sys.argv
    con = store.open_db()
    rows = all_items(con)
    norms = {ik: relevance._normalise(cl) for _, ik, cl in rows}
    base = {}
    for cid, ik, cl in rows:
        v = relevance.assess(cid, cl)
        base[ik] = v.state if v else "UNPROBEABLE"

    orig = relevance.CLASS_VOCAB["api_trust"]
    print(f"baseline items: {len(rows)}   mode: {'FULL' if full else 'prefiltered'}")
    for term in CANDIDATES:
        relevance.CLASS_VOCAB["api_trust"] = sorted(set(orig) | {term})
        subset = rows if full else [r for r in rows if has_term(norms[r[1]], term)]
        freed, harmed = [], []
        for cid, ik, cl in subset:
            v = relevance.assess(cid, cl)
            new = v.state if v else "UNPROBEABLE"
            if new == base[ik]:
                continue
            if base[ik] == "MISFILED" and new != "MISFILED":
                freed.append((cid, ik, cl))
            elif base[ik] != "MISFILED" and new == "MISFILED":
                harmed.append((cid, ik, cl))
        ok, fails = relevance.selftest(verbose=False)
        flag = "INERT" if not harmed and ok else "COLLATERAL"
        print(f"\n=== {term:24s} [{flag}] freed={len(freed)} misfiled={len(harmed)} "
              f"selftest={'PASS' if ok else 'FAIL'} scanned={len(subset)}")
        for cid, ik, cl in freed:
            print(f"    +freed  {cid:24s} {ik[:54]}\n            {cl[:100]}")
        for cid, ik, cl in harmed:
            print(f"    -HARMS  {cid:24s} {ik[:54]}\n            {cl[:130]}")
        for f in fails:
            print(f"    !selftest {f}")
    relevance.CLASS_VOCAB["api_trust"] = orig
    print("\nnothing written; CLASS_VOCAB restored")


if __name__ == "__main__":
    main()