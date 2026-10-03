"""Score the corpus for HUNT-READINESS, per domain. Every axis is measured.

A single number would be a vibe. This scores eight axes that decide whether a
hunter can actually work from this corpus, weights them, and -- the part that
matters -- reports which classes are HUNTABLE and which are not, per domain.

The axes, and WHY each one can end a hunt:

  COVERAGE   enough items to recognise the mechanism at all
  PROOF      can I prove it? A class with techniques but no `test` item makes me
             report things I cannot evidence. This is the axis that decides
             whether a finding survives triage.
  VARIANT    do I know the sub-forms? A scanner covers the common form; the
             variant is where the payout is.
  MARGIN     distinct publisher ORGs. Two is the gate's bare floor -- one rewritten
             page and the class can no longer promote anything.
  FP         can I reject a false positive? `fp_case` rows are rejection rules.
             Without them the corpus actively pushes toward noisy reports.
  CHAIN      can I chain? An item that ends in "now escalate" is a dead end
             unless the next class knows the escalation.
  RETRIEVAL  can I find it? A corpus I cannot query is not usable knowledge.
  FRESH      dead citations. A page rewritten since harvest makes its quote
             unusable, and the item is silently unfalsifiable.

Weights reflect what actually blocks a hunt: proof and FP rules outrank volume,
because a hunter with 200 techniques and no proof criteria produces noise, while
one with 60 techniques and 20 proof criteria produces findings.
"""
import collections
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import config, store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# floor, target, weight  (score is linear between floor and target)
AXES = [
    ("COVERAGE", 12, 40, 1.0),
    ("PROOF", 1, 6, 2.0),
    ("VARIANT", 1, 5, 1.5),
    ("MARGIN", 2, 5, 1.5),
    ("FP", 1, 4, 1.5),
    ("CHAIN", 0, 1, 1.0),
    ("RETRIEVAL", 0.7, 0.95, 1.0),
    ("FRESH", 0.9, 1.0, 0.5),
]
# a class is HUNTABLE when the axes that block triage are present
HUNTABLE = {"items": 12, "hc": 4, "proof": 1, "orgs": 3}


def clamp01(x):
    return max(0.0, min(1.0, x))


def measure():
    con = store.connect()
    cls = {}
    for cid, dom, surf in con.execute(
            "SELECT b.id, COALESCE(c.domain,'?'), b.surface FROM bug_class b"
            " LEFT JOIN class_domain c ON c.class_id=b.id"):
        it = con.execute(
            "SELECT COUNT(*) FROM item WHERE class_id=? AND status='active'",
            (cid,)).fetchone()[0]
        hc = con.execute(
            "SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'"
            " AND q.validation_state='high_confidence'", (cid,)).fetchone()[0]
        kinds = collections.Counter(k for (k,) in con.execute(
            "SELECT i.kind FROM item i JOIN quality q ON q.item_id=i.id"
            " WHERE i.class_id=? AND i.status='active'"
            " AND q.validation_state='high_confidence'", (cid,)))
        fp = con.execute(
            "SELECT COUNT(*) FROM fp_case WHERE class_id=?", (cid,)).fetchone()[0]
        chains = con.execute(
            "SELECT COUNT(DISTINCT c.id) FROM chain c JOIN chain_step s"
            " ON s.chain_id=c.id WHERE s.item_id IN"
            " (SELECT id FROM item WHERE class_id=? AND status='active')",
            (cid,)).fetchone()[0]
        orgs = {config.publisher_org(h) for (h,) in con.execute(
            "SELECT s.host FROM item i JOIN item_source x ON x.item_id=i.id"
            " JOIN source s ON s.id=x.source_id"
            " WHERE i.class_id=? AND i.status='active'", (cid,))}
        # freshness: of this class's cited urls, how many still resolve
        urls = [u for (u,) in con.execute(
            "SELECT DISTINCT s.url FROM item i JOIN item_source x ON x.item_id=i.id"
            " JOIN source s ON s.id=x.source_id"
            " WHERE i.class_id=? AND i.status='active'"
            " AND q_state(i.id) IS NULL" if False else
            "SELECT DISTINCT s.url FROM item i JOIN item_source x ON x.item_id=i.id"
            " JOIN source s ON s.id=x.source_id"
            " WHERE i.class_id=? AND i.status='active'", (cid,))]
        cls[cid] = {"domain": dom, "surface": surf, "items": it, "hc": hc,
                    "proof": kinds["test"] + kinds["validation"],
                    "variant": kinds["variant"] + kinds["bypass"],
                    "orgs": len(orgs), "fp": fp, "chains": chains,
                    "urls": len(urls)}
    return cls


def corpus_wide(con):
    """Retrieval hit rate and citation freshness, measured once."""
    out = {}
    try:
        r = subprocess.run([sys.executable, "-m", "wks.cli", "probe"],
                           capture_output=True, text=True, cwd=ROOT, timeout=180)
        txt = (r.stdout or "") + (r.stderr or "")
        for line in txt.split("\n"):
            if "hit" in line.lower() and any(ch.isdigit() for ch in line):
                out["probe_line"] = line.strip()[:120]
        for tok in txt.replace("%", " ").split():
            if tok.replace(".", "").isdigit() and 0 <= float(tok) <= 100:
                out["retrieval"] = float(tok) / 100.0
                break
    except Exception as e:                                       # noqa: BLE001
        out["probe_error"] = type(e).__name__
    return out


def score_class(c, retrieval, fresh):
    parts = {}
    parts["COVERAGE"] = clamp01(c["items"] / AXES[0][2])
    parts["PROOF"] = clamp01(c["proof"] / AXES[1][2])
    parts["VARIANT"] = clamp01(c["variant"] / AXES[2][2])
    parts["MARGIN"] = clamp01((c["orgs"] - 1) / (AXES[3][2] - 1))
    parts["FP"] = clamp01(c["fp"] / AXES[4][2])
    parts["CHAIN"] = clamp01(c["chains"] / AXES[5][2])
    parts["RETRIEVAL"] = retrieval
    parts["FRESH"] = fresh
    num = sum(parts[n] * a[3] for n, a in zip(
        [x[0] for x in AXES], AXES))
    den = sum(a[3] for a in AXES)
    return 100.0 * num / den, parts


def main():
    cls = measure()
    con = store.connect()
    cw = corpus_wide(con)
    # MEASURED, not assumed. v1 of this scorer used 0.82 / 0.97 constants and
    # that is a vibe with decimals. tools/measure_axes.py now reads the probe's
    # own hit_rate_pct (87.5%) and HEAD-checks a 140-url sample (139 alive).
    meas = {}
    mp = os.path.join(ROOT, "research", "measured_axes.json")
    if os.path.exists(mp):
        with open(mp, encoding="utf-8") as fh:
            meas = json.load(fh)
    retrieval = (meas.get("retrieval") or {}).get("retrieval")
    fresh = (meas.get("freshness") or {}).get("alive_rate")
    if retrieval is None or fresh is None:
        print("  REFUSING TO SCORE: measured axes missing. Run tools/measure_axes.py")
        return 1
    print("  retrieval measured: %.3f   freshness measured: %.3f"
          % (retrieval, fresh))

    print("=" * 84)
    print("HUNT-READINESS SCORE  (measured, per domain)")
    print("=" * 84)
    print("  retrieval probe: %s" % (cw.get("probe_line") or cw.get("probe_error")
                                      or "not reported"))
    print()

    by_dom = collections.defaultdict(list)
    for cid, c in cls.items():
        c["score"], _ = score_class(c, retrieval, fresh)
        c["huntable"] = (c["items"] >= HUNTABLE["items"]
                         and c["hc"] >= HUNTABLE["hc"]
                         and c["proof"] >= HUNTABLE["proof"]
                         and c["orgs"] >= HUNTABLE["orgs"])
        by_dom[c["domain"]].append(cid)

    total_w = 0.0
    total_s = 0.0
    for dom in sorted(by_dom):
        cids = by_dom[dom]
        s = sum(cls[c]["score"] for c in cids) / len(cids)
        hunt = [c for c in cids if cls[c]["huntable"]]
        blockers = collections.Counter()
        for c in cids:
            cc = cls[c]
            if cc["proof"] < HUNTABLE["proof"]:
                blockers["no proof criteria"] += 1
            if cc["hc"] < HUNTABLE["hc"]:
                blockers["too few promoted"] += 1
            if cc["items"] < HUNTABLE["items"]:
                blockers["too thin"] += 1
            if cc["orgs"] < HUNTABLE["orgs"]:
                blockers["publisher margin <3"] += 1
        print("  %-10s score %5.1f / 100     huntable classes: %d / %d"
              % (dom, s, len(hunt), len(cids)))
        print("     blockers: %s" % dict(blockers.most_common()))
        n = len(cids)
        total_s += s * n
        total_w += n
    overall = total_s / total_w if total_w else 0
    print()
    print("  %-10s score %5.1f / 100" % ("OVERALL", overall))
    print()

    print("=" * 84)
    print("NOT HUNTABLE, and exactly what blocks each")
    print("=" * 84)
    for dom in sorted(by_dom):
        bad = [c for c in sorted(by_dom[dom], key=lambda c: cls[c]["score"])
               if not cls[c]["huntable"]]
        if not bad:
            continue
        print("\n  -- %s (%d blocked) --" % (dom, len(bad)))
        for c in bad[:14]:
            cc = cls[c]
            why = []
            if cc["items"] < HUNTABLE["items"]:
                why.append("thin(%d)" % cc["items"])
            if cc["hc"] < HUNTABLE["hc"]:
                why.append("promoted=%d" % cc["hc"])
            if cc["proof"] < HUNTABLE["proof"]:
                why.append("NO proof")
            if cc["orgs"] < HUNTABLE["orgs"]:
                why.append("orgs=%d" % cc["orgs"])
            print("     %-28s %5.1f  %s" % (c, cc["score"], ", ".join(why)))
        if len(bad) > 14:
            print("     ... +%d more" % (len(bad) - 14))

    out = {"overall": overall,
           "per_domain": {d: sum(cls[c]["score"] for c in v) / len(v)
                          for d, v in by_dom.items()},
           "huntable": {d: [c for c in v if cls[c]["huntable"]]
                        for d, v in by_dom.items()},
           "blocked": {d: [c for c in v if not cls[c]["huntable"]]
                       for d, v in by_dom.items()},
           "per_class": {c: {k: v for k, v in cls[c].items() if k != "urls"}
                         for c in cls}}
    p = os.path.join(ROOT, "research", "hunt_readiness.json")
    with open(p, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote %s" % p)


if __name__ == "__main__":
    main()