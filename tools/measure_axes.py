"""Measure the two axes that were GUESSED in the first readiness score.

`tools/hunt_score.py` scored RETRIEVAL and FRESH from constants (0.82, 0.97)
because its probe-output parser misread `n_hits: 3` as a percentage. A score
built on an assumed number is a vibe with decimals, so both are measured here:

  RETRIEVAL  wks.cli probe returns one record per (class, query) with a `pass`
             flag and n_hits. The honest measure is the fraction of probes that
             return the RIGHT class, which is what retrieval has to do for the
             corpus to be usable while hunting.

  FRESH      of the distinct urls cited by promoted items, how many still resolve
             over the network. A page rewritten since harvest makes its quote
             unfalsifiable, which is the quietest way a corpus rots.
"""
import collections
import concurrent.futures as cf
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UA = {"User-Agent": "Mozilla/5.0 (compatible; wks-research/1.0)"}


def retrieval():
    r = subprocess.run([sys.executable, "-m", "wks.cli", "probe"],
                       capture_output=True, text=True, cwd=ROOT, timeout=240)
    txt = (r.stdout or "") + (r.stderr or "")
    start = txt.find("{")
    if start < 0:
        return None, "no JSON in probe output"
    try:
        d = json.loads(txt[start:])
    except Exception as e:                                      # noqa: BLE001
        return None, "unparseable: %s" % type(e).__name__
    # the probe reports its OWN summary: probes / passed / tested /
    # no_knowledge / hit_rate_pct. Reading the vendor's metric beats parsing
    # records whose shape changes -- my first attempt misread `n_hits: 3` as a
    # percentage and would have scored retrieval against a guess.
    recs = d.get("detail") or []
    summary = {k: d.get(k) for k in
               ("probes", "passed", "tested", "no_knowledge", "hit_rate_pct")}
    if not recs:
        # walk for the records wherever they sit
        found = []

        def walk(o):
            if isinstance(o, dict):
                if "class_id" in o and "query" in o:
                    found.append(o)
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(d)
        recs = found
    if not recs:
        return None, "no probe records found"
    ok = summary.get("passed", 0)
    hits = [x.get("n_hits", 0) for x in recs]
    rate = summary.get("hit_rate_pct")
    return {"probes": summary.get("tested"), "passed": ok,
            "no_knowledge": summary.get("no_knowledge"),
            "hit_rate_pct": rate,
            "retrieval": (rate / 100.0) if isinstance(rate, (int, float)) else None,
            "records": len(recs),
            "median_hits": sorted(hits)[len(hits) // 2] if hits else 0}, None


def freshness(limit=140):
    con = store.connect()
    urls = [u for (u,) in con.execute(
        "SELECT DISTINCT s.url FROM item i"
        " JOIN quality q ON q.item_id=i.id"
        " JOIN item_source x ON x.item_id=i.id"
        " JOIN source s ON s.id=x.source_id"
        " WHERE q.validation_state='high_confidence' AND i.status='active'")]
    sample = urls if len(urls) <= limit else urls[:limit]

    def head(u):
        try:
            req = urllib.request.Request(u, headers=UA, method="GET")
            with urllib.request.urlopen(req, timeout=25) as r:
                return u, r.status
        except urllib.error.HTTPError as e:
            return u, e.code
        except Exception:                                       # noqa: BLE001
            return u, 0

    codes = []
    with cf.ThreadPoolExecutor(12) as ex:
        for u, c in ex.map(head, sample):
            codes.append(c)
    cc = collections.Counter(codes)
    live = sum(n for k, n in cc.items() if 200 <= k < 400 or k in (401, 403, 405))
    return {"sampled": len(sample), "total_urls": len(urls),
            "alive": live, "alive_rate": live / len(sample) if sample else 0,
            "codes": {str(k): v for k, v in cc.most_common()}}


if __name__ == "__main__":
    print("=" * 74)
    print("MEASURED AXES (no constants)")
    print("=" * 74)
    r, err = retrieval()
    print("  RETRIEVAL : %s" % (json.dumps(r) if r else "unavailable -- %s" % err))
    f = freshness()
    print("  FRESHNESS : %s" % json.dumps(f))
    print()
    print("  Note on 401/403/405: counted ALIVE. Those are paywalls/WAF/bot blocks,")
    print("  not dead pages -- a 404 is the only unambiguous death, and this corpus")
    print("  has already had a 403 turn out to be a healthy page on this host.")
    out = {"retrieval": r, "freshness": f}
    with open(os.path.join(ROOT, "research", "measured_axes.json"), "w",
              encoding="utf-8") as fh:
        json.dump(out, fh, indent=1)
    print("\nwrote research/measured_axes.json")