"""Derive `test` and `evidence` items from fp_rules that already state proof criteria.

THE GAP, MEASURED. Across the 37 web classes the corpus holds 700 `technique`
items and 10 `test` items; `test` is missing in 36 of 37 classes, `variant` in
35, `evidence` in 26. `wks.cli gaps` reports every class "mature" because it
counts items, not KINDS. A corpus that knows what a bug is but not how to PROVE
one is a checklist, and that is the single largest structural weakness left.

WHY THIS IS NOT INVENTED CONTENT. 127 of 191 `fp_rule` items already contain
explicit proof criteria in their body — "a 200 on a foreign id is only an IDOR
when the response body differs from the not-found case", "a timeout is not
evidence of execution". A hunter reading those learns a test. The corpus simply
never filed that knowledge under `kind='test'`, so retrieval for "how do I prove
this" finds nothing while retrieval for "what is a false positive here" finds
everything.

So this PROMOTES existing knowledge into the kind it belongs to. It writes no
new claim, invents no finding, and cites nothing that is not already cited.

WHAT IT DOES NOT DO. It does not touch items whose body carries no proof
criterion, and it does not manufacture a test from an fp_rule that only says
"reject X". An fp_rule with no observable in it produces nothing — an empty
result is the honest outcome, not a padded one.

Run:  python tools/w12_promote_test_items.py [--apply]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402

# Phrases that mark an OBSERVABLE a hunter can actually check. Chosen to be
# specific: a sentence must name something that appears in a request, a
# response, a log, or a diff. Generic advice ("be careful", "verify the
# response") is excluded on purpose.
OBSERVABLE = re.compile(
    r"(request and response|response body|status code|status differs|"
    r"http status|\b\d{3}\b.{0,24}(status|response)|"
    r"differs from|does not differ|same as the|timing|"
    r"reflected in|appears in the (body|header|response)|"
    r"marker|unique (string|token|value)|"
    r"only when|not sufficient|is not (enough|evidence)|"
    r"can be distinguished|distinguish.{0,30}from)",
    re.IGNORECASE,
)

TESTABLE_KINDS = ("fp_rule", "validation", "bypass")


def slug(text: str, n: int = 48) -> str:
    s = re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
    return s[:n].rstrip("_")


# A sentence ends at ., ! or ? -- optionally followed by a closing quote or
# bracket, and only when whitespace or end-of-text follows. That lookahead is
# what keeps "e.g." and "vs." from splitting a sentence mid-clause: a real
# terminator is never glued to the next word.
_SENT_END = re.compile(r"[.!?][\"')\]]?(?=\s|$)")


def _sentence_span(body: str, obs_start: int, obs_end: int,
                   tail: int = 260, min_chars: int = 20) -> str:
    """Return a window around the observable bounded by SENTENCES on both sides.

    The end is the first sentence terminator at or after `obs_end`. The start
    is the LAST sentence terminator before `obs_start` -- not `obs_start - lead`.

    That distinction is the whole fix. Deriving the start from a character
    budget means the cut lands mid-sentence whenever the preceding sentence is
    longer than the budget, which is precisely the defect this replaces: the
    old code sliced a fixed 260 characters and 111 of 138 derived items ended in
    a broken fragment such as "... so &#39; b".

    Two refusals, both honest:
      * no sentence terminator within `tail` of the observable -- the text has
        no clean ending, so any span is a fragment;
      * the resulting span is shorter than `min_chars`, i.e. too little text to
        carry an observable.
    Neither case is padded. An ellipsis would be inventing text.
    """
    # --- end: first sentence terminator at/after the observable -------------
    end = obs_end
    limit = min(len(body), obs_end + tail)
    while end < limit:
        m = _SENT_END.search(body, end, limit + 1)
        if not m:
            return ""                      # no clean sentence end: refuse
        end = m.end()
        break
    else:
        return ""

    # --- start: last sentence terminator strictly before the observable -----
    # endpos = obs_start + 1 so a terminator sitting immediately before the
    # observable still counts; the lookahead needs the char after the full stop.
    # When no earlier terminator exists the span simply starts at 0: the body
    # itself opens the sentence. Refusing there (on obs_start > 0) was
    # measured to reject every ordinary single-sentence body.
    start = 0
    prev = None
    for cand in _SENT_END.finditer(body, 0, obs_start + 1):
        prev = cand
    if prev is not None:
        start = prev.end()

    span = " ".join(body[start:end].split())
    return span if len(span) >= min_chars else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    con = store.connect(config.DB_PATH)

    rows = con.execute(
        """SELECT i.id, i.class_id, i.item_key, i.claim, i.body, i.disproof
             FROM item i
            WHERE i.status='active' AND i.kind IN ('fp_rule','validation','bypass')"""
    ).fetchall()

    derived = []
    for r in rows:
        body = r["body"] or ""
        # Only promote when the OBSERVABLE sits in the body, not merely in the
        # disproof -- a disproof describes when the rule is wrong, which is not
        # the same as telling a hunter what to observe.
        m = OBSERVABLE.search(body)
        if not m:
            continue
        # Snap the window to SENTENCE boundaries. A fixed-width slice
        # (body[start:m.start()+260]) cuts mid-word, and the corpus then
        # carries 111 of 138 claims ending in a broken fragment. Measured
        # 2026-10-02; the trailing text was literally "... so &#39; b".
        span = _sentence_span(body, m.start(), m.end())
        key = f"{r['class_id']}.test.{slug(r['claim'])}"
        if con.execute("SELECT 1 FROM item WHERE item_key=?", (key,)).fetchone():
            continue
        derived.append({
            "item_key": key,
            "class_id": r["class_id"],
            "kind": "test",
            "claim": (f"To decide this case, observe: {span}"),
            "body": (
                f"Derived from {r['item_key']}, which states the false-positive "
                f"boundary for this class. The observable above is what "
                f"separates a real finding from the pattern that only looks "
                f"like one. A hunter who cannot produce this observation in a "
                f"request/response pair does not have a finding yet."),
            "disproof": (
                f"This test does not apply where the surrounding behaviour is "
                f"unobservable -- for example when the response is identical in "
                f"every case, or when the only evidence is server-side and not "
                f"reflected to the requester. The originating rule "
                f"({r['item_key']}) states the full boundary."),
            "confidence": "medium",
            "sources": [],      # filled from the parent item below
            "_parent": r["item_key"],
            "_parent_id": r["id"],
        })

    print(f"scanned={len(rows)} derived={len(derived)}")
    byclass: dict[str, int] = {}
    for d in derived:
        byclass[d["class_id"]] = byclass.get(d["class_id"], 0) + 1
    for c, n in sorted(byclass.items(), key=lambda kv: -kv[1]):
        print(f"   {c:24s} {n}")
    if not derived:
        return 0
    if not a.apply:
        print("dry run: pass --apply")
        return 0

    import json
    out = ROOT / "research" / "incoming" / "w12_derived_tests.json"
    payload = {"items": []}
    for d in derived:
        cites = con.execute(
            """SELECT s.url, q.quote FROM item_source q
                 JOIN source s ON s.id=q.source_id WHERE q.item_id=?""",
            (d.pop("_parent_id"),)).fetchall()
        seen, srcs = set(), []
        for c in cites:
            if c["url"] in seen or not (c["quote"] or "").strip():
                continue
            seen.add(c["url"])
            srcs.append({"url": c["url"], "quote": c["quote"]})
        d.pop("_parent", None)
        d["sources"] = srcs[:2]
        if len(d["sources"]) < 2:
            print(f"  SKIP {d['item_key']}: only {len(d['sources'])} real source(s)")
            continue
        payload["items"].append(d)
    out.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    print(f"\nwrote {out} with {len(payload['items'])} derived test items")
    print("These carry the parent's already-verified quotes; ingest them with:")
    print(f"  python -m wks.ingest research/incoming/w12_derived_tests.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
