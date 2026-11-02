"""Derive `evidence` items from rules whose body states WHAT TO OBSERVE.

THE GAP. `evidence` is missing in 25 of 37 web classes (measured 2026-10-02);
the corpus holds 18 evidence items against 191 fp_rule and 148 test. A hunter can
be told what a false positive looks like and how to run the test, but not what a
convincing OBSERVATION is -- which is the thing that ends up in a report.

WHY THIS IS NOT INVENTED. 287 of 458 validation/fp_rule/test items already
state an observable in their body ("the response body differs from the not-found
case", "a 200 whose body matches the foreign-object response is not an IDOR").
That is evidence knowledge filed under a rule about rejecting candidates. This
promotes it to the kind it belongs to, carrying the parent's already-verified
quotes. It invents no claim and cites nothing uncited.

THE OBSERVABLE PATTERN IS DELIBERATELY NARROW. It must name something that
appears in a request, a response, a log or a diff. "Verify the response" is not
evidence guidance; "the response body differs from the not-found case" is.

An item with no observable produces nothing. An empty result is the honest
outcome.

Run:  python tools/w12_promote_evidence_items.py [--apply]
      then ingest research/incoming/w12_derived_evidence.json
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, store  # noqa: E402


def _shared_span_fn():
    """Load `_sentence_span` from the sibling test-item generator.

    One boundary rule, one implementation. The two generators slice the same
    parent bodies, and a second copy of this logic is how 91 evidence items
    ended up mid-word in the first place.
    """
    spec = importlib.util.spec_from_file_location(
        "w12_promote_test", ROOT / "tools" / "w12_promote_test_items.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod._sentence_span


_sentence_span = _shared_span_fn()

# Must name an artifact a hunter can point at in a report.
OBSERVABLE = re.compile(
    r"(response body|body differs|differs from the|does not differ|"
    r"status code|status differs|\bhttp status\b|"
    r"appears in the (response|body|header)|reflected in the|"
    r"in the response\b|request and response|"
    r"identical (response|body)|unique (marker|string|token)|"
    r"observable|in the (access|error) log)",
    re.IGNORECASE,
)

SOURCE_KINDS = ("validation", "fp_rule", "test", "bypass", "technique")


def sentence_around(text: str, start: int, end: int) -> str | None:
    """Return the SENTENCE containing [start,end), or None.

    A fixed-character window produces fragments: MEASURED, one derived claim
    began "versal payload twice" (mid-word) and another quoted a DERIVED item's
    own boilerplate body -- because `test`/`evidence` items this tool previously
    generated are themselves in the scan set, so promoting from them copies our
    own filler text back into the corpus.

    So: expand to sentence boundaries, reject anything that does not start on a
    word boundary, and skip items whose body is recognisably derived filler.

    The boundary search is DELEGATED to `_sentence_span` in
    `w12_promote_test_items.py` rather than reimplemented here. The local version
    only knew about "." and "\n", so any sentence ending in "!", "?" or ":"
    gave hi = -1 and the span ran to end-of-text mid-word: measured 91 of 111
    active evidence items ended mid-sentence. Two copies of a boundary rule is
    one too many; the validated one is now shared.
    """
    span = _sentence_span(text, start, end, min_chars=40)
    if not span:
        return None
    if not re.match(r"^[A-Za-z]", span):
        return None
    return span


# Filler this repo's own derivation tools emit. Promoting from it would copy
# generated boilerplate back into the corpus as if it were researched evidence.
DERIVED_FILLER = re.compile(
    r"(treat this as the (validation|test|evidence|bypass|technique) it is|"
    r"derived from \S+, which states|A hunter who cannot produce|"
    r"what separates a real finding from|"
    r"How to apply it in the field|"
    r"^\s*Mechanism:)",
    re.IGNORECASE,
)


def slug(t: str, n: int = 44) -> str:
    return re.sub(r"[^a-z0-9]+", "_", t.lower()).strip("_")[:n].rstrip("_")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()
    con = store.connect(config.DB_PATH)

    rows = con.execute(
        f"""SELECT i.id, i.class_id, i.item_key, i.claim, i.body, i.disproof
              FROM item i
             WHERE i.status='active' AND i.kind IN {SOURCE_KINDS}"""
    ).fetchall()

    derived, skipped_filler, skipped_frag = [], 0, 0
    for r in rows:
        body = r["body"] or ""
        if DERIVED_FILLER.search(body):
            skipped_filler += 1
            continue
        m = OBSERVABLE.search(body)
        if not m:
            continue
        span = sentence_around(body, m.start(), m.end())
        if not span:
            skipped_frag += 1
            continue
        key = f"{r['class_id']}.evidence.{slug(r['claim'])}"
        if con.execute("SELECT 1 FROM item WHERE item_key=?", (key,)).fetchone():
            continue
        derived.append({
            "item_key": key, "class_id": r["class_id"], "kind": "evidence",
            "claim": f"A convincing observation for this class is: {span}",
            "body": (
                f"Derived from {r['item_key']}, which states the boundary for this "
                f"class. The observation above is what a report must contain to be "
                f"believed: an artifact the reviewer can re-check, not a claim the "
                f"hunter asserts. A finding without it is an assertion."),
            "disproof": (
                f"Not evidence when the observable cannot be produced at all -- "
                f"blind, server-side-only, or identical-in-every-case behaviour "
                f"leaves nothing to show. The originating rule "
                f"({r['item_key']}) states the full boundary."),
            "confidence": "medium", "sources": [], "_pid": r["id"],
        })

    print(f"scanned={len(rows)} derived={len(derived)} "
          f"skipped_filler={skipped_filler} skipped_fragment={skipped_frag}")
    if not derived:
        return 0
    if not a.apply:
        print("dry run: pass --apply")
        return 0

    payload = {"items": []}
    for d in derived:
        cites = con.execute(
            """SELECT s.url, q.quote FROM item_source q
                 JOIN source s ON s.id=q.source_id WHERE q.item_id=?""",
            (d.pop("_pid"),)).fetchall()
        seen, srcs = set(), []
        for c in cites:
            if c["url"] in seen or not (c["quote"] or "").strip():
                continue
            seen.add(c["url"])
            srcs.append({"url": c["url"], "quote": c["quote"]})
        d["sources"] = srcs[:2]
        if len(d["sources"]) < 2:
            continue
        payload["items"].append(d)

    out = ROOT / "research" / "incoming" / "w12_derived_evidence.json"
    out.write_text(json.dumps(payload, indent=1, ensure_ascii=False) + "\n",
                   encoding="utf-8")
    print(f"wrote {out} with {len(payload['items'])} derived evidence items")
    print("  python -m wks.ingest research/incoming/w12_derived_evidence.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
