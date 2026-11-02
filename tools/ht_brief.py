"""Render a harvest packet into a child brief: one line of evidence per item.

A child must never be handed the raw packet JSON. It gets, per candidate item:
the verbatim quote (so it can only claim what the quote says), the class's
vocabulary (so the claim uses real terminology), and the recycled partner.

Writes a flat JSON list; the parent then builds items from it and re-verifies
every quote itself, because a child's claim is a self-report and its file is
staging, not the corpus.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from wks import relevance, store  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

KINDS = ["technique", "test", "signal", "prerequisite", "variant", "impact"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--packets", required=True)
    ap.add_argument("--classes", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    with open(a.packets, encoding="utf-8") as fh:
        data = json.load(fh)
    want = {c.strip() for c in a.classes.split(",") if c.strip()}

    con = store.connect()
    rows = []
    for cid, entries in data["packets"].items():
        if cid not in want:
            continue
        for e in entries:
            for q in e["quotes"]:
                rows.append({
                    "class_id": cid,
                    "kind": "technique",
                    "hacktricks_url": e["url"],
                    "hacktricks_page": e["page"],
                    "page_title": e["title"],
                    "QUOTE_VERBATIM": q["quote"],
                    "class_terms_in_quote": q["class_terms"],
                    "class_vocabulary": sorted(relevance.CLASS_VOCAB.get(cid, [])),
                    "partner_url": e["partner"]["url"],
                    "partner_org": e["partner"]["org"],
                    "partner_quote_already_verified": e["partner"]["quote"],
                    "partner2_url": (e.get("partner2") or {}).get("url"),
                    "partner2_org": (e.get("partner2") or {}).get("org"),
                    "partner2_quote_already_verified":
                        (e.get("partner2") or {}).get("quote"),
                })
    with open(a.out, "w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=1)
    print("wrote %s: %d candidates over %d classes"
          % (a.out, len(rows), len({r["class_id"] for r in rows})))


if __name__ == "__main__":
    sys.exit(main())