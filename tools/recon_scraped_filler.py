"""How much of the corpus is one scraped sentence sprayed across classes?

Found while refiling: `dns_enum.auto.01` is a HackTheBox course-catalogue
scrape whose BODY is literally "Easy / 11 Sections / Reward: +10", replicated
13 times under 10 different class ids. Its disproof is a generic template that
quotes the claim back at itself, so it refutes nothing.

That is a different defect from the one the quarantine manifest buckets: this
is not a claim filed under the wrong class, it is non-knowledge that passed
every gate 13 times. Before choosing a disposition, measure how far it spreads
and whether the boilerplate disproof is corpus-wide.

    python tools/recon_scraped_filler.py
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from collections import Counter

WKS = os.environ.get("WKS_ROOT")
if not WKS:
    raise SystemExit("WKS_ROOT is not set")
DB = os.path.join(WKS, "db", "wks.db")

sys.path.insert(0, WKS)

# HackTheBox/ TryHackMe catalogue chrome that appears in scraped bodies.
SCRAPE = re.compile(
    r"\b\d+\s+sections?\b|\breward:\s*\+?\d+|"
    r"\b\d+\s+days?\s+(left|remaining)\b|"
    r"\bno\s+points\s+for\s+lab\b|\bcomplete\s+the\s+lab\b",
    re.I,
)

# The generic disproof template: it quotes the claim back and asserts an
# authority would refute it. It names no falsifying test for THIS mechanism.
TEMPLATE_DISPROOF = re.compile(
    r"^this is refuted if an authoritative source shows the described "
    r"behaviour does not occur", re.I)


def main() -> int:
    con = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row

    rows = con.execute(
        "SELECT id, item_key, class_id, kind, claim, body, disproof "
        "FROM item WHERE status='active'").fetchall()

    scraped = [r for r in rows if r["body"] and SCRAPE.search(r["body"])]
    templated = [r for r in rows
                 if r["disproof"] and TEMPLATE_DISPROOF.match(r["disproof"].strip())]

    # cluster identical claims
    by_claim: dict[str, list] = {}
    for r in rows:
        by_claim.setdefault((r["claim"] or "").strip().lower(), []).append(r)
    multi = {k: v for k, v in by_claim.items() if len(v) > 1}
    cross_class = {k: v for k, v in multi.items()
                   if len({x["class_id"] for x in v}) > 1}

    print(f"active items                       {len(rows)}")
    print(f"bodies carrying scrape chrome      {len(scraped)}")
    print(f"template disproof (refutes nothing){len(templated)}")
    print(f"claims appearing >1x              "
          f"{sum(len(v) for v in multi.values())} rows in {len(multi)} groups")
    print(f"  of those, spanning >1 class     "
          f"{sum(len(v) for v in cross_class.values())} rows in "
          f"{len(cross_class)} groups")
    print()

    print("worst cross-class claim clusters (rows x classes):")
    worst = sorted(cross_class.items(), key=lambda kv: -len(kv[1]))[:8]
    for claim, group in worst:
        classes = sorted({x["class_id"] for x in group})
        print(f"  {len(group):3} rows / {len(classes):2} classes : "
              f"{claim[:74]}")
        print(f"       {', '.join(classes[:8])}"
              f"{' ...' if len(classes) > 8 else ''}")
    print()

    tmpl_and_scrape = [r for r in templated
                       if r["body"] and SCRAPE.search(r["body"])]
    print(f"items that are BOTH scraped and template-disproofed: "
          f"{len(tmpl_and_scrape)}")
    per_class = Counter(r["class_id"] for r in tmpl_and_scrape)
    print("  worst classes:",
          ", ".join(f"{c}={n}" for c, n in per_class.most_common(8)))
    print()

    out = {
        "active_items": len(rows),
        "scraped_bodies": len(scraped),
        "template_disproofs": len(templated),
        "duplicate_groups": len(multi),
        "cross_class_groups": len(cross_class),
        "both_scraped_and_templated": len(tmpl_and_scrape),
        "scraped_and_templated_by_class": dict(per_class),
        "verdict": ("this is a SEPARATE defect from misfiling: non-knowledge "
                    "that passed every gate. Deduping it would leave one copy "
                    "of junk instead of thirteen, so it needs rejection, not "
                    "refiling."),
    }
    p = os.path.join(WKS, "research", "recon", "scraped_filler_report.json")
    json.dump(out, open(p, "w", encoding="utf-8"), indent=2)
    print("wrote", p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())