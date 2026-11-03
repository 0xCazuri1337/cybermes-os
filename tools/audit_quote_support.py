#!/usr/bin/env python
"""Audit whether an item's quoted sources even discuss the item's claim.

The gate verifies that a quote exists on the cited page and that two different
publisher orgs are present. It does not prove the quote *supports* the claim.
This tool does not pretend to solve entailment either. It finds review
candidates using three conservative signals:

1. LABEL_ONLY_QUOTE -- the span is a CWE label, not a sentence;
2. TEMPLATE_CLAIM -- the known generated CVE sentence shape;
3. NO_LEXICAL_SUPPORT -- the quote has no content-word overlap with the claim
   and neither the quote nor the source URL contains the class's vocabulary.

Signal 3 is deliberately a *review* signal, not a gate. A legitimate source can
paraphrase a claim completely; the tool reports those cases instead of silently
demoting them. Signals 1 and 2 are enforced by ``wks.quality`` because they are
specific, measured defects.

    python tools/audit_quote_support.py

Writes:
    knowledge/activity/gaps/quote-support-<YYYYMMDD>.md
    knowledge/activity/gaps/quote-support-<YYYYMMDD>.json
"""
from __future__ import annotations

import collections
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wks import quality, relevance, store  # noqa: E402

GAPS = ROOT / "learning" / "gaps"
STOP = set(
    """the and for with that this from are was were will would can could should
    not have has had but its their they them then than into over under about
    after before when where which while who whom whose what how why all any each
    other some such only also more most very may might must does did done being
    been because between through during within without across via per upon these
    those there here is are was were be been being to of in on at by or as if it
    its we our you your i""".split()
)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tokens(text: str | None) -> set[str]:
    return {
        w for w in re.findall(r"[a-z0-9]{4,}", (text or "").lower())
        if w not in STOP
    }


def _flag_source(row: sqlite3.Row) -> dict[str, Any]:
    """Return the review signals for one item_source row."""
    cid = row["class_id"]
    quote = row["quote"] or ""
    claim = row["claim"] or ""
    terms = relevance.CLASS_VOCAB.get(cid, {})
    overlap = _tokens(claim) & _tokens(quote)
    q_hits = relevance._hits(relevance._normalise(quote), terms) if terms else []
    u_hits = relevance._hits(relevance._normalise(row["url"]), terms) if terms else []
    label_only = bool(quality._LABEL_ONLY_QUOTE.match(quote.strip()))
    # If the class has no registry vocabulary, absence of a match is not a
    # signal. This keeps the report from flagging classes we cannot assess.
    no_lexical_support = bool(terms) and not overlap and not q_hits and not u_hits
    return {
        "host": row["host"],
        "url": row["url"],
        "source_type": row["source_type"],
        "quote": quote,
        "quote_overlap": sorted(overlap),
        "quote_class_hits": q_hits,
        "url_class_hits": u_hits,
        "label_only": label_only,
        "no_lexical_support": no_lexical_support,
    }


def build(con: sqlite3.Connection) -> dict[str, Any]:
    rows = con.execute(
        """SELECT i.id, i.item_key, i.class_id, i.kind, i.claim, i.status,
                  q.validation_state, s.url, s.host, s.source_type, x.quote
           FROM item i
           JOIN item_source x ON x.item_id=i.id
           JOIN source s ON s.id=x.source_id
           LEFT JOIN quality q ON q.item_id=i.id
           WHERE i.status='active' AND x.quote IS NOT NULL
             AND trim(x.quote) <> ''
           ORDER BY i.class_id, i.item_key, s.host, s.url"""
    ).fetchall()

    items: dict[int, dict[str, Any]] = {}
    for row in rows:
        rec = items.setdefault(int(row["id"]), {
            "item_key": row["item_key"],
            "class_id": row["class_id"],
            "kind": row["kind"],
            "claim": row["claim"],
            "state": row["validation_state"],
            "sources": [],
        })
        rec["sources"].append(_flag_source(row))

    label_only = []
    template = []
    no_support = []
    for rec in items.values():
        if quality._TEMPLATE_CLAIM.search(rec["claim"] or ""):
            template.append(rec)
        sources = rec["sources"]
        labels = [s for s in sources if s["label_only"]]
        if labels:
            label_only.append({**rec, "label_sources": labels})
        unsupported = [s for s in sources if s["no_lexical_support"] or s["label_only"]]
        if sources and len(unsupported) == len(sources):
            no_support.append({**rec, "unsupported_sources": unsupported})

    def slim_source(s: dict[str, Any]) -> dict[str, Any]:
        return {k: s[k] for k in
                ("host", "url", "source_type", "quote", "quote_overlap",
                 "label_only", "no_lexical_support")}

    def slim(rec: dict[str, Any]) -> dict[str, Any]:
        out = {k: rec[k] for k in
               ("item_key", "class_id", "kind", "claim", "state")}
        out["sources"] = [slim_source(s) for s in rec.get("sources", [])]
        for key in ("label_sources", "unsupported_sources"):
            if key in rec:
                out[key] = [slim_source(s) for s in rec[key]]
        return out

    by_class = collections.Counter(r["class_id"] for r in no_support)
    by_state = collections.Counter(r["state"] for r in no_support)
    label_by_state = collections.Counter(r["state"] for r in label_only)
    template_by_state = collections.Counter(r["state"] for r in template)

    return {
        "generated_at": _now(),
        "db": "db/wks.db",
        "summary": {
            "items_with_quoted_sources": len(items),
            "quoted_sources": len(rows),
            "label_only_items": len(label_only),
            "label_only_by_state": dict(label_by_state),
            "template_claim_items": len(template),
            "template_by_state": dict(template_by_state),
            "no_lexical_support_items": len(no_support),
            "no_lexical_support_by_state": dict(by_state),
            "no_lexical_support_by_class": dict(
                sorted(by_class.items(), key=lambda kv: (-kv[1], kv[0]))),
            "note": ("NO_LEXICAL_SUPPORT is a review signal, not proof: a "
                     "legitimate source may paraphrase completely. LABEL_ONLY "
                     "and TEMPLATE are enforced by wks.quality."),
        },
        "label_only": [slim(r) for r in label_only],
        "template_claims": [slim(r) for r in template],
        "no_lexical_support": [slim(r) for r in no_support],
    }


def markdown(doc: dict[str, Any]) -> str:
    s = doc["summary"]
    L = [
        "# Quote-support audit",
        "",
        f"Generated: `{doc['generated_at']}` from `{doc['db']}`.",
        "",
        "This is an audit of **whether the quoted span discusses the item's claim**. "
        "It is not a truth oracle. `LABEL_ONLY` and `TEMPLATE` are enforced by the "
        "gate; `NO_LEXICAL_SUPPORT` is a review queue because paraphrase is common.",
        "",
        "## Summary",
        "",
        f"- items with quoted sources: **{s['items_with_quoted_sources']}**",
        f"- quoted sources: **{s['quoted_sources']}**",
        f"- items with a label-only quote: **{s['label_only_items']}** "
        f"`{s['label_only_by_state']}`",
        f"- items with the generated CVE template: **{s['template_claim_items']}** "
        f"`{s['template_by_state']}`",
        f"- items with no lexical/class support in any quoted source: "
        f"**{s['no_lexical_support_items']}** `{s['no_lexical_support_by_state']}`",
        "",
        "## No lexical/class support by class",
        "",
        "| Class | Items |",
        "|---|---:|",
    ]
    for cid, n in s["no_lexical_support_by_class"].items():
        L.append(f"| `{cid}` | {n} |")

    def item_block(rec: dict[str, Any], sources: list[dict[str, Any]]) -> list[str]:
        out = [f"- `{rec['item_key']}` [{rec['state']}] — {rec['claim'][:240]}"]
        for src in sources:
            out.append(f"  - `{src['host']}` {src['url']}")
            out.append(f"    - quote: {src['quote'][:260]}")
        return out

    L += ["", "## Label-only quotes", ""]
    if doc["label_only"]:
        for rec in doc["label_only"]:
            L += item_block(rec, rec["label_sources"])
    else:
        L.append("None.")

    L += ["", "## Generated CVE template claims", ""]
    if doc["template_claims"]:
        for rec in doc["template_claims"]:
            L += item_block(rec, rec["sources"])
    else:
        L.append("None.")

    L += ["", "## No lexical/class support (review queue)", ""]
    if doc["no_lexical_support"]:
        for rec in doc["no_lexical_support"]:
            L += item_block(rec, rec["unsupported_sources"])
    else:
        L.append("None.")
    return "\n".join(L).rstrip() + "\n"


def main() -> int:
    con = store.open_db(create=False)
    doc = build(con)
    con.close()
    GAPS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    md = GAPS / f"quote-support-{stamp}.md"
    js = GAPS / f"quote-support-{stamp}.json"
    md.write_text(markdown(doc), encoding="utf-8")
    js.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    s = doc["summary"]
    print(f"items with quoted sources: {s['items_with_quoted_sources']}")
    print(f"label-only items: {s['label_only_items']}; "
          f"template items: {s['template_claim_items']}; "
          f"no-lexical-support items: {s['no_lexical_support_items']}")
    print(f"wrote {md.relative_to(ROOT)}")
    print(f"wrote {js.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
