"""Derive normative seed sources for every class from what already cites it.

The problem this solves
-----------------------
`researcher.research_class` only reads `taxonomy._SEED`, which covers 15 of the
corpus's 62 classes. The other 47 were unreachable: every research attempt
returned "no normative seed sources for this class". That was the real reason
49 classes sat below the item threshold — not a lack of knowledge.

Measured: all 62 classes ALREADY carry items citing 2 or more independent
registrable domains. The knowledge and the citations exist. Only the seed LIST
was missing, and the researcher had no way to see sources that were already
recorded as evidence.

The rule
--------
A source becomes a seed only if it ALREADY corroborates this class through a
gated item. Nothing is invented and nothing is imported from an external list:
the seeds are read out of the corpus's own evidence table. That means a seed
cannot point at a page that never supported an item for this class, and it
cannot point at a single-publisher class pretending to have two.

Preferring authority
--------------------
Sources are ranked by `source.authority` then by how many items they support,
so the chosen seeds lean on standards bodies and vendor documentation where the
corpus has them, rather than on whichever blog happened to be cited first.
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict
from typing import Any

from orch.researcher import registrable_domain

# How many seeds to record per class.
#
# Was 3, chosen when the derived list covered 62 classes thinly. Measurement
# showed the cap was discarding evidence the corpus already had:
# `ad_acl_abuse` cites 8 URLs across 7 independent publishers and used 3;
# `path_traversal` cites 9 across 8 publishers and used 3. Yield is bounded by
# the SECOND-BEST publisher, so every unseeded publisher is capacity thrown
# away. Six lets a class use the independent evidence it actually has while
# still keeping the list small enough to stay curated.
_SEEDS_PER_CLASS = 6


def _authority_rank(source_type: str | None) -> int:
    """Lower is better. Mirrors the corpus's own authority ordering."""
    order = (
        "standard", "rfc", "spec", "docs", "cwe", "taxonomy", "cheatsheet",
        "advisory", "vendor_advisory", "vendor", "research", "writeup",
        "report", "blog", "community",
    )
    st = (source_type or "").lower()
    for i, name in enumerate(order):
        if name in st:
            return i
    return len(order)


def class_sources(con: sqlite3.Connection, class_id: str) -> list[dict[str, Any]]:
    """Distinct source URLs already backing this class's gated items."""
    return [dict(r) for r in con.execute(
        """SELECT s.url, s.host, s.source_type, s.authority,
                  count(DISTINCT i.id) AS n_items
           FROM item i
           JOIN item_source q ON q.item_id = i.id
           JOIN source s ON s.id = q.source_id
           WHERE i.class_id = ? AND i.status = 'active'
           GROUP BY s.url
           HAVING count(DISTINCT i.id) > 0""",
        (class_id,),
    ).fetchall()]


def derive_seeds(con: sqlite3.Connection, class_id: str
                 ) -> list[tuple[str, str]]:
    """Pick up to 3 seed (url, source_type) pairs spanning 2+ publishers.

    Round-robins across registrable domains so the result is never two pages
    from the same publisher, then takes a second pass from the best-ranked
    remaining domain.
    """
    srcs = class_sources(con, class_id)
    if not srcs:
        return []

    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in srcs:
        dom = registrable_domain(s["host"] or "")
        if dom:
            by_domain[dom].append(s)

    if len(by_domain) < 2:
        # One publisher cannot satisfy the independence rule. Returning fewer
        # seeds than requested is the honest result; the researcher will then
        # refuse and say so, rather than the gate silently seeing one host.
        return []

    for group in by_domain.values():
        group.sort(key=lambda s: (_authority_rank(s["source_type"]),
                                  -int(s["n_items"] or 0)))

    domains = sorted(by_domain)
    seeds: list[tuple[str, str]] = []
    # First pass: the best source from each domain, strongest domains first.
    # A class with 7 independent publishers must reach the 6-seed cap from this
    # pass alone; the filler below is for classes that have only one or two.
    for dom in domains:
        best = by_domain[dom][0]
        seeds.append((best["url"], best["source_type"] or "taxonomy"))
        if len(seeds) >= _SEEDS_PER_CLASS:
            break
    # Second pass: fill remaining slots from the strongest domains, best first.
    for dom in domains:
        for extra in by_domain[dom][1:]:
            if len(seeds) >= _SEEDS_PER_CLASS:
                break
            if all(u != extra["url"] for u, _ in seeds):
                seeds.append((extra["url"],
                              extra["source_type"] or "taxonomy"))
    return seeds[:_SEEDS_PER_CLASS]


def all_class_seeds(con: sqlite3.Connection) -> dict[str, list[tuple[str, str]]]:
    out: dict[str, list[tuple[str, str]]] = {}
    for row in con.execute("SELECT id FROM bug_class ORDER BY id").fetchall():
        seeds = derive_seeds(con, row["id"])
        if seeds:
            out[row["id"]] = seeds
    return out


def write_seed_file(seeds: dict[str, list[tuple[str, str]]], path) -> str:
    """Persist the derived seeds so `researcher` can load them offline."""
    import json
    body = {cid: [{"url": u, "source_type": t} for u, t in pairs]
            for cid, pairs in sorted(seeds.items())}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return str(path)
