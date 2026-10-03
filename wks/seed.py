"""Seed the taxonomy into the database.

Idempotent. Refuses to register a class whose seed set cannot ever satisfy the
corroboration gate, because a class that can never promote is a class no amount
of research will fix — it is a seed-design bug, not a research gap.
"""
from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import config, research_sources, store, taxonomy  # noqa: E402


def register_research_sources(con: sqlite3.Connection) -> dict:
    """Register `wks.research_sources` as `source` rows. Idempotent.

    This registers SOURCES ONLY. It deliberately does not:
      * create or modify any item,
      * link evidence to an item,
      * write `validation_state` (quality.py is the sole writer of that),
      * touch a class's seed set.

    The registry is a lead list, not authority. Registering a source here makes
    it *citeable*; it makes nothing true. R20: an item evidenced only by
    registry sources is practitioner/tooling-tier and must not be described as
    normatively backed.

    Notes carry the tier and access metadata so a future reader can see WHY a
    source is weak without re-fetching it: `http_status` is left NULL rather
    than asserted, because an unverified 200 is exactly the claim that made
    HackerOne look like a working source when its body was a bot-wall notice.
    """
    created = updated = 0
    for s in research_sources.RESEARCH_SOURCES:
        existed = con.execute(
            "SELECT id FROM source WHERE url=?", (s.url,)
        ).fetchone() is not None
        store.upsert_source(
            con, s.url, s.host,
            title=s.title,
            publisher=s.publisher,
            source_type=s.source_type,
            http_status=None,
            notes=(f"TIER={s.tier} ({research_sources.TIERS[s.tier]}); "
                   f"ACCESS={s.access} ({research_sources.ACCESS[s.access]}); "
                   f"REGISTRY=wks.research_sources. {s.note}"),
        )
        created += 0 if existed else 1
        updated += 1 if existed else 0
    con.commit()
    return {"registry_total": len(research_sources.RESEARCH_SOURCES),
            "created": created, "updated": updated,
            "hosts": len(research_sources.by_host()),
            "problems": research_sources.problems()}


def seed(con: sqlite3.Connection, *, verify: bool = False,
         domain: str = "all") -> dict:
    """Register classes for one domain, or both.

    `domain` accepts "web", "network" or "all" (default). The two taxonomies
    are registered through the SAME corroboration gate and the SAME store
    writer — the brief (§2) requires shared validation/evidence mechanisms, and
    a second seeding path with its own rules would be exactly the duplication
    the architecture forbids.
    """
    from wks import network_taxonomy as nettax

    if domain not in ("all", "web", "network"):
        raise ValueError(f"unknown domain {domain!r}; use web|network|all")

    created, skipped = [], []
    plan: list[tuple] = []
    if domain in ("all", "web"):
        plan += [(cid, s, "web") for cid, s in taxonomy.CLASSES.items()]
    if domain in ("all", "network"):
        plan += [(cid, s, "network") for cid, s in nettax.NET_CLASSES.items()]

    for cid, s, dom in plan:
        hset = {(urlparse(u).hostname or "").removeprefix("www.")
                for u, _ in s.sources}
        hset.discard("")
        # Count the same thing `quality.py` counts, or this check is theatre.
        # It used to count distinct HOSTS while the gate counted distinct
        # publisher ORGS after filtering builder hosts, so nine NETWORK classes
        # whose seeds are attack.mitre.org + cwe.mitre.org passed here on two
        # hostnames and could then never promote a single item — registered,
        # researched, and silently held forever. A seeder that admits a class
        # the gate will reject is worse than one that refuses it: it spends a
        # research wave to produce unpromotable output.
        #   attack.mitre.org and cwe.mitre.org are ONE publisher (MITRE).
        #   Two pages a single author uploaded are one publisher, not two.
        counted = {h for h in hset if not config.is_builder_host(h)}
        orgset = {config.publisher_org(h) for h in counted
                  if config.publisher_org(h)}
        if len(orgset) < config.MIN_PUBLISHER_HOSTS:
            skipped.append({
                "class_id": cid, "domain": dom,
                "reason": (f"{len(hset)} publisher host(s) collapse to "
                           f"{len(orgset)} publisher org(s); corroboration gate "
                           f"is unreachable"),
                "hosts": sorted(hset), "publisher_orgs": sorted(orgset),
            })
            continue
        if store.get_class(con, cid) is None:
            created.append(cid)
        store.upsert_class(
            con, cid, s.name, s.surface, cwe=s.cwe,
            owasp=getattr(s, "owasp", "") or None,
            aliases=s.aliases, summary=s.summary,
        )
        # Domain + specialization are recorded as class NOTES rather than as new
        # columns: `bug_class.surface` is a documented closed set the WEB
        # generators already read, and widening it would change every existing
        # query. The note keeps the mapping greppable and one line per class
        # instead of a schema migration with no consumer behind it.
        store.note_class(con, cid,
                         f"domain={dom} "
                         f"specialization={getattr(s, 'specialization', '') or '-'}")
        for (url, stype) in s.sources:
            store.upsert_source(
                con, url, (urlparse(url).hostname or "").removeprefix("www."),
                title=s.name, publisher=(urlparse(url).hostname or "").removeprefix("www."),
                source_type=stype,
            )
    con.commit()
    return {"registered": len(plan) - len(skipped),
            "created": created, "skipped": skipped, "domain": domain}


if __name__ == "__main__":
    con = store.open_db(create=True)
    r = seed(con, verify="--verify" in sys.argv)
    print(f"registered {r['registered']} classes ({len(r['created'])} new)")
    for s in r["skipped"]:
        print(f"  SKIP {s['class_id']}: {s['reason']}")
    con.close()
