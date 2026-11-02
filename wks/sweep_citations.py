"""Db-side dead-citation sweeper.

Why this exists
---------------
MEASURED (2026-10-02): three PROMOTED `sqli` items cite

    https://owasp.org/.../07-Input_Validation_Testing/05-Testing_for_SQL_Injection.html

which now returns 404 — WSTG moved that chapter to `07-Injection/05-SQL_Injection`.
The quotes are genuine (the resolver finds them verbatim in the pinned v4.2 tag),
so this is a MOVED PAGE, not fabrication.

The gap was not the resolver: `wks.resolver --check` reported `resolved=0
unresolved=0` because it only inspects INCOMING json files. Nothing ever walked
the CANONICAL db, so a promoted item could cite a dead URL indefinitely and the
corpus would read as fully sourced while a third of those citations 404.

This module is that missing walk. It is report-only by default and rewrites only
with --apply, and it never invents a mapping: a successor is accepted only when
`resolve()` — which requires the quote to be present in the candidate — returns
one.

    python -m wks.sweep_citations            # report dead citations
    python -m wks.sweep_citations --apply    # rewrite them, preserving provenance
    python -m wks.sweep_citations --hosts owasp.org   # narrow the sweep
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wks import pipeline, resolver, store  # noqa: E402


def dead_citations(hosts: list[str] | None = None) -> list[dict]:
    """Every distinct cited URL that 404s, with the quotes attributed to it."""
    con = store.open_db(create=False)
    q = ("SELECT DISTINCT s.id, s.url, s.host FROM source s "
         "JOIN item_source i_ ON i_.source_id = s.id "
         "JOIN item i ON i.id = i_.item_id "
         "JOIN quality qq ON qq.item_id = i.id "
         "WHERE qq.validation_state IN ('high_confidence','supported')")
    p: list = []
    if hosts:
        q += " AND s.host IN (%s)" % ",".join("?" * len(hosts))
        p.extend(hosts)
    rows = con.execute(q, p).fetchall()
    out = []
    for r in rows:
        res = pipeline.fetch(r["url"], limit=200_000)
        if res.get("status") != 404:
            continue
        quotes = [x["quote"] for x in con.execute(
            """SELECT DISTINCT i_.quote FROM item_source i_
               JOIN item i ON i.id=i_.item_id
               JOIN quality qq ON qq.item_id=i.id
               WHERE i_.source_id=? AND i_.quote IS NOT NULL""",
            (r["id"],)).fetchall()]
        out.append({"source_id": r["id"], "url": r["url"], "host": r["host"],
                    "quotes": quotes})
    con.close()
    return out


def sweep(hosts: list[str] | None = None, apply: bool = False) -> dict:
    dead = dead_citations(hosts)
    resolved = unresolved = 0
    report = []
    for d in dead:
        # Try each attributed quote; a successor must hold the quote it replaces.
        found = None
        for q in d["quotes"] or [None]:
            res = resolver.resolve(d["url"], q)
            if res.get("resolved"):
                found = res["resolved"]
                break
        entry = dict(d, resolved=found)
        if found:
            resolved += 1
            print("  RESOLVED  %s\n      was: %s\n      now: %s"
                  % (d["host"], d["url"], found))
            if apply:
                con = store.open_db(create=False)
                con.execute(
                    "UPDATE source SET url=?, host=?, "
                    "notes=COALESCE(notes,'')||? WHERE id=?",
                    (found, urllib.parse.urlparse(found).netloc,
                     f" cited {d['url']} (moved; resolved by wks.sweep_citations)",
                     d["source_id"]))
                con.commit()
                con.close()
        else:
            unresolved += 1
            print("  UNRESOLVED  %s  %s" % (d["host"], d["url"][-90:]))
        report.append(entry)
    print("\ndead citations: %d  resolved: %d  unresolved: %d%s"
          % (len(dead), resolved, unresolved,
             "  (APPLIED)" if apply else "  (report-only)"))
    return {"dead": len(dead), "resolved": resolved,
            "unresolved": unresolved, "detail": report}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="wks.sweep_citations")
    ap.add_argument("--apply", action="store_true",
                    help="rewrite dead citations to their live location")
    ap.add_argument("--hosts", nargs="*", help="restrict the sweep to these hosts")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    out = sweep(args.hosts, args.apply)
    if args.json:
        print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())