"""Build the next research wave from MEASURED state, not from a hand-written brief.

WHY THIS IS A GENERATOR. The standing lesson from the last cycle: a
hand-written brief is wrong by construction when vocabulary varies, because it
freezes a snapshot of class ids, host lists and item counts that go stale the
moment anything changes — and a stale brief silently sends six researchers at
work that is already done, or at classes that no longer exist.

So the brief IS this script's output. It reads the live db and emits the exact
work list, the exact exclusion list, and the exact per-child JSON schema. One
command, re-run each cycle.

WHAT IT PRIORISES, in this order, and why:

  1. classes with items but ZERO fp_case rows   <- scarcest kind
  2. classes with items but ZERO chain_step rows <- second scarcest
  3. classes with items=0                       <- bulk

`quality.maturity()` requires >=2 fp rules and >=1 chain for a class to be
mature, so fp_case and chain_step are not decoration: they are two of the six
gates. Adding a 50th item to a class that already has 40 moves nothing toward
mature; adding its first fp_rule does.

WHY NEW HOSTS ARE MANDATORY. Every already-cited host is excluded by name. The
`MIN_PUBLISHER_HOSTS` gate counts DISTINCT HOSTS, so re-citing owasp.org for a
NETWORK class adds zero gate value on its own — and worse, it makes the class
look researched while its corroboration still rests on the same two hosts.

THE POSITIVE LIST CAME FROM NOWHERE UNTIL `db/sources.json`. This script used to
emit only an exclusion list, so every wave re-derived its own idea of where to
read and a child that wanted PortSwigger had to guess the URL or invent it. An
invented URL fails `verify_quotes.py` a wave later; a guessed one costs a probe.
Sources now come from `wks/sourcebook.py`, which reads the single merged
registry, and they are emitted PER CLASS so a child is handed pages for its own
class rather than the whole corpus.

Read-only against the canonical db. Writes exactly one file.
"""
from __future__ import annotations

import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

if str(Path(__file__).resolve().parent.parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wks import config, sourcebook

# Hosts already cited. Auto-derived, never hand-listed: a hand-maintained
# exclusion list is exactly the thing that goes stale.
def cited_hosts(con: sqlite3.Connection) -> list[str]:
    return sorted(r[0] for r in con.execute("SELECT DISTINCT host FROM source"))


def builder_hosts_in_citations(con: sqlite3.Connection) -> list[str]:
    return [h for h in cited_hosts(con) if config.is_builder_host(h)]


def measure(con: sqlite3.Connection) -> dict:
    rows = []
    for c in con.execute(
        """SELECT c.id,
                  (SELECT COUNT(*) FROM item i WHERE i.class_id=c.id
                     AND i.status='active')                          AS items,
                  (SELECT COUNT(*) FROM item i JOIN quality q ON q.item_id=i.id
                     WHERE i.class_id=c.id AND i.status='active'
                       AND q.validation_state IN
                           ('supported','high_confidence'))          AS sup,
                  (SELECT COUNT(*) FROM fp_case f WHERE f.class_id=c.id) AS fp,
                  (SELECT COUNT(*) FROM chain_step s WHERE s.class_id=c.id) AS chn
             FROM bug_class c"""
    ):
        r = dict(c)
        r["id"] = r["id"]
        rows.append(r)

    for r in rows:
        missing = []
        if r["items"] == 0:
            missing.append("items")
        if r["sup"] < 2:
            missing.append("supported_items")
        if r["fp"] < config.MATURITY_MIN_FP_RULES:
            missing.append("fp_rules")
        if r["chn"] < config.MATURITY_MIN_CHAINS:
            missing.append("chains")
        r["missing"] = missing

    def priority(r):
        # Lower number = do sooner.
        if r["items"] > 0 and r["fp"] == 0:
            return 0
        if r["items"] > 0 and r["chn"] == 0:
            return 1
        if r["items"] == 0:
            return 2
        return 3

    for r in rows:
        r["priority"] = priority(r)
    rows.sort(key=lambda r: (r["priority"], -r["items"], r["id"]))
    return rows


def bucket(rows, p):
    return [r["id"] for r in rows if r["priority"] == p]


def main() -> int:
    con = sqlite3.connect("db/wks.db")
    con.row_factory = sqlite3.Row
    rows = measure(con)

    p0 = bucket(rows, 0)   # items, zero fp
    p1 = bucket(rows, 1)   # items, zero chain
    p2 = bucket(rows, 2)   # items == 0
    p3 = bucket(rows, 3)

    hosts = cited_hosts(con)
    builders = builder_hosts_in_citations(con)

    # The positive worklist, per class, from the ONE merged source file. This
    # is what turns the brief from "here is what you must not cite" into "here
    # is what to read". Roles stay separated per class so a child cannot
    # corroborate with a practitioner lead by accident.
    known = set(sourcebook.classes())
    class_sources: dict[str, Any] = {}
    unreachable: list[str] = []
    for cid in sorted(known):
        w = sourcebook.worklist(cid, con)
        class_sources[cid] = {
            "normative": [
                {"url": e["url"], "publisher_org": e["publisher_org"],
                 "source_type": e["source_type"], "authority": e["authority"],
                 "already_cited": e["host"] in set(hosts)}
                for e in w["normative"]
            ],
            "leads": [
                {"url": e["url"], "tier": e["tier"], "access": e["access"],
                 "note": e["note"]}
                for e in w["leads"]
            ],
            "uncited_publishers": sorted({
                e["publisher_org"] for e in w["fresh_hosts"]
                if e["publisher_org"]}),
            "corroboration_reachable": w["corroboration_reachable"],
            "gate_warning": w["gate_warning"],
        }
        if not w["corroboration_reachable"]:
            unreachable.append(cid)

    out = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": ("Generated by tools/plan_wave.py from live db state. Do not "
                 "hand-edit: re-run the generator. A hand-written brief goes "
                 "stale silently and sends researchers at finished work."),
        "totals": {
            "classes": len(rows),
            "items_active": sum(r["items"] for r in rows),
            "fp_cases": sum(r["fp"] for r in rows),
            "chain_steps": sum(r["chn"] for r in rows),
        },
        "priority_bands": {
            "P0_items_but_zero_fp_rules": p0,
            "P1_items_but_zero_chains": p1,
            "P2_no_items": p2,
            "P3_near_complete": p3,
        },
        "class_state": rows,
        "exclusion": {
            "already_cited_hosts": hosts,
            "count": len(hosts),
            "builder_hosts_never_count_as_publishers": (
                list(config.BUILDER_HOSTS_EXACT) +
                list(config.BUILDER_HOST_SUFFIXES)),
            "builder_hosts_present_in_citations": builders,
        },
        "item_schema": {
            "item_key": "<class_id>.<short_slug>",
            "class_id": "<must be one of the classes assigned to this child>",
            "kind": "prerequisite|signal|technique|test|validation|fp_rule|"
                    "evidence|impact|variant|bypass|chain_link",
            "claim": "ONE falsifiable assertion, >=40 chars. Not 'this may be vulnerable'.",
            "body": "elaboration; how to actually test it",
            "disproof": "the observation that would REFUTE this claim. Required.",
            "severity_hint": "critical|high|medium|low|info",
            "hunting_value": "1..5",
            "source_refs": [
                {"url": "https://...", "source_type": "<one of the closed "
                 "vocabulary in wks.config.SOURCE_AUTHORITY>",
                 "quote": "VERBATIM sentence copied from the page, <200 chars, "
                          "re-verified by fetching the page yourself"}
            ],
        },
        "sources": {
            "registry_file": "db/sources.json",
            "registry_reader": "python -m wks.sourcebook <class_id>",
            "note": ("Read this section BEFORE choosing any URL. Do not invent a "
                     "URL and do not reuse an excluded host. `normative` counts "
                     "toward MIN_PUBLISHER_HOSTS; `leads` NEVER does. Publisher "
                     "independence is publisher_org, not host: attack.mitre.org "
                     "and cwe.mitre.org are ONE publisher (MITRE)."),
            "counts_toward_gate": "role == 'normative'",
            "never_counts_toward_gate": "role == 'lead'",
            "independence_unit": "publisher_org",
            "by_class": class_sources,
            "classes_with_unreachable_corroboration": unreachable,
        },
        "closed_source_type_vocabulary": sorted(config.SOURCE_AUTHORITY),
        "min_publisher_hosts": config.MIN_PUBLISHER_HOSTS,
    }

    path = "runtime/state/wave-plan.json"
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)

    t = out["totals"]
    print(f"MEASURED  classes={t['classes']} items={t['items_active']} "
          f"fp={t['fp_cases']} chain_steps={t['chain_steps']}")
    print()
    print(f"P0 items but ZERO fp_rules ({len(p0)}): {p0}")
    print(f"P1 items but ZERO chains     ({len(p1)}): {p1}")
    print(f"P2 no items                  ({len(p2)}): {p2}")
    print(f"P3 near complete             ({len(p3)}): {p3}")
    print()
    print(f"EXCLUSION — {len(hosts)} already-cited hosts (do not reuse):")
    for h in hosts:
        print(f"   {h}")
    print()
    if builders:
        print(f"builder hosts currently in citations (cite-only, never counted): "
              f"{builders}")
    if unreachable:
        print()
        print(f"!! {len(unreachable)} class(es) whose seeds CANNOT satisfy the gate "
              f"(hosts collapse to <{config.MIN_PUBLISHER_HOSTS} publisher orgs). "
              f"Do not assign these until seeded from an independent publisher:")
        for cid in unreachable:
            print(f"   {cid}")
    print(f"\nsources: per-class worklist for {len(class_sources)} class(es) from "
          f"db/sources.json")
    print(f"written: {path}")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())