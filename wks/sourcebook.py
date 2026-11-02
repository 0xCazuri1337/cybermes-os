"""SOURCE retrieval for the learning loop — one file, one API.

This is the READ side of the merged source registry (`db/sources.json`).

NAMED `sourcebook`, NOT `retrieval`. `wks/retrieval.py` already exists and is a
different concern entirely: BM25/FTS5 retrieval over ITEMS. Naming this file
`retrieval.py` would have silently replaced a working, selftest-covered module
with an unrelated one. Two kinds of retrieval, two modules:
    wks/retrieval.py   -> which KNOWLEDGE to return   (items, FTS5)
    wks/sourcebook.py  -> which SOURCES to read        (URLs, db/sources.json)

WHY THIS EXISTS. The brief generator (`tools/plan_wave.py`) knew only which
hosts were ALREADY CITED. It could not tell a child where to go. So every wave
re-derived its own source list, and a subagent that wanted to cite PortSwigger
either guessed the URL or invented it. Both are costly: an invented URL fails
`verify_quotes.py` a wave later, and a correct-but-guessed one costs a probe.

`db/sources.json` is that missing positive worklist, and this module is the only
reader of it in the codebase.

THE INVARIANT. `role == "normative"` is the ONLY thing that counts toward
`MIN_PUBLISHER_HOSTS`. `worklist()` returns leads in a SEPARATE bucket, so a
brief can hand a child practitioner material for technique with no path by which
a Medium post corroborates a Medium post into `supported`. R20. Concatenating
the buckets is the mistake this shape exists to prevent.

Publisher independence is `publisher_org`, not host: `attack.mitre.org` and
`cwe.mitre.org` are one publisher (MITRE). A brief that tells a child to "cite
two MITRE pages" sends it into a gate it can never pass.

Run:
    python -m wks.sourcebook idor            # text brief for one class
    python -m wks.sourcebook idor --json     # structured
    python -m wks.sourcebook --classes       # every class in the registry
"""
from __future__ import annotations

import json
import sqlite3
import sys
from typing import Any

from . import config, sourcegate, store

SOURCES_PATH = config.root() / "db" / "sources.json"
SCHEMA_VERSION = 2

_CACHE: dict[str, Any] | None = None


class SourceRegistryMissing(FileNotFoundError):
    """`db/sources.json` absent.

    A distinct type so a caller can say "run the builder" instead of reporting
    a corrupt corpus. A missing registry must never degrade to "no sources
    available", because that reads as a class with no evidence rather than as a
    missing build step.
    """


def load(refresh: bool = False) -> dict[str, Any]:
    """Read the merged registry, cached per process.

    The file is a build artifact, so re-reading it inside one run would only
    hide a partially-written merge.
    """
    global _CACHE
    if _CACHE is not None and not refresh:
        return _CACHE
    if not SOURCES_PATH.exists():
        raise SourceRegistryMissing(
            f"{SOURCES_PATH} not found. Run: python tools/build_sources.py")
    doc = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
    if doc.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(
            f"unsupported schema_version {doc.get('schema_version')!r}; "
            f"rebuild with: python tools/build_sources.py")
    _CACHE = doc
    return doc


def classes() -> list[str]:
    return sorted({c for e in load()["sources"] for c in e["classes"]})


def by_class(class_id: str, role: str | None = None) -> list[dict[str, Any]]:
    out = [e for e in load()["sources"] if class_id in e["classes"]]
    if role:
        out = [e for e in out if e["role"] == role]
    return out


def leads_for(class_id: str) -> list[dict[str, Any]]:
    """Practitioner/tooling leads routed to a class. Advisory, never binding."""
    return [e for e in load()["sources"]
            if e["role"] == "lead" and class_id in e["classes"]]


def excluded_hosts(con: sqlite3.Connection) -> list[str]:
    """Hosts already cited. Never reuse: the gate counts orgs, so re-citing an
    existing host adds zero corroboration while making the class look
    researched."""
    return sorted(r[0] for r in con.execute("SELECT DISTINCT host FROM source"))


def excluded_orgs(con: sqlite3.Connection) -> list[str]:
    """Publisher ORGS already cited — the unit the gate actually counts."""
    orgs = {config.publisher_org(h)
            for (h,) in con.execute("SELECT DISTINCT host FROM source")}
    return sorted(o for o in orgs if o)


def worklist(class_id: str,
             con: sqlite3.Connection | None = None) -> dict[str, Any]:
    """Everything one child needs to research a class, from the one file.

    Three deliberately SEPARATE buckets. Keeping them apart in the return value
    is what stops a caller concatenating them into one list and handing a lead
    to the gate:

      normative    gate-counting seed pages. Cite these.
      leads        technique/recon/tooling. NEVER gate-counting.
      fresh_hosts  normative-eligible publishers not yet cited, so the child can
                   ADD corroboration rather than re-citing what is already there.
      excluded_hosts  do not reuse.
    """
    doc = load()
    normative = by_class(class_id, role="normative")
    leads = leads_for(class_id)

    cited: set[str] = set()
    if con is not None:
        cited = set(excluded_hosts(con))

    # A "fresh" publisher is one not cited anywhere yet. These are the only
    # genuinely additive targets, so they are what can move a class from
    # unpromotable to promotable.
    fresh = [e for e in normative if e["host"] and e["host"] not in cited]

    hosts = {e["host"] for e in normative if e["host"]}
    orgs = {e["publisher_org"] for e in normative if e["publisher_org"]}
    MIN = doc["gate_contract"]["min_publisher_hosts"]

    # What is actually fetchable, per the store's MEASURED state -- not the
    # tier the builder declared in db/sources.json. Added 2026-10-02: the brief
    # was handing children sources already known to be walled, and six Medium
    # URLs already known to return 403.
    normative_split = sourcegate.annotate(con, normative)
    lead_split = sourcegate.annotate(con, leads)
    do_not_use = normative_split["unusable"] + lead_split["unusable"]

    return {
        "class_id": class_id,
        "normative": normative_split["usable"] or normative_split["unmeasured"],
        "leads": lead_split["usable"] or lead_split["unmeasured"],
        "normative_unmeasured": normative_split["unmeasured"],
        "leads_unmeasured": lead_split["unmeasured"],
        "do_not_use": do_not_use,
        "verification": sourcegate.verification_summary(con),
        "fresh_hosts": fresh,
        "excluded_hosts": sorted(cited),
        "seed_publisher_orgs": sorted(orgs),
        "corroboration_reachable": len(orgs) >= MIN,
        # Named, not implied. A brief handing out 2 hosts that collapse to 1 org
        # has told the child to do work that can never be promoted.
        "gate_warning": (
            f"{len(hosts)} seed host(s) collapse to {len(orgs)} publisher org(s); "
            f"MIN_PUBLISHER_HOSTS={MIN} — items citing only these are held as "
            f"INSUFFICIENT_PUBLISHER_HOSTS"
            if len(orgs) < MIN else ""),
        "counts_toward_gate": doc["gate_contract"]["counts_toward_gate"],
        "never_counts": doc["gate_contract"]["never_counts"],
    }


def brief(class_id: str, con: sqlite3.Connection | None = None) -> str:
    """Plain-text brief section for one child.

    Plain text, not JSON: this gets pasted into a delegation `context`, and a
    child parses prose faster than a nested dict.
    """
    w = worklist(class_id, con)
    L = [f"SOURCES FOR {class_id} — from db/sources.json (the only source file)"]

    # Verification status FIRST. A child that reads only the first screen must
    # learn that the sources below were MEASURED reachable, and which ones were
    # measured not to be.
    vs = w.get("verification") or {}
    if vs.get("sources"):
        L += [f"VERIFIED FETCHABLE: {vs['active']}/{vs['sources']} sources "
              f"({vs['coverage_pct']}%) measured ACTIVE by an earlier run."]
    dnu = w.get("do_not_use") or []
    if dnu:
        L += ["", "DO NOT USE — measured unreachable. Do not spend a fetch here:",
              "  (listed first: a wasted fetch costs the whole wave)"]
        for e in dnu[:20]:
            L.append(f"    {e.get('measured_state', '?'):18} {e['url'][:96]}")
    L += ["", "NORMATIVE (counts toward the gate — cite these):"]
    for e in w["normative"]:
        L.append(f"  {e['publisher_org']:<26} {e['source_type']:<11} "
                 f"[{e.get('measured_state') or 'unmeasured':<11}] {e['url']}")
    if w["gate_warning"]:
        L.append(f"  !! {w['gate_warning']}")
    L += ["", "LEADS (technique/recon/tooling — NEVER counts toward the gate):"]
    if w["leads"]:
        for e in w["leads"]:
            L.append(f"  T{e['tier']} {e['access']:<6} "
                 f"[{e.get('measured_state') or 'unmeasured':<11}] {e['url']}")
            if e["note"]:
                L.append(f"        {e['note'][:150]}")
    else:
        L.append("  (none routed to this class)")
    if w["fresh_hosts"]:
        L += ["", "UNCITED normative publishers (additive — prefer these):"]
        for e in w["fresh_hosts"]:
            L.append(f"  {e['publisher_org']:<26} {e['url']}")
    if w["excluded_hosts"]:
        tail = " ..." if len(w["excluded_hosts"]) > 12 else ""
        L += ["", f"DO NOT REUSE ({len(w['excluded_hosts'])} hosts already cited): "
                  f"{', '.join(w['excluded_hosts'][:12])}{tail}"]
    return "\n".join(L)


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(prog="sourcebook")
    ap.add_argument("class_id", nargs="?", help="print that class's brief")
    ap.add_argument("--classes", action="store_true", help="list every class")
    ap.add_argument("--json", action="store_true", help="emit JSON, not text")
    a = ap.parse_args(argv)

    if a.classes:
        print("\n".join(classes()))
        return 0
    if not a.class_id:
        ap.print_help()
        return 2

    # `store.connect()`, NOT a bare sqlite3.connect(): sourcegate.measured_state()
    # reads its row as a mapping (`row["access_state"]`), which a default
    # connection cannot do -- it returns plain tuples, so every per-class
    # worklist raised TypeError and the source retriever was unusable.
    dbp = config.root() / "db" / "wks.db"
    con = store.connect(dbp) if dbp.exists() else None
    try:
        print(json.dumps(worklist(a.class_id, con), indent=1) if a.json
              else brief(a.class_id, con))
    finally:
        if con:
            con.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
