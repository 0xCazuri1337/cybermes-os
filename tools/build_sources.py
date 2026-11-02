"""Merge every source registry into ONE retrieval file: `db/sources.json`.

WHY THIS EXISTS. The learning loop had four places to look for a source and no
single answer:

    wks/taxonomy.py          _SEED        15 WEB classes, normative
    wks/network_taxonomy.py  _NET_SEED    20 NETWORK classes, normative
    wks/taxonomy_ext.py      CATALOG      37 WEB/API classes, GET-verified
    wks/research_sources.py  RESEARCH_SOURCES   25 practitioner/tooling leads

`tools/plan_wave.py` — the generator that writes the brief the loop actually
runs on — had access to NONE of them as a positive worklist. It could tell a
child which hosts were already cited, but not which pages to go read. So each
wave re-derived its own source list in the supervisor's head, and a
subagent invented URLs that already existed in the corpus.

THE ONE RULE THIS FILE MUST NOT BREAK. Normative (taxonomy/CWE/OWASP/PortSwigger)
and practitioner (Medium/GitHub blogs) sources are merged into ONE file but stay
**role-separated**. A lead must never satisfy `MIN_PUBLISHER_HOSTS`, because two
blog posts on two hosts would then corroborate each other into `supported`. The
previous system promoted 1,378 unsourced items to `validated` for exactly that
reason. `role` is therefore load-bearing, not metadata: it is what
`wks/quality.py` and the wave brief must filter on.

Publisher independence is carried per entry as `publisher_org`, because a
publisher is an ORGANISATION, not a hostname. `www.microsoft.com` and
`learn.microsoft.com` are one publisher, and counting them as two is how a
single vendor's docs promote a claim by themselves.

GENERATED FILE. `db/sources.json` is a projection of the four registries, not a
fifth hand-maintained truth. `python tools/build_sources.py --check` re-derives
it and diffs: any drift means a registry changed without the merge being
re-run, and the loop would then be reading a stale worklist.

Run:
    python tools/build_sources.py            # write db/sources.json
    python tools/build_sources.py --check    # drift check, exit 1 on drift
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, network_taxonomy as nettax, research_sources, taxonomy  # noqa: E402
from wks import taxonomy_ext  # noqa: E402

SCHEMA_VERSION = 2
OUT = ROOT / "db" / "sources.json"

# Role vocabulary. CLOSED, and the two roles are not interchangeable:
#   normative  - defines what the class IS. Counts toward the gate.
#   lead       - practitioner/intel/tooling material. NEVER counts toward the
#                gate (R20). Useful for technique, bypass, recon, tooling.
ROLES = ("normative", "lead")


def _host(url: str) -> str:
    from urllib.parse import urlparse
    h = (urlparse(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _load_ext_verification() -> dict:
    """The measured GET report from `taxonomy_ext.py --verify`.

    Read, never re-fetched: this builder must be fast, offline and
    deterministic. Re-verification is `verify-seeds`, a separate command.
    """
    p = ROOT / "state" / "taxonomy-ext-verification.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _ext_dead_by_class(rep: dict) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for d in rep.get("dead_urls", []):
        out.setdefault(d["class"], set()).add(d["url"])
    return out


def _authority(source_type: str) -> int:
    return config.SOURCE_AUTHORITY.get(source_type, 3)


def build() -> dict:
    """Derive the merged registry. Pure function of the four registries."""
    rep = _load_ext_verification()
    dead = _ext_dead_by_class(rep)
    verified_ok = {u for u, r in _verified_map(rep).items() if r["ok"]}

    entries: dict[str, dict] = {}

    def add(url: str, source_type: str, role: str, origin: str,
            classes: tuple[str, ...] = (), title: str = "",
            publisher: str = "", tier: int | None = None,
            access: str | None = None, note: str = "",
            verified: str | None = None) -> None:
        """Insert or merge one source URL. Idempotent by URL."""
        host = _host(url)
        e = entries.get(url)
        if e is None:
            e = entries[url] = {
                "url": url,
                "host": host,
                "publisher_org": config.publisher_org(host),
                # A lead's publisher is a NAME ("Notion (user-published)"), not
                # a domain, so it cannot be collapsed by publisher_org(). It is
                # still recorded, because "one publisher" is exactly the reason
                # two Medium slugs can never corroborate each other.
                "publisher_name": publisher or host,
                "source_type": source_type,
                "authority": _authority(source_type),
                "role": role,
                "tier": tier,
                "access": access,
                "title": title,
                "note": note,
                "defined_in": [],
                "classes": [],
                "verified": verified,
            }
        # A URL claimed by both a seed and the lead registry is normative for
        # the gate. Roles never get "downgraded" — merging must not weaken a
        # gate that a seed already anchors.
        if role == "normative" and e["role"] != "normative":
            e["role"] = "normative"
            e["source_type"] = source_type
            e["authority"] = _authority(source_type)
        if e["tier"] is None and tier is not None:
            e["tier"] = tier
        if e["access"] is None and access is not None:
            e["access"] = access
        if not e["title"] and title:
            e["title"] = title
        if not e["note"] and note:
            e["note"] = note
        if e["verified"] is None and verified is not None:
            e["verified"] = verified
        if origin not in e["defined_in"]:
            e["defined_in"].append(origin)
        for c in classes:
            if c not in e["classes"]:
                e["classes"].append(c)

    # ---------------- 1. WEB normative seeds (taxonomy._SEED) --------------
    for cid, s in taxonomy.CLASSES.items():
        for url, stype in s.sources:
            add(url, stype, "normative", "taxonomy._SEED", (cid,),
                title=s.name, publisher=_host(url), access="open",
                tier=2,
                verified="seed-asserted",
                note="Web normative seed. GET-verified when the taxonomy was "
                     "built; re-check with `wks.cli verify-seeds`.")

    # ---------------- 2. NETWORK normative seeds ---------------------------
    for cid, s in nettax.NET_CLASSES.items():
        for url, stype in s.sources:
            add(url, stype, "normative", "network_taxonomy._NET_SEED", (cid,),
                title=s.name, publisher=_host(url), access="open",
                tier=2, verified="seed-asserted",
                note="NETWORK normative seed. Every URL in _NET_SEED was "
                     "GET-verified at build time.")

    # ---------------- 3. taxonomy_ext CATALOG (GET-verified) ---------------
    # Survivors are derived as candidates MINUS the report's dead list, and the
    # count is asserted against the report's own per-class `urls` field. If the
    # reconstruction disagrees with the measurement, the build FAILS rather than
    # publishing a worklist built from a URL the measurement rejected.
    ext_rows = []
    for cid, name, surface, cwe, owasp, ps, aliases, summary in taxonomy_ext.CATALOG:
        cand = taxonomy_ext.candidates(cid, cwe, ps)
        bad = dead.get(cid, set())
        kept = [(u, t) for u, t in cand if u not in bad]
        rep_entry = next((e for e in rep.get("classes", [])
                          if e["class_id"] == cid), None)
        if rep_entry is not None and rep_entry["urls"] != len(kept):
            raise SystemExit(
                f"PARITY FAIL {cid}: report says {rep_entry['urls']} live URL(s), "
                f"reconstruction yields {len(kept)}. The verification report and "
                f"candidates() disagree; refusing to publish a worklist."
            )
        for url, stype in kept:
            add(url, stype, "normative", "taxonomy_ext.CATALOG", (cid,),
                title=name, publisher=_host(url), access="open", tier=2,
                verified="GET-verified" if url in verified_ok else None,
                note=f"Extended web/API seed. CWE-{cwe}, {owasp}, surface={surface}.")
        ext_rows.append({
            "class_id": cid, "name": name, "surface": surface,
            "cwe": f"CWE-{cwe}", "owasp": owasp,
            "summary": summary,
            "urls": [u for u, _ in kept],
            "dead_urls": sorted(bad),
        })

    # ---------------- 4. lead registry (never a gate publisher) -----------
    for s in research_sources.RESEARCH_SOURCES:
        add(s.url, s.source_type, "lead", "research_sources.RESEARCH_SOURCES",
            s.classes, title=s.title, publisher=s.publisher,
            tier=s.tier, access=s.access, note=s.note,
            verified="registry-entry")

    # ---------------- 5. DISCOVERED sources (wave findings) ---------------
    # A research child that reads 40 pages and cites 5 leaves 35 verified,
    # on-topic pages with nowhere to live; the next wave re-derives them and
    # re-spends the fetch budget. `wks.source_intake` is the fifth registry:
    # it verifies each candidate live before storing it, so a wave's findings
    # become retrievable for every future wave.
    #
    # It is a REGISTRY like the other four, not a fifth truth: intake writes it,
    # this builder merges it, and `--check` proves the two agree. A lead stays
    # a lead here, so intake can never widen the gate on a wave's say-so.
    disc_path = ROOT / "db" / "discovered_sources.json"
    if disc_path.exists():
        disc = json.loads(disc_path.read_text(encoding="utf-8"))
        for e in disc.get("sources", []):
            add(e["url"], e.get("source_type", "writeup"),
                e.get("role", "lead"), "wks.source_intake",
                tuple(e.get("classes", [])),
                title=e.get("title", ""), publisher=e.get("publisher_name", ""),
                tier=e.get("tier"), access=e.get("access"),
                note=e.get("note", ""), verified=e.get("verified"))

    rows = [entries[u] for u in sorted(entries)]
    for e in rows:
        e["classes"] = sorted(e["classes"])
        e["defined_in"] = sorted(e["defined_in"])
        # Access of record: a lead carries a MEASURED access tier; a seed
        # declares "open". An explicit measurement always wins.
        if e["access"] is None:
            e["access"] = "open" if e["role"] == "normative" else "unknown"

    by_role = {r: sum(1 for e in rows if e["role"] == r) for r in ROLES}
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_by": "tools/build_sources.py",
        "note": ("GENERATED. Do not hand-edit: re-run the builder. This is the "
                 "single file the learning loop retrieves sources from. "
                 "`role` separates gate-counting normative seeds from "
                 "practitioner leads and is load-bearing, not descriptive: a "
                 "`lead` entry must never satisfy MIN_PUBLISHER_HOSTS."),
        "gate_contract": {
            "min_publisher_hosts": config.MIN_PUBLISHER_HOSTS,
            "counts_toward_gate": "role == 'normative'",
            "never_counts": "role == 'lead'",
            "independence_unit": "publisher_org, not host",
            "builder_hosts": sorted(list(config.BUILDER_HOSTS_EXACT)
                                    + list(config.BUILDER_HOST_SUFFIXES)),
        },
        "vocabularies": {
            "source_authority": config.SOURCE_AUTHORITY,
            "access": research_sources.ACCESS,
            "tiers": research_sources.TIERS,
            "roles": list(ROLES),
        },
        "totals": {
            "sources": len(rows),
            "by_role": by_role,
            "hosts": len({e["host"] for e in rows}),
            "publisher_orgs": len({e["publisher_org"] for e in rows if e["publisher_org"]}),
            "classes": len({c for e in rows for c in e["classes"]}),
        },
        "extended_web_catalog": ext_rows,
        "sources": rows,
    }
    return doc


def _verified_map(rep: dict) -> dict[str, dict]:
    """URLs the ext report measured OK, rebuilt from its per-class host/urls.

    The report stores per-class COUNTS, not the URL list, so membership is
    recovered from the class's surviving candidates. That is the same
    reconstruction the parity assert above validates.
    """
    out: dict[str, dict] = {}
    for cid, name, surface, cwe, owasp, ps, aliases, summary in taxonomy_ext.CATALOG:
        for url, _ in taxonomy_ext.candidates(cid, cwe, ps):
            out.setdefault(url, {"ok": False})
    for e in rep.get("classes", []):
        cid = e["class_id"]
        for cid2, name, surface, cwe, owasp, ps, aliases, summary in taxonomy_ext.CATALOG:
            if cid2 != cid:
                continue
            dead = {d["url"] for d in rep.get("dead_urls", []) if d["class"] == cid}
            for url, _ in taxonomy_ext.candidates(cid2, cwe, ps):
                if url not in dead:
                    out[url] = {"ok": True}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="build_sources")
    ap.add_argument("--check", action="store_true",
                    help="fail if db/sources.json has drifted from the registries")
    a = ap.parse_args(argv)

    doc = build()
    text = json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=False) + "\n"

    if a.check:
        if not OUT.exists():
            print(f"DRIFT: {OUT} does not exist. Run: python tools/build_sources.py")
            return 1
        cur = OUT.read_text(encoding="utf-8")
        if cur != text:
            print(f"DRIFT: {OUT.name} is stale relative to the registries.")
            print("A registry changed without the merge being re-run, so the "
                  "learning loop would read an out-of-date worklist.")
            print("Run: python tools/build_sources.py")
            return 1
        t = doc["totals"]
        print(f"PARITY OK — {t['sources']} sources "
              f"(normative={t['by_role']['normative']} lead={t['by_role']['lead']}) "
              f"across {t['hosts']} hosts / {t['publisher_orgs']} publisher orgs, "
              f"{t['classes']} classes")
        return 0

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    t = doc["totals"]
    print(f"wrote {OUT}")
    print(f"  sources={t['sources']} normative={t['by_role']['normative']} "
          f"lead={t['by_role']['lead']}")
    print(f"  hosts={t['hosts']} publisher_orgs={t['publisher_orgs']} "
          f"classes={t['classes']}")
    print(f"  extended_web_catalog rows={len(doc['extended_web_catalog'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
