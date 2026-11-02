"""Independent parity check: does `db/sources.json` lose or invent a URL?

WHY THIS IS NOT JUST `--check`. `build_sources.py --check` re-runs the same
derivation and diffs the file against it — it proves the FILE matches the
BUILDER. It cannot prove the builder itself is faithful, because a bug that
drops a source is invisible to a diff against itself. This file reads each of
the four registries DIRECTLY, bypassing the builder, and asserts set equality in
both directions:

    registry  - merged   == empty      (nothing dropped)
    merged    - registry == only roles the registry genuinely claims
                                              (nothing invented)

The anti-fabrication rule applies to our own tooling: a merge that silently
loses the CWE page for a class is a corpus that reports `items=0` forever for a
reason that has nothing to do with research.

Run:  python tools/check_sources_parity.py
Exit: 0 = parity, 1 = a defect (every failure is named).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import network_taxonomy as nettax, research_sources, taxonomy  # noqa: E402
from wks import taxonomy_ext  # noqa: E402

SOURCES = ROOT / "db" / "sources.json"


def measured_dead() -> set[str]:
    """URLs the GET verification measured as unusable.

    These are a legitimate exclusion, not a dropped source: `taxonomy_ext.py`
    probes every candidate and drops the ones that 404 or return a stub, then
    substitutes an OWASP cheat sheet so the class keeps two independent
    publishers. Treating a measured 404 as "lost" would require the builder to
    re-publish dead URLs, which is the exact defect the verification pass
    exists to prevent.
    """
    p = ROOT / "state" / "taxonomy-ext-verification.json"
    if not p.exists():
        return set()
    rep = json.loads(p.read_text(encoding="utf-8"))
    return {d["url"] for d in rep.get("dead_urls", [])}


def registry_urls() -> tuple[dict[str, set[str]], set[str]]:
    """Every URL each registry claims, read straight from the modules.

    Returns `(per_registry, dead)`. `dead` is excluded from the
    nothing-dropped assertion and reported separately, so a URL that dies is
    accounted for once as EXCLUDED rather than as a silent loss.
    """
    out: dict[str, set[str]] = {
        "taxonomy._SEED": set(),
        "network_taxonomy._NET_SEED": set(),
        "taxonomy_ext.CATALOG": set(),
        "research_sources.RESEARCH_SOURCES": set(),
        "wks.source_intake": set(),
    }
    for s in taxonomy.CLASSES.values():
        out["taxonomy._SEED"].update(u for u, _ in s.sources)
    for s in nettax.NET_CLASSES.values():
        out["network_taxonomy._NET_SEED"].update(u for u, _ in s.sources)
    for row in taxonomy_ext.CATALOG:
        cid, cwe, ps = row[0], row[3], row[5]
        out["taxonomy_ext.CATALOG"].update(
            u for u, _ in taxonomy_ext.candidates(cid, cwe, ps))
    out["research_sources.RESEARCH_SOURCES"].update(
        s.url for s in research_sources.RESEARCH_SOURCES)
    # The FIFTH registry: sources a research wave discovered and intake
    # verified. Omitting it here made this checker report every discovered
    # source as INVENT -- the checker's own blindness, not a merge defect,
    # which is the same "a checker must be validated in both directions"
    # lesson as the negative controls.
    disc = ROOT / "db" / "discovered_sources.json"
    if disc.exists():
        out["wks.source_intake"].update(
            e["url"] for e in json.loads(
                disc.read_text(encoding="utf-8")).get("sources", []))
    return out, measured_dead()


def main() -> int:
    if not SOURCES.exists():
        print(f"FAIL: {SOURCES} missing. Run: python tools/build_sources.py")
        return 1
    doc = json.loads(SOURCES.read_text(encoding="utf-8"))
    merged = {e["url"]: e for e in doc["sources"]}
    reg, dead = registry_urls()

    failures: list[str] = []
    # Pre-existing seed-design defects, reported but NOT counted as merge
    # failures: these classes are already registered in the db and this merge
    # neither caused nor can fix them. They surface here because the merge is
    # the first place the org-vs-host disagreement is visible in one place.
    advisories: list[str] = []

    # ---- 1. nothing dropped, except what measurement killed ---------------
    union = set().union(*reg.values())
    excluded = sorted((union - set(merged)) & dead)
    lost = sorted((union - set(merged)) - dead)
    for u in lost:
        owners = [k for k, v in reg.items() if u in v]
        failures.append(f"LOST    {u}  (claimed by {', '.join(owners)}, "
                        f"NOT in the measured-dead list)")

    # ---- 2. role separation held -------------------------------------------
    # A URL that is ONLY a lead in the lead registry and nowhere a seed must
    # not be tagged normative: that would let a blog post satisfy the gate.
    lead_only = (reg["research_sources.RESEARCH_SOURCES"]
                 | reg["wks.source_intake"]) - (
        reg["taxonomy._SEED"]
        | reg["network_taxonomy._NET_SEED"]
        | reg["taxonomy_ext.CATALOG"])
    for u in sorted(lead_only):
        e = merged.get(u)
        if e is None:
            continue
        if e["role"] != "lead":
            failures.append(
                f"ROLE    {u} is a lead-only URL but merged role={e['role']!r} — "
                f"it would count toward MIN_PUBLISHER_HOSTS")

    # ---- 3. every seed URL is normative ------------------------------------
    seed_urls = (reg["taxonomy._SEED"] | reg["network_taxonomy._NET_SEED"]
                 | reg["taxonomy_ext.CATALOG"])
    for u in sorted(seed_urls):
        e = merged.get(u)
        if e is not None and e["role"] != "normative":
            failures.append(
                f"ROLE    {u} is a class seed but merged role={e['role']!r}")

    # ---- 4. no invented URLs ------------------------------------------------
    for u in sorted(set(merged) - union):
        failures.append(f"INVENT  {u}  (in merged file, in NO registry)")

    # ---- 5. closed vocabulary ----------------------------------------------
    for u, e in sorted(merged.items()):
        if e["source_type"] not in doc["vocabularies"]["source_authority"]:
            failures.append(
                f"TYPE    {u}: source_type {e['source_type']!r} not in "
                f"SOURCE_AUTHORITY — would silently score authority 3")
        if e["role"] not in doc["vocabularies"]["roles"]:
            failures.append(f"ROLE    {u}: role {e['role']!r} outside closed vocabulary")
        if e["access"] not in doc["vocabularies"]["access"]:
            failures.append(f"ACCESS  {u}: access {e['access']!r} not a known tier")

    # ---- 6. the two-publisher rule is satisfiable per class -----------------
    # ADVISORY, not a merge failure. `seed.py` gates on distinct HOSTS while
    # `quality.py` gates on distinct publisher ORGS, so a class whose seeds are
    # attack.mitre.org + cwe.mitre.org is registered by the seeder and can then
    # never promote anything. That contradiction predates this merge; it is
    # reported here because this is the first file that shows both sides at once.
    MIN = doc["gate_contract"]["min_publisher_hosts"]
    thin = []
    for cid in sorted({c for e in merged.values() for c in e["classes"]}):
        ents = [e for e in merged.values()
                if e["role"] == "normative" and cid in e["classes"]]
        orgs = {e["publisher_org"] for e in ents if e["publisher_org"]}
        hosts = {e["host"] for e in ents if e["host"]}
        if len(orgs) < MIN:
            thin.append((cid, sorted(hosts), sorted(orgs)))
    for cid, hosts, orgs in thin:
        advisories.append(
            f"GATE    {cid}: {len(hosts)} seed host(s) {hosts} collapse to "
            f"{len(orgs)} publisher org(s) {orgs}; seed.py admits it on hosts, "
            f"quality.py would hold every item as INSUFFICIENT_PUBLISHER_HOSTS")

    # ---- 7. publisher_org is present, since it IS the independence unit ----
    for u, e in sorted(merged.items()):
        if not e.get("publisher_org"):
            failures.append(f"ORG     {u}: empty publisher_org")

    reg_total = sum(len(v) for v in reg.values())
    print(f"registry url-slots={reg_total} distinct={len(union)} "
          f"merged={len(merged)}")
    for k, v in sorted(reg.items()):
        print(f"  {k:36} {len(v):>4}")
    print(f"  merged by role: " + ", ".join(
        f"{r}={sum(1 for e in merged.values() if e['role'] == r)}"
        for r in doc["vocabularies"]["roles"]))
    if excluded:
        print(f"\n{len(excluded)} URL(s) excluded by MEASURED 404 (correct, not a loss):")
        for u in excluded:
            print(f"  EXCLUDED {u}")

    if advisories:
        print(f"\nADVISORY — {len(advisories)} pre-existing seed-design defect(s) "
              f"(NOT caused by this merge; reported because this file shows "
              f"hosts and orgs together):")
        for a in advisories:
            print(f"  {a}")
        print("  FIX: seed.py must gate on config.publisher_org(), not on host, "
              "or these classes stay registered-but-unpromotable forever.")

    if failures:
        print(f"\nPARITY FAIL — {len(failures)} defect(s):")
        for f in failures:
            print(f"  {f}")
        return 1
    print("\nPARITY OK — no URL lost, none invented, role separation held, "
          "vocabulary closed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
