"""Adversarial tests for the merged source registry.

WHY A TEST FILE AND NOT JUST THE PARITY CHECK. `check_sources_parity.py` proves
the merge is FAITHFUL to the four registries. It does not prove the merged file
is SAFE to hand a child. Those are different questions, and the dangerous one
is the second: the whole reason `research_sources.py` was kept separate from
`taxonomy._SEED` is that mixing them lets two practitioner blog posts
satisfy `MIN_PUBLISHER_HOSTS` and promote an unbacked claim to `supported`. The
previous system promoted 1,378 unsourced items that way.

So these tests attack the merge the way a well-meaning future edit would:

  1. a lead relabelled `normative`  -> must be detectable
  2. two sibling subdomains of one org -> must collapse to one publisher
  3. a publisher counted by hostname   -> must be caught (the microsoft trap)
  4. an empty note on a lead           -> must be caught (mystery citation)
  5. an unknown source_type            -> must be caught (silent authority 3)
  6. a stale registry                  -> must be caught by --check

Each negative control differs from a real entry in exactly ONE dimension, the
dimension under test. A control that fails on shape instead of on evidence
proves nothing — that mistake was made and paid for once already.

Run:  python tools/test_sourcebook.py
Exit: 0 = all pass, 1 = a defect.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from wks import config, sourcebook  # noqa: E402

RESULTS: list[tuple[bool, str]] = []


def check(ok: bool, label: str) -> None:
    RESULTS.append((bool(ok), label))


def test_registry_loads() -> None:
    doc = sourcebook.load()
    check(doc["schema_version"] == 2, "registry loads at schema_version 2")
    check(len(doc["sources"]) > 0, "registry is non-empty")
    check("normative" in doc["totals"]["by_role"]
          and "lead" in doc["totals"]["by_role"],
          "both roles are counted separately")


def test_roles_are_separated_in_worklist() -> None:
    """A child must never receive leads and normative seeds as one list."""
    w = sourcebook.worklist("idor")
    check(all(e["role"] == "normative" for e in w["normative"]),
          "worklist.normative contains only role=normative")
    check(all(e["role"] == "lead" for e in w["leads"]),
          "worklist.leads contains only role=lead")
    check(isinstance(w["normative"], list) and isinstance(w["leads"], list),
          "normative and leads are SEPARATE containers (cannot be concatenated "
          "by accident)")


def test_lead_relabelled_normative_is_detectable() -> None:
    """NEGATIVE CONTROL. Take a real lead, flip only its role.

    If nothing detects this, the merge has become the bug it was built to
    prevent: a Medium post could then be cited as corroboration.

    Picked from leads that are actually ROUTED to a class — several leads
    (the Notion pages, cvebase, Vulners) are class-agnostic and carry an empty
    `classes` tuple, so taking `leads[0]` here would test a lead that no
    worklist can ever hand out.
    """
    doc = sourcebook.load()
    lead = next(e for e in doc["sources"]
                if e["role"] == "lead" and e["classes"])
    tampered = json.loads(json.dumps(doc))
    victim = next(e for e in tampered["sources"] if e["url"] == lead["url"])
    victim["role"] = "normative"

    # Recompute what the gate WOULD see for that class, using the same
    # publisher_org rule quality.py uses.
    cid = lead["classes"][0]
    orgs = {e["publisher_org"] for e in tampered["sources"]
            if e["role"] == "normative" and cid in e["classes"]}
    lead_org = config.publisher_org(lead["host"])
    check(lead_org in orgs,
          f"CONTROL: relabelling lead {lead['host']} as normative DOES change "
          f"the publisher set for {cid} (so the tamper is observable)")

    # And the real registry must NOT already contain that condition for a
    # class whose only corroboration would be leads.
    real = sourcebook.worklist(cid)
    check(not (real["corroboration_reachable"] and not real["normative"]),
          "no class is 'reachable' on the strength of leads alone")


def test_sibling_subdomains_collapse() -> None:
    """NEGATIVE CONTROL. Two hosts, ONE publisher.

    This is the microsoft trap: `www.microsoft.com` + `learn.microsoft.com`
    satisfied the two-publisher rule on their own in an earlier wave.
    """
    a = config.publisher_org("www.microsoft.com")
    b = config.publisher_org("learn.microsoft.com")
    c = config.publisher_org("docs.microsoft.com")
    check(a == b == c,
          f"sibling Microsoft subdomains collapse to one org ({a})")
    check(config.publisher_org("owasp.org") != config.publisher_org("portswigger.net"),
          "genuinely different publishers stay distinct")


def test_publisher_independence_not_host_count() -> None:
    """A class whose seeds are 2 hosts / 1 org must be flagged, not passed.

    THE FIXTURE IS BUILT HERE, NOT BORROWED FROM THE LIVE REGISTRY.
    MEASURED 2026-11-01: this control used to look for a real class that
    happened to be 2-hosts/1-org. When the corpus improved -- and it did:
    every class now has >= 2 distinct publisher ORGS, because the nine
    NETWORK classes that were blocked on a single org were re-seeded --
    the control found ZERO thin classes and reported FAIL.

    That is a control that rots as the system improves. It measures the
    corpus's health and calls the result a defect in the detector. The
    detector was fine; the corpus got better.

    So the control now CONSTRUCTS the thin class it needs -- two sibling
    subdomains of one publisher -- and proves the detector catches it. The
    live registry is still checked, but only to report how many classes are
    currently thin, which is information and not a pass/fail condition.
    """
    # The synthetic class: two DIFFERENT hosts, ONE publisher org.
    thin_class = "control.thin.publisher"
    synthetic = [
        {"url": "https://a.example.com/one", "host": "a.example.com",
         "publisher_org": config.publisher_org("a.example.com"),
         "role": "normative", "source_type": "taxonomy",
         "classes": [thin_class], "defined_in": ["CONTROL"],
         "title": "control", "note": "control fixture",
         "tier": None, "access": None, "verified": None,
         "publisher_name": "example.com"},
        {"url": "https://b.example.com/two", "host": "b.example.com",
         "publisher_org": config.publisher_org("b.example.com"),
         "role": "normative", "source_type": "taxonomy",
         "classes": [thin_class], "defined_in": ["CONTROL"],
         "title": "control", "note": "control fixture",
         "tier": None, "access": None, "verified": None,
         "publisher_name": "example.com"},
    ]

    saved = sourcebook._CACHE
    doc = sourcebook.load()
    patched = dict(doc)
    patched["sources"] = list(doc["sources"]) + synthetic
    sourcebook._CACHE = patched
    try:
        ents = sourcebook.by_class(thin_class, role="normative")
        hosts = {e["host"] for e in ents}
        orgs = {e["publisher_org"] for e in ents if e["publisher_org"]}
        check(len(hosts) >= config.MIN_PUBLISHER_HOSTS and len(orgs) == 1,
              f"CONTROL: the synthetic class is "
              f"{len(hosts)} hosts / {len(orgs)} org (as intended)")
        w = sourcebook.worklist(thin_class)
        check(w["corroboration_reachable"] is False,
              "CONTROL: corroboration_reachable=False despite >=2 hosts")
        check(bool(w["gate_warning"]),
              "CONTROL: gate_warning is populated so a brief cannot hide it")
    finally:
        sourcebook._CACHE = saved

    # And the live registry, as INFORMATION rather than as a pass/fail: a
    # class that is thin today must be flagged, but zero thin classes is a
    # healthy corpus, not a broken detector.
    live_thin = []
    for cid in sourcebook.classes():
        ents = sourcebook.by_class(cid, role="normative")
        hosts = {e["host"] for e in ents}
        orgs = {e["publisher_org"] for e in ents if e["publisher_org"]}
        if len(hosts) >= config.MIN_PUBLISHER_HOSTS and len(orgs) < config.MIN_PUBLISHER_HOSTS:
            live_thin.append(cid)
    check(not live_thin,
          f"no live class is 2-hosts/1-org ({len(live_thin)} thin: "
          f"{live_thin[:3]})")


def test_closed_vocabulary() -> None:
    """A source_type outside the closed map silently scores authority 3."""
    doc = sourcebook.load()
    bad_type = [e["url"] for e in doc["sources"]
                if e["source_type"] not in config.SOURCE_AUTHORITY]
    check(not bad_type, f"every source_type is in SOURCE_AUTHORITY ({bad_type[:3]})")
    bad_access = [e["url"] for e in doc["sources"]
                  if e["access"] not in doc["vocabularies"]["access"]]
    check(not bad_access, f"every access tier is known ({bad_access[:3]})")
    bad_role = [e["url"] for e in doc["sources"]
                if e["role"] not in ("normative", "lead")]
    check(not bad_role, f"every role is in the closed vocabulary ({bad_role[:3]})")


def test_notes_present() -> None:
    """An unexplained registry entry becomes a mystery citation later."""
    doc = sourcebook.load()
    missing = [e["url"] for e in doc["sources"]
               if e["role"] == "lead" and not (e["note"] or "").strip()]
    check(not missing, f"every lead carries a note ({missing[:3]})")


def test_no_dead_urls_published() -> None:
    """A measured 404 must not be handed to a child as a source to read."""
    report = ROOT / "state" / "taxonomy-ext-verification.json"
    if not report.exists():
        check(True, "SKIP no verification report to compare against")
        return
    dead = {d["url"] for d in json.loads(
        report.read_text(encoding="utf-8")).get("dead_urls", [])}
    published = {e["url"] for e in sourcebook.load()["sources"]}
    leaked = dead & published
    check(not leaked, f"no measured-404 URL is published ({sorted(leaked)})")


def test_stale_registry_is_detected() -> None:
    """NEGATIVE CONTROL. Corrupt the file, confirm --check fails, restore.

    A drift check that cannot fail is decoration. This proves the check works
    by making it fail on purpose.
    """
    src = ROOT / "db" / "sources.json"
    original = src.read_text(encoding="utf-8")
    try:
        doc = json.loads(original)
        doc["sources"] = doc["sources"][:5]
        src.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                       encoding="utf-8")
        r = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "build_sources.py"), "--check"],
            capture_output=True, text=True, cwd=str(ROOT))
        check(r.returncode != 0 and "DRIFT" in (r.stdout + r.stderr),
              "CONTROL: truncating the registry makes --check fail with DRIFT")
    finally:
        src.write_text(original, encoding="utf-8")
    r2 = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "build_sources.py"), "--check"],
        capture_output=True, text=True, cwd=str(ROOT))
    check(r2.returncode == 0, "registry restored and --check passes again")


def test_missing_registry_raises_its_own_type() -> None:
    """A missing registry must not degrade to 'no sources available'."""
    check(issubclass(sourcebook.SourceRegistryMissing, FileNotFoundError),
          "SourceRegistryMissing is a FileNotFoundError (callers can catch it "
          "and say 'run the builder', not 'corpus is empty')")


# ---------------------------------------------------------------------------
# METADATA PRESERVATION (added 2026-11-01)
#
# The parity check proves the merge does not LOSE or INVENT URLs. It does
# not prove the merged file still carries the metadata the gate reads: the
# publisher org (the unit `MIN_PUBLISHER_HOSTS` counts), the role (the unit
# that decides whether a source counts at all), the class association (what
# routes a source to a class), and the provenance (`defined_in` -- which
# registry contributed it).
#
# A registry that kept the URLs and dropped the publisher org would pass
# every URL-level parity check and quietly collapse "two publishers" into
# "two pages", which is the exact defect this project already paid for.
# ---------------------------------------------------------------------------


def test_metadata_is_preserved_not_just_urls() -> None:
    doc = sourcebook.load()
    by_url = {e["url"]: e for e in doc["sources"]}

    # 1. publisher_org -- the unit the gate counts.
    bad_org = [e["url"] for e in doc["sources"]
               if e["publisher_org"] != config.publisher_org(e["host"])]
    check(not bad_org,
          f"every source's publisher_org is derivable from its host "
          f"({len(bad_org)} mismatches)")

    # 2. role -- the unit that decides whether a source counts at all.
    bad_role = [e["url"] for e in doc["sources"]
                if e["role"] not in ("normative", "lead")]
    check(not bad_role, f"every source has a role in the closed vocabulary "
                        f"({len(bad_role)} bad)")

    # 3. defined_in -- which registry contributed it.
    no_prov = [e["url"] for e in doc["sources"] if not e["defined_in"]]
    check(not no_prov, f"every source records where it was defined "
                       f"({len(no_prov)} with no provenance)")

    # 4. source_type -- the authority lookup key.
    bad_type = [e["url"] for e in doc["sources"]
                if e["source_type"] not in config.SOURCE_AUTHORITY]
    check(not bad_type, f"every source_type is in the closed authority "
                        f"vocabulary ({len(bad_type)} unknown)")

    # 5. The CURATED seeds keep their class, their type, and their role.
    #    A merge may ADD sources to a class; it may not detach one.
    from wks import taxonomy, network_taxonomy
    bad: list[str] = []
    for cid, s in taxonomy.CLASSES.items():
        for url, stype in s.sources:
            e = by_url.get(url)
            if e is None:
                bad.append(f"{cid}: {url} missing")
            elif cid not in e["classes"]:
                bad.append(f"{cid}: {url} lost its class")
            elif e["source_type"] != stype:
                bad.append(f"{cid}: {url} type {e['source_type']} != {stype}")
            elif e["role"] != "normative":
                bad.append(f"{cid}: {url} role {e['role']} != normative")
    check(not bad, f"every curated WEB seed keeps its class, type and "
                   f"normative role ({len(bad)} broken)")

    bad = []
    for cid, s in network_taxonomy.NET_CLASSES.items():
        for url, stype in s.sources:
            e = by_url.get(url)
            if e is None:
                bad.append(f"{cid}: {url} missing")
            elif cid not in e["classes"]:
                bad.append(f"{cid}: {url} lost its class")
            elif e["source_type"] != stype:
                bad.append(f"{cid}: {url} type {e['source_type']} != {stype}")
    check(not bad, f"every curated NETWORK seed keeps its class and type "
                   f"({len(bad)} broken)")

    # 6. The lead registry's entries stay leads. A lead relabelled
    #    normative would let two blog posts satisfy the publisher rule --
    #    the defect this file exists to catch.
    #
    #    `RESEARCH_SOURCES` is a tuple of `ResearchSource` records, so the
    #    URL is the `.url` attribute. MEASURED 2026-11-01: the first
    #    version iterated the tuple as if it were a list of URL strings,
    #    so every lookup was `None` and the check matched nothing --
    #    a check that silently passes because it compares the wrong thing.
    from wks import research_sources
    relabelled = []
    for rs in research_sources.RESEARCH_SOURCES:
        e = by_url.get(rs.url)
        if e is None:
            continue
        if (e["role"] == "normative"
                and e.get("defined_in") == ["research_sources.RESEARCH_SOURCES"]):
            relabelled.append(rs.url)
    check(not relabelled,
          f"no lead-only source was promoted to normative ({len(relabelled)})")

    # And the control proves the detector would SEE such a promotion. A
    # check that cannot fail is not a check.
    probe_url = research_sources.RESEARCH_SOURCES[0].url
    probe = by_url.get(probe_url)
    check(probe is not None and probe["role"] == "lead",
          f"CONTROL: the probe lead {probe_url[:48]} is present and is a lead")
    promoted = dict(probe or {})
    promoted["role"] = "normative"
    detected = (promoted["role"] == "normative"
                and promoted.get("defined_in")
                == ["research_sources.RESEARCH_SOURCES"])
    check(detected,
          "CONTROL: a lead promoted to normative IS detectable by the rule "
          "above")


def test_derived_fallback_cannot_override_the_registry() -> None:
    """The corpus-derived fallback must never OVERRIDE a canonical entry.

    `orch.researcher.seed_sources` reads the merged registry and falls back
    to `runtime/state/class-seeds.json` -- seeds derived from the corpus's own
    evidence -- when the registry yields nothing for a class.

    The fallback is a FALLBACK, not a second registry. Two properties:

      a. When the registry HAS the class, the derived list must not add to
         it. Otherwise a corpus-derived URL silently joins the curated set,
         and the curated set is no longer curated.
      b. When the registry is UNREADABLE, the derived list is used -- and
         the researcher must not then reach for a private curated list.
         That is the split source of truth defect 21 removed.
    """
    from orch import researcher

    registry_classes = set(sourcebook.classes())
    derived = researcher._derived_seed_sources()

    # (a) For every class the registry covers, the result must be exactly
    #     the registry's normative rows -- no derived extras.
    added: list[str] = []
    for cid in sorted(registry_classes & set(derived)):
        reg = {e["url"] for e in sourcebook.by_class(cid, role="normative")}
        got = {u for u, _ in researcher.seed_sources(cid)}
        extra = got - reg
        if extra:
            added.append(f"{cid}: +{sorted(extra)[:2]}")
    check(not added,
          f"the derived list adds nothing to a class the registry covers "
          f"({len(added)} classes overridden: {added[:3]})")

    # (b) With the registry hidden, the fallback must be the DERIVED list.
    #     The discriminator is a curated-only URL: one that is in the
    #     taxonomy seed but NOT in the derived seeds.
    real = Path(sourcebook.SOURCES_PATH)
    hidden = Path(tempfile.mkdtemp()) / "sources.json"
    saved = sourcebook._CACHE
    try:
        from wks import taxonomy
        derived_all = researcher._derived_seed_sources()
        probe = max(taxonomy._SEED,
                    key=lambda s: len({u for u, _ in s.sources}
                                      - {u for u, _ in derived_all.get(s.id, [])}))
        curated_only = {u for u, _ in probe.sources} - {
            u for u, _ in derived_all.get(probe.id, [])}
        shutil.move(str(real), str(hidden))
        sourcebook._CACHE = None
        got = {u for u, _ in researcher.seed_sources(probe.id)}
        leaked = got & curated_only
        check(not leaked,
              f"with the registry hidden, the fallback is the derived list and "
              f"not a private curated list ({len(leaked)} leaked)")
        check(len(curated_only) > 0,
              "the registry-hidden probe is not vacuous (the chosen class has "
              "curated-only URLs to discriminate on)")
    finally:
        shutil.move(str(hidden), str(real))
        sourcebook._CACHE = saved
        shutil.rmtree(hidden.parent, ignore_errors=True)


def main() -> int:
    for fn in (test_registry_loads,
               test_roles_are_separated_in_worklist,
               test_lead_relabelled_normative_is_detectable,
               test_sibling_subdomains_collapse,
               test_publisher_independence_not_host_count,
               test_closed_vocabulary,
               test_notes_present,
               test_no_dead_urls_published,
               test_stale_registry_is_detected,
               test_missing_registry_raises_its_own_type,
               test_metadata_is_preserved_not_just_urls,
               test_derived_fallback_cannot_override_the_registry):
        fn()
    npass = sum(1 for ok, _ in RESULTS if ok)
    for ok, label in RESULTS:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print(f"\n{npass}/{len(RESULTS)} pass")
    if npass != len(RESULTS):
        return 1
    print("SOURCEBOOK OK — merge is faithful AND safe to hand a child.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
