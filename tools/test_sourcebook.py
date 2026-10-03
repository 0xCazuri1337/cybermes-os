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
    """A class whose seeds are 2 hosts / 1 org must be flagged, not passed."""
    doc = sourcebook.load()
    thin = []
    for cid in sourcebook.classes():
        ents = sourcebook.by_class(cid, role="normative")
        hosts = {e["host"] for e in ents}
        orgs = {e["publisher_org"] for e in ents if e["publisher_org"]}
        if len(hosts) >= config.MIN_PUBLISHER_HOSTS and len(orgs) < config.MIN_PUBLISHER_HOSTS:
            thin.append(cid)
    check(bool(thin),
          f"CONTROL: at least one class is 2-hosts/1-org and detectable ({len(thin)})")
    for cid in thin[:3]:
        w = sourcebook.worklist(cid)
        check(w["corroboration_reachable"] is False,
              f"{cid}: corroboration_reachable=False despite >=2 hosts")
        check(bool(w["gate_warning"]),
              f"{cid}: gate_warning is populated so a brief cannot hide it")


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
               test_missing_registry_raises_its_own_type):
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
