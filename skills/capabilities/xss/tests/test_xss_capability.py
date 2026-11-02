"""Capability-level regression checks for the canonical XSS capability."""
import hashlib
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SKILL = BASE / "SKILL.md"
REFS = BASE / "references"
MMAP = BASE / "migration_map.json"

REQUIRED_SECTIONS = [
    "Identity and purpose",
    "Scope",
    "Invocation and routing",
    "Inputs and outputs",
    "Preconditions and authorization",
    "Reconnaissance",
    "Detection methodology",
    "Technique selection",
    "Execution steps",
    "Tool usage",
    "Payloads and test cases",
    "Evidence",
    "Reproduction and validation",
    "False-positive rejection",
    "Impact",
    "Reporting",
    "Failure modes",
    "References",
    "Testing and mastery",
]

REQUIRED_REFS = [
    "reflected.md", "stored.md", "dom.md", "blind.md", "mutation-mxss.md",
    "framework-specific.md", "filter-bypass.md", "csp-interactions.md",
    "high-payout-patterns.md", "burp-validation.md",
    "dom-clobbering-postmessage-sw-css.md", "evidence-and-fp-rules.md",
]


def test_skill_exists():
    assert SKILL.is_file(), "SKILL.md missing"


def test_frontmatter():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---"), "missing frontmatter"
    assert "name: xss" in text, "canonical name must be xss"
    assert "description:" in text, "description missing"


def test_nineteen_sections():
    text = SKILL.read_text(encoding="utf-8")
    headings = re.findall(r"^## \d+\. (.+)$", text, flags=re.MULTILINE)
    assert len(headings) == 19, f"expected 19 sections, got {len(headings)}"
    for expected in REQUIRED_SECTIONS:
        assert expected in headings, f"missing section: {expected}"


def test_references_resolve_and_nonempty():
    refs = sorted(p.name for p in REFS.glob("*.md"))
    assert len(refs) >= 12, f"expected >=12 references, got {len(refs)}"
    for r in refs:
        assert (REFS / r).stat().st_size > 100, f"empty/superficial reference: {r}"


def test_skill_references_all_resolve():
    text = SKILL.read_text(encoding="utf-8")
    linked = re.findall(r"references/[A-Za-z0-9_.-]+\.md", text)
    assert len(set(linked)) >= 12, f"SKILL.md references only {len(set(linked))} refs"
    for rel in set(linked):
        assert (BASE / rel).is_file(), f"broken reference link: {rel}"


def test_required_refs_present():
    text = SKILL.read_text(encoding="utf-8")
    for r in REQUIRED_REFS:
        assert r in text, f"SKILL.md does not reference {r}"
        assert (REFS / r).is_file(), f"missing reference: {r}"


def test_migration_map_valid():
    data = json.loads(MMAP.read_text(encoding="utf-8"))
    assert data["capability"] == "xss"
    assert data["canonical_skill"] == "skills/capabilities/xss/SKILL.md"
    assert data["stage"] == "mission-standard"
    assert len(data["legacy_sources"]) >= 3
    assert len(data["deprecated_aliases"]) >= 3
    for entry in data["legacy_sources"]:
        assert "path" in entry and "destination" in entry and "status" in entry
        assert "hash" in entry and len(entry["hash"]) == 64, f"bad hash for {entry['path']}"
        assert (BASE / entry["path"]).is_file(), f"legacy source missing: {entry['path']}"
        actual = hashlib.sha256((BASE / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["hash"], f"hash mismatch for {entry['path']}"


def test_content_preservation():
    for d in ["hunt-dom", "hunt-xss", "xss-hunter", "testing-for-xss-vulnerabilities", "testing-for-xss-vulnerabilities-with-burpsuite"]:
        assert (BASE / d).is_dir(), f"missing legacy dir: {d}"



def test_fragment_methodology_preserved():
    text = (REFS / "dom.md").read_text(encoding="utf-8")
    assert "fragment trap" in text.lower()
    assert "location.hash` NEVER yields a raw" in text or "location.hash NEVER yields a raw" in text
    assert "decodeURIComponent" in text


def test_oob_gate_preserved():
    text = (REFS / "blind.md").read_text(encoding="utf-8")
    assert "OOB-Or-It-Didn't-Happen" in text
    assert "Collaborator" in text


def test_cdp_headless_validation_preserved():
    text = (REFS / "dom.md").read_text(encoding="utf-8")
    assert "headless Chromium over CDP" in text
    assert "remote-debugging-port" in text


def test_migration_destination_valid():
    data = json.loads(MMAP.read_text(encoding="utf-8"))
    for entry in data["legacy_sources"]:
        dest = entry["destination"]
        # hunt-dom must not reference the fabricated section 5.5
        if entry["path"] == "hunt-dom/SKILL.md":
            assert "section 5.5" not in dest
            assert "references/dom.md" in dest
        # any references/*.md token in destination must resolve
        for token in dest.split():
            token = token.strip(",+")
            if token.startswith("references/") and token.endswith(".md"):
                assert (BASE / token).is_file(), f"bad migration destination: {token}"


def test_no_stray_py():
    for ref in REFS.glob("*.md"):
        for line in ref.read_text(encoding="utf-8").splitlines():
            assert line.strip() != "PY", f"stray PY in {ref.name}"

if __name__ == "__main__":
    tests = [
        test_skill_exists, test_frontmatter, test_nineteen_sections,
        test_references_resolve_and_nonempty, test_skill_references_all_resolve,
        test_required_refs_present, test_migration_map_valid, test_content_preservation,
        test_fragment_methodology_preserved, test_oob_gate_preserved,
        test_cdp_headless_validation_preserved, test_migration_destination_valid,
        test_no_stray_py,
    ]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
