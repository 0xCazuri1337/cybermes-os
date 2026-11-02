"""Capability-level regression checks for the canonical business-logic capability."""
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


def test_skill_exists():
    assert SKILL.is_file(), "SKILL.md missing"


def test_frontmatter():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---"), "missing frontmatter"
    assert "name: business-logic" in text, "canonical name must be business-logic"
    assert "description:" in text, "description missing"


def test_nineteen_sections():
    text = SKILL.read_text(encoding="utf-8")
    headings = re.findall(r"^## \d+\. (.+)$", text, flags=re.MULTILINE)
    assert len(headings) == 19, f"expected 19 sections, got {len(headings)}"
    for expected in REQUIRED_SECTIONS:
        assert expected in headings, f"missing section: {expected}"


def test_references_resolve_and_nonempty():
    refs = sorted(p.name for p in REFS.glob("*.md"))
    assert len(refs) >= 4, f"expected >=4 references, got {len(refs)}"
    for r in refs:
        assert (REFS / r).stat().st_size > 100, f"empty/superficial reference: {r}"


def test_skill_references_all_resolve():
    text = SKILL.read_text(encoding="utf-8")
    linked = re.findall(r"references/[A-Za-z0-9_.-]+\.md", text)
    assert len(set(linked)) >= 4, f"SKILL.md references only {len(set(linked))} refs"
    for rel in set(linked):
        assert (BASE / rel).is_file(), f"broken reference link: {rel}"


def test_migration_map_valid():
    data = json.loads(MMAP.read_text(encoding="utf-8"))
    assert data["capability"] == "business-logic"
    assert data["canonical_skill"] == "skills/capabilities/business-logic/SKILL.md"
    assert len(data["legacy_sources"]) >= 4
    assert len(data["deprecated_aliases"]) >= 4
    for entry in data["legacy_sources"]:
        assert "path" in entry and "destination" in entry and "status" in entry
        assert "hash" in entry and len(entry["hash"]) == 64, f"bad hash for {entry['path']}"
        assert (BASE / entry["path"]).is_file(), f"legacy source missing: {entry['path']}"
        actual = hashlib.sha256((BASE / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["hash"], f"hash mismatch for {entry['path']}"


def test_content_preservation():
    for d in ["businesslogic-hunter", "hunt-business-logic", "hunt-captcha-bypass", "testing-for-business-logic-vulnerabilities"]:
        assert (BASE / d).is_dir(), f"missing legacy dir: {d}"


if __name__ == "__main__":
    tests = [
        test_skill_exists, test_frontmatter, test_nineteen_sections,
        test_references_resolve_and_nonempty, test_skill_references_all_resolve,
        test_migration_map_valid, test_content_preservation,
    ]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
