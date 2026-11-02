"""Capability-level regression checks for the canonical file-upload capability."""
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
    assert "name: file-upload" in text, "canonical name must be file-upload"
    assert "description:" in text, "description missing"


def test_nineteen_sections():
    text = SKILL.read_text(encoding="utf-8")
    headings = re.findall(r"^## \d+\. (.+)$", text, flags=re.MULTILINE)
    assert len(headings) == 19, f"expected 19 sections, got {len(headings)}"
    for expected in REQUIRED_SECTIONS:
        assert expected in headings, f"missing section: {expected}"


def test_references_resolve_and_nonempty():
    refs = sorted(p.name for p in REFS.glob("*.md"))
    assert len(refs) >= 3, f"expected >=3 references, got {len(refs)}"
    for r in refs:
        assert (REFS / r).stat().st_size > 100, f"empty/superficial reference: {r}"


def test_skill_references_all_resolve():
    text = SKILL.read_text(encoding="utf-8")
    linked = re.findall(r"references/[A-Za-z0-9_.-]+\.md", text)
    assert len(set(linked)) >= 3, f"SKILL.md references only {len(set(linked))} refs"
    for rel in set(linked):
        assert (BASE / rel).is_file(), f"broken reference link: {rel}"


def test_migration_map_valid():
    data = json.loads(MMAP.read_text(encoding="utf-8"))
    assert data["capability"] == "file-upload"
    assert data["canonical_skill"] == "skills/capabilities/file-upload/SKILL.md"
    assert data["stage"] == "mission-standard"
    assert len(data["legacy_sources"]) >= 2
    assert len(data["deprecated_aliases"]) >= 2
    for entry in data["legacy_sources"]:
        assert "path" in entry and "destination" in entry and "status" in entry
        assert "hash" in entry and len(entry["hash"]) == 64, f"bad hash for {entry['path']}"
        assert (BASE / entry["path"]).is_file(), f"legacy source missing: {entry['path']}"
        actual = hashlib.sha256((BASE / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["hash"], f"hash mismatch for {entry['path']}"


def test_content_preservation():
    for d in ["hunt-file-upload", "hunting-for-webshell-activity"]:
        assert (BASE / d).is_dir(), f"missing legacy dir: {d}"



def test_subskill_scripts_preserved():
    d = "hunting-for-webshell-activity"
    assert (BASE / d / "scripts" / "agent.py").is_file(), "missing agent.py"
    assert (BASE / d / "scripts" / "process.py").is_file(), "missing process.py"
    assert (BASE / d / "assets" / "template.md").is_file(), "missing template.md"
    assert (BASE / d / "references" / "standards.md").is_file(), "missing standards.md"
    assert (BASE / d / "references" / "workflows.md").is_file(), "missing workflows.md"
    assert (BASE / d / "references" / "api-reference.md").is_file(), "missing api-reference.md"



if __name__ == "__main__":
    tests = [
        test_skill_exists, test_frontmatter, test_nineteen_sections,
        test_references_resolve_and_nonempty, test_skill_references_all_resolve,
        test_migration_map_valid, test_content_preservation,
        test_subskill_scripts_preserved,
    ]
    for t in tests:
        try:
            t(); print(f"PASS {t.__name__}")
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
