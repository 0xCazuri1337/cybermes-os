"""Capability-level regression checks for the canonical redteam capability."""
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SKILL = BASE / "SKILL.md"
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
    assert "name: redteam" in text, "canonical name must be redteam"
    assert "description:" in text, "description missing"


def test_nineteen_sections():
    text = SKILL.read_text(encoding="utf-8")
    headings = re.findall(r"^## \d+\. (.+)$", text, flags=re.MULTILINE)
    assert len(headings) == 19, f"expected 19 sections, got {len(headings)}"
    for expected in REQUIRED_SECTIONS:
        assert expected in headings, f"missing section: {expected}"


def test_migration_map_valid():
    data = json.loads(MMAP.read_text(encoding="utf-8"))
    assert data["capability"] == "redteam"
    assert data["canonical_skill"] == "skills/capabilities/redteam/SKILL.md"
    assert len(data["legacy_sources"]) == 8
    for entry in data["legacy_sources"]:
        assert (BASE / entry["path"]).is_dir(), f"nested source missing: {entry['path']}"


def test_nested_scripts_present():
    scripts = [p for p in BASE.rglob("*.py") if p.is_file()]
    assert len(scripts) >= 200, f"expected >=200 redteam scripts, got {len(scripts)}"


def test_nested_subskills_present():
    for name in ["ad", "network", "infra", "mobile", "cicd", "supply-chain", "linux", "misc"]:
        assert (BASE / name).is_dir(), f"missing nested redteam area: {name}"


if __name__ == "__main__":
    for t in [test_skill_exists, test_frontmatter, test_nineteen_sections, test_migration_map_valid, test_nested_scripts_present, test_nested_subskills_present]:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
