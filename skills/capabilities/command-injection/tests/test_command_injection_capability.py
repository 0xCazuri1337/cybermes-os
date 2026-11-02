"""Capability-level regression checks for command-injection."""
import hashlib
import json
import re
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]

def test_skill_exists():
    assert (BASE / "SKILL.md").is_file()

def test_nineteen_sections():
    text = (BASE / "SKILL.md").read_text(encoding="utf-8")
    sections = re.findall(r"^## \d+\. ", text, re.MULTILINE)
    assert len(sections) == 19, f"expected 19 sections, got {len(sections)}"

def test_references_exist():
    refs = list((BASE / "references").glob("*.md"))
    assert len(refs) >= 2

def test_subskills_preserved():
    assert (BASE / "exploiting-vulnerabilities-with-metasploit-framework" / "SKILL.md").is_file()
    assert (BASE / "hunt-rce" / "SKILL.md").is_file()

def test_migration_map_valid():
    data = json.loads((BASE / "migration_map.json").read_text())
    assert data["capability"] == "command-injection"
    assert len(data["legacy_sources"]) >= 1
    assert data["stage"] == "mission-standard"
    for src in data["legacy_sources"]:
        assert "sha256_source" in src and "sha256_destination" in src
        src_path = BASE / src["path"]
        dst_path = BASE / src["destination"]
        assert src_path.is_file() and dst_path.is_file()
        assert hashlib.sha256(src_path.read_bytes()).hexdigest() == src["sha256_source"]
        assert hashlib.sha256(dst_path.read_bytes()).hexdigest() == src["sha256_destination"]

if __name__ == "__main__":
    for t in (test_skill_exists, test_nineteen_sections, test_references_exist,
              test_subskills_preserved, test_migration_map_valid):
        try:
            t(); print("PASS", t.__name__)
        except AssertionError as e:
            print("FAIL", t.__name__, e)
