"""Capability-level regression checks for the canonical clickjacking capability."""
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
    assert "name: clickjacking" in text, "canonical name must be clickjacking"
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
    assert data["capability"] == "clickjacking"
    assert data["canonical_skill"] == "skills/capabilities/clickjacking/SKILL.md"
    assert len(data["legacy_sources"]) >= 2
    assert len(data["deprecated_aliases"]) >= 2
    for entry in data["legacy_sources"]:
        assert "path" in entry and "destination" in entry and "status" in entry
        assert "hash" in entry and len(entry["hash"]) == 64, f"bad hash for {entry['path']}"
        assert (BASE / entry["path"]).is_file(), f"legacy source missing: {entry['path']}"
        actual = hashlib.sha256((BASE / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["hash"], f"hash mismatch for {entry['path']}"


def test_content_preservation():
    for d in ["hunt-clickjacking", "performing-clickjacking-attack-test"]:
        assert (BASE / d).is_dir(), f"missing legacy dir: {d}"


import sys
sys.path.insert(0, str(BASE / "performing-clickjacking-attack-test" / "scripts"))

from unittest.mock import patch, MagicMock

import agent as cj_agent  # noqa: E402


def _mock_response(headers, status=200, text=""):
    r = MagicMock()
    r.headers = headers
    r.status_code = status
    r.text = text
    return r


def test_fp_missing_xfo_but_csp_blocks():
    headers = {"Content-Security-Policy": "frame-ancestors 'self'"}
    with patch("requests.get", return_value=_mock_response(headers)):
        res = cj_agent.check_frame_headers("https://example.com/settings")
    assert res["vulnerable"] is False
    assert res["framing_allowed"] is False
    assert res["severity"] != "HIGH"


def test_fp_missing_both_controls_is_candidate_not_auto_high():
    headers = {}
    with patch("requests.get", return_value=_mock_response(headers)):
        res = cj_agent.check_frame_headers("https://example.com/settings")
    assert res["vulnerable"] is False
    assert res["framing_allowed"] is True
    assert res["severity"] != "HIGH"


def test_fp_explicitly_allowed_framing():
    headers = {"Content-Security-Policy": "frame-ancestors *"}
    with patch("requests.get", return_value=_mock_response(headers)):
        res = cj_agent.check_frame_headers("https://example.com/settings")
    assert res["framing_allowed"] is True
    assert res["explicitly_allowed_framing"] is True
    assert res["vulnerable"] is False
    assert res["severity"] != "HIGH"


def test_fp_protected_sensitive_action():
    headers = {"X-Frame-Options": "DENY"}
    with patch("requests.get", return_value=_mock_response(headers)):
        res = cj_agent.check_frame_headers("https://example.com/transfer")
    assert res["vulnerable"] is False
    assert res["protected"] is True
    assert res["framing_allowed"] is False


def test_fp_non_sensitive_public_page():
    headers = {}
    with patch("requests.get", return_value=_mock_response(headers)):
        res = cj_agent.check_frame_headers("https://example.com/")
    assert res["vulnerable"] is False
    assert res["sensitive"] is False
    assert res["severity"] in ("LOW", "NONE", "INFO")

if __name__ == "__main__":
    import types
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    for t in tests:
        try:
            t()
            print(f"PASS {t.__name__}")
        except AssertionError as e:
            print(f"FAIL {t.__name__}: {e}")
