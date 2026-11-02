"""Capability-level regression checks for the canonical recon capability."""
import hashlib
import json
import re
from pathlib import Path

BASE = Path("C:/Users/Administrator/.hermes/cyber/skills/capabilities/recon")
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

LEGACY_DIRS = [
    "attack-surface/bb-local-toolkit",
    "attack-surface/bot-mitigated-spa-recon",
    "attack-surface/bugbounty-ops-egress-captcha",
    "attack-surface/configuring-pfsense-firewall-rules",
    "attack-surface/find-skills",
    "attack-surface/hunt-dispatch",
    "attack-surface/performing-ip-reputation-analysis-with-shodan",
    "attack-surface/redteam-mindset",
    "attack-surface/scanning-network-with-nmap-advanced",
    "attack-surface/skill-folder-claude-bughunter-layout",
    "attack-surface/web-pentest/spa-auth-recon",
    "osint/building-threat-actor-profile-from-osint",
    "osint/collecting-open-source-intelligence",
    "osint/conducting-external-reconnaissance-with-osint",
    "osint/offensive-osint",
    "osint/osint-methodology",
    "osint/performing-ai-driven-osint-correlation",
    "osint/performing-brand-monitoring-for-impersonation",
    "osint/performing-open-source-intelligence-gathering",
    "osint/performing-osint-with-spiderfoot",
    "osint/tracking-threat-actor-infrastructure",
    "scope/recon-scope-triage",
    "secrets/hunt-ntlm-info",
    "secrets/hunt-source-leak",
    "secrets/performing-paste-site-monitoring-for-credentials",
    "subdomains/analyzing-typosquatting-domains-with-dnstwist",
    "subdomains/hunt-subdomain",
    "subdomains/performing-dns-enumeration-and-zone-transfer",
    "subdomains/performing-subdomain-enumeration-with-subfinder",
]


def test_skill_exists():
    assert SKILL.is_file(), "SKILL.md missing"


def test_frontmatter():
    text = SKILL.read_text(encoding="utf-8")
    assert text.startswith("---"), "missing frontmatter"
    assert "name: recon" in text, "canonical name must be recon"
    assert "description:" in text, "description missing"


def test_nineteen_sections():
    text = SKILL.read_text(encoding="utf-8")
    headings = re.findall(r"^## \d+\. (.+)$", text, flags=re.MULTILINE)
    assert len(headings) == 19, f"expected 19 sections, got {len(headings)}"
    for expected in REQUIRED_SECTIONS:
        assert expected in headings, f"missing section: {expected}"


def test_references_resolve_and_nonempty():
    refs = sorted(p.name for p in REFS.glob("*.md"))
    assert len(refs) >= 29, f"expected >=29 references, got {len(refs)}"
    for r in refs:
        assert (REFS / r).stat().st_size > 100, f"empty/superficial reference: {r}"


def test_skill_references_all_resolve():
    text = SKILL.read_text(encoding="utf-8")
    linked = re.findall(r"references/[A-Za-z0-9_.-]+\.md", text)
    assert len(set(linked)) >= 29, f"SKILL.md references only {len(set(linked))} refs"
    for rel in set(linked):
        assert (BASE / rel).is_file(), f"broken reference link: {rel}"


def test_migration_map_valid():
    data = json.loads(MMAP.read_text(encoding="utf-8"))
    assert data["capability"] == "recon"
    assert data["canonical_skill"] == "skills/capabilities/recon/SKILL.md"
    assert len(data["legacy_sources"]) >= 29
    assert len(data["deprecated_aliases"]) >= 29
    for entry in data["legacy_sources"]:
        assert "path" in entry and "destination" in entry and "status" in entry
        assert "hash" in entry and len(entry["hash"]) == 64, f"bad hash for {entry['path']}"
        assert (BASE / entry["path"]).is_file(), f"legacy source missing: {entry['path']}"
        actual = hashlib.sha256((BASE / entry["path"]).read_bytes()).hexdigest()
        assert actual == entry["hash"], f"hash mismatch for {entry['path']}"


def test_content_preservation():
    for d in LEGACY_DIRS:
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
