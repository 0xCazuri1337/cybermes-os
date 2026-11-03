"""Behavioral tests for the canonical prototype-pollution capability."""
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "exploiting-prototype-pollution-in-javascript" / "scripts" / "agent.py"


def load_module():
    spec = importlib.util.spec_from_file_location("prototype_pollution", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_help_exits_zero():
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "prototype pollution" in result.stdout.lower()


def test_scan_source_code_finds_sink():
    module = load_module()
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
        handle.write("const merged = Object.assign({}, userInput);\n")
        path = handle.name
    findings = module.scan_source_code(path)
    assert any("Object.assign" in item["pattern"] for item in findings)


def test_payload_inventory_present():
    module = load_module()
    assert len(module.PROTOTYPE_PAYLOADS) >= 3
    assert len(module.PROTOTYPE_PAYLOADS_QUERY) >= 3