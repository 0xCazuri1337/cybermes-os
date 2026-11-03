"""Behavioral tests for the canonical NoSQL injection capability."""
import importlib.util
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "exploiting-nosql-injection-vulnerabilities" / "scripts" / "process.py"


def load_module():
    spec = importlib.util.spec_from_file_location("nosqli", SCRIPT)
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
    assert "NoSQL" in result.stdout


def test_escape_regex():
    module = load_module()
    assert module._escape_regex("a.b*c?") == "a\\.b\\*c\\?"


def test_operator_payload_structure():
    module = load_module()
    assert callable(module.test_operator_injection)
    assert module.test_operator_injection.__doc__