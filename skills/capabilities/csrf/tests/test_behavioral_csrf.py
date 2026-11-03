"""Behavioral tests for the canonical CSRF capability."""
import importlib.util
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "performing-csrf-attack-simulation" / "scripts" / "agent.py"


def load_module():
    spec = importlib.util.spec_from_file_location("csrf", SCRIPT)
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
    assert "CSRF" in result.stdout


def test_generate_csrf_poc():
    module = load_module()
    poc = module.generate_csrf_poc("https://example.com/action", "POST", {"amount": "100"})
    assert "<form" in poc
    assert 'name="amount"' in poc
    assert "example.com/action" in poc


def test_token_validation_report_shape():
    module = load_module()
    # No network: generate_report should still format provided data.
    report = module.generate_report([], [], [])
    assert isinstance(report, str)
    assert "CSRF" in report or "Analysis" in report or "Report" in report