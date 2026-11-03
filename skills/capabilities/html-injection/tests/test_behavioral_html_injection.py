"""Behavioral tests for the canonical html-injection capability."""
import importlib.util
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "scripts" / "validate_html_context.py"


def load_module():
    spec = importlib.util.spec_from_file_location("html_context", SCRIPT)
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
    assert "captured HTML injection" in result.stdout


def test_unescaped_classification():
    module = load_module()
    canary = "CANARY-123"
    response = f"<b>{canary}</b>"
    assert module.classify_context(response, canary) == "unescaped_html"
    assert module.is_unescaped(response, canary) is True


def test_escaped_classification():
    module = load_module()
    canary = "CANARY-123"
    response = "&lt;b&gt;CANARY-123&lt;/b&gt;"
    assert module.classify_context(response, canary) == "escaped"
    assert module.is_unescaped(response, canary) is False


def test_not_reflected():
    module = load_module()
    assert module.classify_context("no canary here", "CANARY-123") == "not_reflected"