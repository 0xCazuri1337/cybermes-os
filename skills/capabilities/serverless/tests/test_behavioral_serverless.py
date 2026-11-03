"""Behavioral tests for the canonical serverless capability."""
import importlib.util
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "detecting-serverless-function-injection" / "scripts" / "agent.py"


def load_module():
    spec = importlib.util.spec_from_file_location("serverless", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_runtime_family_detection():
    module = load_module()
    assert module.detect_runtime_family("python3.11") == "python"
    assert module.detect_runtime_family("nodejs18.x") == "nodejs"
    assert module.detect_runtime_family("java11") == "java"
    assert module.detect_runtime_family("") == "unknown"


def test_help_does_not_crash_import():
    # The agent may lack cloud SDKs; importing and calling a pure helper is enough.
    module = load_module()
    assert callable(module.detect_runtime_family)