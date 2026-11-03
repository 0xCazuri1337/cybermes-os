"""Behavioral tests for the canonical command-injection capability."""
import importlib.util
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
SCRIPT = BASE / "exploiting-vulnerabilities-with-metasploit-framework" / "scripts" / "agent.py"


def load_module():
    spec = importlib.util.spec_from_file_location("command_injection", SCRIPT)
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
    assert "Metasploit" in result.stdout


def test_cve_mapping():
    module = load_module()
    assert module.map_cve_to_module("CVE-2017-0144") == "exploit/windows/smb/ms17_010_eternalblue"
    assert module.map_cve_to_module("CVE-0000-0000") is None


def test_rc_file_generation(tmp_path):
    module = load_module()
    output = tmp_path / "test.rc"
    result = module.generate_rc_file("exploit/test", {"RHOSTS": "127.0.0.1"}, str(output))
    assert result["rc_file"] == str(output)
    assert output.read_text().startswith("use exploit/test")