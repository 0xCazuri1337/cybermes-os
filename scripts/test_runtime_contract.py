"""Contract tests for the runtime preflight command."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve()
PREFLIGHT_PATH = SCRIPT.with_name("runtime_preflight.py")
_spec = importlib.util.spec_from_file_location("runtime_preflight_under_test", PREFLIGHT_PATH)
assert _spec is not None and _spec.loader is not None
preflight = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preflight)


RESOLVER_SOURCE = """\
import argparse
import sys

parser = argparse.ArgumentParser()
parser.add_argument("command")
parser.add_argument("--scenario", required=True)
parser.add_argument("--mode", required=True)
parser.add_argument("--paths-only", action="store_true")
args = parser.parse_args()
if args.scenario == "missing-route":
    print("no usable route", file=sys.stderr)
    raise SystemExit(3)
print("skills/demo/SKILL.md")
"""


class RuntimePreflightContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "repo"
        (self.root / "scripts").mkdir(parents=True)
        (self.root / "runtime" / "opencode").mkdir(parents=True)
        (self.root / "skills" / "demo").mkdir(parents=True)
        (self.root / "testing").mkdir(parents=True)
        (self.root / "runtime" / "registry.json").write_text(
            json.dumps({"skills": [], "agents": [], "commands": []}), encoding="utf-8"
        )
        (self.root / "settings.json").write_text("{}\n", encoding="utf-8")
        (self.root / "runtime" / "opencode" / "loader.md").write_text("loader\n", encoding="utf-8")
        (self.root / "skills" / "demo" / "SKILL.md").write_text("# demo\n", encoding="utf-8")
        (self.root / "scripts" / "skill_registry.py").write_text(
            RESOLVER_SOURCE, encoding="utf-8"
        )

        self.patchers = [
            mock.patch.object(preflight, "ROOT", self.root),
            mock.patch.object(preflight, "REGISTRY", self.root / "runtime" / "registry.json"),
            mock.patch.object(preflight, "SETTINGS", self.root / "settings.json"),
            mock.patch.object(preflight, "LOADER", self.root / "runtime" / "opencode" / "loader.md"),
            mock.patch.object(preflight, "SKILLS_ROOT", self.root / "skills"),
            mock.patch.object(preflight, "TESTING_ROOT", self.root / "testing"),
        ]
        for patcher in self.patchers:
            patcher.start()
            self.addCleanup(patcher.stop)

    def invoke(self, *arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = preflight.main(list(arguments))
        text = output.getvalue()
        payload = json.loads(text)
        return code, payload, text

    def common_arguments(self, workspace="testing/example.com/app"):
        return (
            "--target",
            "app.example.com",
            "--scenario",
            "web",
            "--mode",
            "hunt",
            "--workspace",
            workspace,
            "--authorization-ref",
            "AUTH-123",
        )

    def test_valid_authorization_proceeds(self):
        code, payload, _ = self.invoke(*self.common_arguments())
        self.assertEqual(code, 0)
        self.assertEqual(payload["result"], "OK")
        self.assertEqual(payload["status"], "OK")
        self.assertEqual(payload["resolved_skill_paths"], ["skills/demo/SKILL.md"])
        self.assertFalse(payload["boundaries"]["active_target_access"])

    def test_missing_authorization_blocks(self):
        arguments = list(self.common_arguments())
        authorization_index = arguments.index("--authorization-ref")
        del arguments[authorization_index : authorization_index + 2]
        code, payload, _ = self.invoke(*arguments)
        self.assertEqual(code, 2)
        self.assertEqual(payload["result"], "BLOCKED_AUTHORIZATION")
        self.assertEqual(payload["status"], "BLOCKED")

    def test_invalid_scope_blocks_and_creates_no_session(self):
        workspace = self.root / "testing" / "example.com" / "app"
        code, payload, _ = self.invoke(
            *self.common_arguments(),
            "--in-scope",
            "*.example.com",
            "--ensure-session",
        )
        self.assertEqual(code, 2)
        self.assertEqual(payload["result"], "BLOCKED_AUTHORIZATION")
        self.assertFalse(workspace.exists())

    def test_missing_resolver_route_blocks(self):
        arguments = list(self.common_arguments())
        scenario_index = arguments.index("--scenario")
        arguments[scenario_index + 1] = "missing-route"
        code, payload, _ = self.invoke(*arguments)
        self.assertEqual(code, 2)
        self.assertEqual(payload["result"], "BLOCKED_SKILL_RESOLUTION")

    def test_ensure_session_creates_workspace_and_record(self):
        workspace = self.root / "testing" / "example.com" / "app"
        code, payload, _ = self.invoke(*self.common_arguments(), "--ensure-session")
        self.assertEqual(code, 0)
        self.assertTrue(payload["session_created"])

        session_path = workspace / "session.json"
        self.assertTrue(session_path.is_file())
        record = json.loads(session_path.read_text(encoding="utf-8"))
        self.assertEqual(record["target"], "app.example.com")
        self.assertEqual(record["scenario"], "web")
        self.assertEqual(record["authorization_ref"], "AUTH-123")
        self.assertEqual(record["resolved_skill_paths"], ["skills/demo/SKILL.md"])
        self.assertIn("timestamp", record)
        self.assertEqual(record["boundaries"]["in_scope"], ["app.example.com"])
        for directory in preflight.STANDARD_DIRECTORIES:
            self.assertTrue((workspace / directory).is_dir())
        self.assertEqual(list(workspace.glob(".*.tmp")), [])

    def test_existing_target_record_is_loaded_without_overwrite(self):
        workspace = self.root / "testing" / "example.com" / "app"
        workspace.mkdir(parents=True)
        session_path = workspace / "session.json"
        original = {
            "target": "app.example.com",
            "timestamp": "2026-01-01T00:00:00Z",
            "evidence": "preserve-me",
        }
        session_path.write_text(json.dumps(original), encoding="utf-8")

        code, payload, _ = self.invoke(*self.common_arguments(), "--ensure-session")
        self.assertEqual(code, 0)
        self.assertFalse(payload["session_created"])
        self.assertEqual(payload["session"], original)
        self.assertEqual(json.loads(session_path.read_text(encoding="utf-8")), original)

    def test_preflight_performs_no_network_access(self):
        def forbidden(*args, **kwargs):
            raise AssertionError("preflight attempted a network connection")

        with mock.patch.object(socket, "create_connection", forbidden), mock.patch.object(
            socket.socket, "connect", forbidden
        ):
            code, payload, _ = self.invoke(*self.common_arguments(), "--ensure-session")
        self.assertEqual(code, 0)
        self.assertFalse(payload["boundaries"]["active_target_access"])

    def test_test_mode_remains_validation_only(self):
        arguments = list(self.common_arguments())
        mode_index = arguments.index("--mode")
        arguments[mode_index + 1] = "test"
        code, payload, _ = self.invoke(*arguments)
        self.assertEqual(code, 0)
        self.assertTrue(payload["boundaries"]["validation_only"])
        self.assertFalse(payload["boundaries"]["active_target_access"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
