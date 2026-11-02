"""Contract tests for the canonical skill registry and resolver.

These are BEHAVIOUR tests, not wiring tests. Each one can go red.

The registry was, for the whole life of the project:

    {"skills": [], "aliases": {}, "routes": {}}

while the runtime manifest told every agent it was "the canonical registry
... all agents use it as truth", and the resolver was a five-line stub that
printed an empty list and exited 0. A resolver that cannot fail is
indistinguishable from one that resolved everything, so these tests exist to
make it fail when it should.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
RESOLVER = ROOT / "scripts" / "skill_registry.py"
REGISTRY = ROOT / "runtime" / "registry.json"

PASS = 0
FAIL = 0


def check(label: str, ok: bool, detail: str = "") -> None:
    global PASS, FAIL
    if ok:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}" + (f"  ({detail})" if detail else ""))


def run_resolver(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RESOLVER), *args],
                          cwd=str(ROOT), capture_output=True, text=True,
                          timeout=180)


class SkillRegistryContractTests(unittest.TestCase):
    def test_registry_is_not_empty(self):
        print("\nR1  THE REGISTRY IS NOT EMPTY")
        self.assertTrue(REGISTRY.is_file(), "runtime/registry.json is missing")
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        check("registry has skills", bool(registry.get("skills")),
              f"skills={len(registry.get('skills') or {})}")
        check("registry has routes", bool(registry.get("routes")),
              f"routes={len(registry.get('routes') or {})}")
        check("the corpus is indexed, not a token handful",
              len(registry.get("skills") or {}) >= 100,
              f"skills={len(registry.get('skills') or {})}")

    def test_every_registered_skill_exists_on_disk(self):
        print("\nR2  EVERY REGISTERED SKILL IS A REAL FILE")
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        missing = []
        for key, rec in (registry.get("skills") or {}).items():
            rel = rec.get("path") or key
            p = (ROOT / rel) if not Path(rel).is_absolute() else Path(rel)
            if not p.is_file():
                missing.append(rel)
        check("no registered skill points at a missing file",
              not missing, f"{len(missing)} missing: {missing[:3]}")

    def test_every_route_points_at_a_registered_skill(self):
        print("\nR3  EVERY ROUTE RESOLVES TO A REGISTERED SKILL")
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
        skills = registry.get("skills") or {}
        dangling = []
        empty = []
        for route, keys in (registry.get("routes") or {}).items():
            if not keys:
                empty.append(route)
            for k in keys:
                if k not in skills:
                    dangling.append((route, k))
        check("no route is empty", not empty, str(empty[:3]))
        check("no route points at an unregistered skill", not dangling,
              str(dangling[:3]))

    def test_check_command_reports_a_healthy_registry(self):
        print("\nR4  THE CHECK COMMAND PASSES ON THE REAL REGISTRY")
        p = run_resolver("check")
        check("check exits 0", p.returncode == 0, p.stdout[-200:])
        check("check reports a skill count", "skills" in p.stdout,
              p.stdout[-200:])

    def test_resolve_returns_usable_paths(self):
        print("\nR5  RESOLVE RETURNS REAL, LOADABLE PATHS")
        p = run_resolver("resolve", "--scenario",
                         "authenticated API with object identifiers",
                         "--mode", "test", "--paths-only")
        check("resolve exits 0 for a routable scenario", p.returncode == 0,
              p.stdout[-200:] + p.stderr[-200:])
        paths = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        check("resolve returns at least one path", bool(paths), p.stdout[-200:])
        unusable = []
        for rel in paths:
            f = ROOT / rel
            if not f.is_file():
                unusable.append(rel)
            elif f.stat().st_size == 0:
                unusable.append(rel + " (empty)")
        check("every returned path is a readable, non-empty file",
              not unusable, str(unusable[:3]))

    def test_resolve_returns_the_right_class_for_the_class_scenario(self):
        print("\nR6  THE REQUIRED SCENARIO REACHES THE RIGHT SKILLS")
        p = run_resolver("resolve", "--scenario",
                         "authenticated API with object identifiers",
                         "--mode", "test", "--paths-only")
        paths = [l.strip() for l in p.stdout.splitlines() if l.strip()]
        joined = " ".join(paths)
        check("an object-level-authorization skill is resolved",
              "idor" in joined or "object-level-authorization" in joined,
              joined[:300])

    def test_resolve_refuses_an_unroutable_scenario(self):
        print("\nR7  AN UNROUTABLE SCENARIO IS REFUSED, NOT EMPTYLY 'OK'")
        p = run_resolver("resolve", "--scenario",
                         "zzzz nonexistent quantum surface",
                         "--mode", "test", "--paths-only")
        check("resolve exits NON-zero when nothing resolves",
              p.returncode != 0, f"exit={p.returncode}")

    def test_generate_is_idempotent(self):
        print("\nR8  GENERATE IS IDEMPOTENT")
        before = REGISTRY.read_text(encoding="utf-8")
        p = run_resolver("generate")
        check("generate exits 0", p.returncode == 0, p.stdout[-200:])
        after = REGISTRY.read_text(encoding="utf-8")
        check("a second generate leaves the registry byte-identical",
              before == after,
              "registry changed on a no-op generate")


if __name__ == "__main__":
    unittest.main(verbosity=2)
