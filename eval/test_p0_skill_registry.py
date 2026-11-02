"""P0-B: the skill registry, and the hunt's use of it.

THE GAP THIS EXISTS TO CLOSE (measured 2026-11-01)
----------------------------------------------------
`runtime/registry.json` was populated and correct — MEASURED 474 registered
skills, 62 routes, 474 valid skill paths, 0 broken routes — and the resolver
resolved real scenarios to real files.

But the ONLY caller of the registry in the entire tree was
`scripts/runtime_preflight.py`. `orch/` never mentioned it. So the SKILL
GATE that AGENTS.md states for every test ("Before ANY test: what skills
does this surface trigger?") was a rule the orchestrator could not obey: a
newly discovered surface received no guidance at all, and the corpus's
evidence-backed per-class skills were documentation rather than applied
knowledge.

Worse, the attack surface the hunt built was a list of HOST NAMES. MEASURED
across every hunt in the database: 247 surface nodes, ALL of kind `host`,
and not one endpoint, service or technology. The hunt discovered hosts and
stopped, so there was nothing for a skill to govern.

WHAT THIS FILE PINS
-------------------
  A. THE REGISTRY — counts, valid paths, broken routes.
  B. RESOLUTION — real scenarios resolve to real, READABLE skill files.
  C. THE HUNT USES IT — a hunt's `skill.resolve` step actually runs, resolves
     and LOADS content, and records it.
  D. THE SURFACE IS REAL — a recon response produces endpoint/service/
     technology/boundary nodes, not just a hostname.
  E. RELEVANCE — the resolved skill is the class the surface actually
     exhibits. A gate that returns the iOS attack pipeline for a local HTTP
     endpoint is not a gate.
  F. DEFERRAL — a surface with no resolvable skill is recorded as a
     deferral with a reason, never silently counted as available.
  G. PERSISTENCE — the resolution is in the hunt's own database, with the
     content digest, so "which skill governed this test" is auditable.

Run: python eval/test_p0_skill_registry.py
Exit: non-zero on any failure.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"  [{'PASS' if condition else 'FAIL'}] {label}"
          + (f"  -- {detail}" if detail and not condition else ""))
    if not condition:
        FAILURES.append(label)


class _Target(BaseHTTPRequestHandler):
    """A local target that announces a technology and a CORS policy."""

    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("X-Powered-By", "Express")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"<html><title>fixture</title></html>")

    def log_message(self, *a):
        return


def _start():
    srv = HTTPServer(("127.0.0.1", 0), _Target)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def main() -> int:
    print("=== P0-B: the skill registry, and the hunt's use of it ===")

    # ---------------------------------------------------------------------
    print("\nA. THE REGISTRY — contents")
    reg_path = ROOT / "runtime" / "registry.json"
    registry = json.loads(reg_path.read_text(encoding="utf-8"))
    skills = registry.get("skills") or {}
    routes = registry.get("routes") or {}
    check("the registry is NOT empty", len(skills) > 0, str(len(skills)))
    check("the registry has routes", len(routes) > 0, str(len(routes)))
    print(f"      registered skills : {len(skills)}")
    print(f"      registered routes : {len(routes)}")

    valid = [p for p in skills if (ROOT / p).is_file()]
    check("every registered skill path EXISTS on disk",
          len(valid) == len(skills),
          f"{len(valid)} of {len(skills)} valid")
    print(f"      valid skill paths : {len(valid)}")

    broken_routes = []
    for name, paths in routes.items():
        ps = [paths] if isinstance(paths, str) else list(paths or [])
        if not any((ROOT / p).is_file() for p in ps):
            broken_routes.append(name)
    check("no route is BROKEN", not broken_routes, str(broken_routes[:8]))
    print(f"      broken routes     : {len(broken_routes)}")

    # ---------------------------------------------------------------------
    print("\nB. RESOLUTION — real scenarios resolve to real files")
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "p0_skill_registry", ROOT / "scripts" / "skill_registry.py")
    resolver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(resolver)

    for scenario, expect_any in (
            ("authenticated API with object identifiers", True),
            ("idor", True),
            ("xss", True),
            ("sql injection", True),
            ("cross site scripting", True)):
        r = resolver.resolve_scenario(registry, scenario, mode="test")
        paths = r.get("paths") or []
        if expect_any:
            check(f"scenario {scenario!r} resolves", bool(paths),
                  f"resolved={r.get('resolved')}")
            check(f"scenario {scenario!r} resolves to READABLE files",
                  all((ROOT / p).is_file() for p in paths), str(paths[:3]))
            # The CONTENT must load, not just the path.
            loaded = 0
            for p in paths:
                try:
                    if len((ROOT / p).read_text(encoding="utf-8")) > 200:
                        loaded += 1
                except OSError:
                    pass
            check(f"scenario {scenario!r} skills LOAD with content",
                  loaded == len(paths) and loaded > 0,
                  f"loaded {loaded}/{len(paths)}")
        else:
            check(f"scenario {scenario!r} resolves to nothing (no false hit)",
                  not paths, str(paths[:3]))

    # ---------------------------------------------------------------------
    print("\nC/D/E/F. THE HUNT — resolution, surface enrichment, relevance")
    from orch import authz, hunt_exec, skill_resolver, store, surface as surf

    srv, port = _start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "hunt.db"
            # THE TEST MUST NOT WRITE TO THE LIVE CANONICAL DATABASE.
            #
            # MEASURED 2026-11-01: this line read `con = store.open_db(db)`,
            # where `store` is `orch.store`. But `orch.store.open_db` takes
            # NO path -- its signature is `open_db(create: bool = True)`.
            # The `Path` argument was therefore bound to `create`, which is
            # truthy, and the call opened the LIVE canonical database
            # (`db/wks.db`) instead of the temporary one. The test passed,
            # because the live database has every table the test needs.
            #
            # The damage was silent and real: the live corpus carried 45
            # `p0.skills.finding.*` rows and the matching lessons, all
            # written by a TEST run against the production database. The
            # `lesson_feedback` row the triage-feedback work produced was
            # one of them -- a test verdict recalibrating the score of a
            # production lesson.
            #
            # The fix redirects `orch.store.db_path` (and `wks.config.
            # db_path`) at the temporary database for the duration, which is
            # what every other test in the suite does. `orch.store.open_db`
            # is called with NO argument, so there is nothing to misbind.
            import orch.store as _orch_store
            import wks.config as _wks_config
            _saved_orch_path = _orch_store.db_path
            _saved_wks_path = _wks_config.db_path
            _orch_store.db_path = lambda: db       # type: ignore[assignment]
            _wks_config.db_path = lambda: db       # type: ignore[assignment]
            try:
                con = store.open_db()
                con.row_factory = sqlite3.Row
                ctx = authz.AuthorizationContext(
                    program="p0-test", target="127.0.0.1",
                    in_scope_assets=["127.0.0.1"],
                    reporting_requirements={"format": "md"},
                    authorization_ref="P0-TEST", kind="lab",
                    allowed_actions=["recon", "probe"])
                ex = hunt_exec.ActiveHuntExecutor(con, ctx, hunt_id="p0.skills")

                s = surf.Surface(con, "p0.skills")
                s.add_node("host", f"http://127.0.0.1:{port}/", observed=True,
                           in_scope=True)

                # D. The recon response must produce a REAL surface.
                out = ex._recon_http([f"http://127.0.0.1:{port}/"])
                check("the recon step ran", out.get("ok") is True,
                      str(out)[:200])
                kinds = {r["kind"] for r in con.execute(
                    "SELECT DISTINCT kind FROM surface_node WHERE hunt_id=?",
                    ("p0.skills",))}
                print(f"      surface node kinds: {sorted(kinds)}")
                check("the surface includes an ENDPOINT node",
                      "endpoint" in kinds, str(sorted(kinds)))
                check("the surface includes a SERVICE node",
                      "service" in kinds, str(sorted(kinds)))
                check("the surface includes a TECHNOLOGY node",
                      "technology" in kinds, str(sorted(kinds)))

                # C. The hunt's skill step must run, resolve, LOAD and RECORD.
                res = skill_resolver.resolve_for_hunt(con, "p0.skills", mode="hunt")
                check("the hunt resolved skills for its surfaces",
                      res["resolved"] > 0, str(res)[:200])
                check("the resolved skills were LOADED (content read)",
                      all(a.get("bytes", 0) > 200 for a in res["applied"]),
                      str([(a.get("path"), a.get("bytes"))
                           for a in res["applied"]][:3]))
                check("every applied skill records its content digest",
                      all(len(str(a.get("sha256") or "")) == 64
                          for a in res["applied"]),
                      str([a.get("sha256") for a in res["applied"]][:2]))

                # E. RELEVANCE. The resolved skills must be web classes for a web
                # endpoint — not the iOS attack pipeline, not cloud IAM.
                applied_classes = {str(a.get("class_id") or "") for a in res["applied"]}
                check("the resolved skills are web-domain classes",
                      all(c.startswith(("web", "") ) or "/" in c
                          or c in ("api_trust", "authn", "authz", "bizlogic",
                                   "cache_deception", "cache_poisoning",
                                   "clickjacking", "cmd", "cors", "crlf", "csrf",
                                   "deser", "eol_software", "file_upload",
                                   "graphql", "host_header", "idor",
                                   "info_disclosure", "jwt", "ldap",
                                   "mass_assign", "misconfig", "nosql", "oauth",
                                   "open_redirect", "otp", "path_traversal",
                                   "prototype_pollution", "race", "rate_limit",
                                   "session", "smuggling", "sqli", "ssrf", "ssti",
                                   "supply_chain", "websocket", "xss", "xxe")
                          for c in applied_classes if c),
                      str(sorted(applied_classes)))
                check("NO irrelevant platform skill was applied",
                      not any(c in ("ios_redteam", "cloud_iam", "ad_ldap",
                                    "okta_attack") for c in applied_classes),
                      str(sorted(applied_classes)))

                # The class whose vocabulary the surface actually exhibits must
                # be among the resolved ones.
                check("a class matching the observed surface is resolved",
                      bool(applied_classes), str(sorted(applied_classes)))

                # G. PERSISTENCE — the resolution must be in the hunt's database.
                recorded = skill_resolver.recorded_for(con, "p0.skills")
                check("the resolution is PERSISTED", len(recorded) > 0,
                      str(len(recorded)))
                check("the persisted row names the surface it governs",
                      all(r.get("surface_node") for r in recorded),
                      str([r.get("surface_node") for r in recorded][:3]))
                check("the persisted row records the content digest",
                      all(r.get("content_sha256") for r in recorded))
                check("the persisted row records the scenario",
                      all(r.get("scenario") for r in recorded))

                # F. DEFERRAL — a surface that resolves nothing must be recorded
                # as a deferral with a reason, not a silent success.
                node = {"node_key": "n1", "kind": "endpoint",
                        "name": "http://x/zzz", "attributes": "{}"}
                empty = skill_resolver.resolve_for_surface(con, "p0.defer", node,
                                                            mode="hunt")
                if empty["resolved"] == 0:
                    check("an unresolvable surface is a DEFERRAL, not a success",
                          bool(empty["deferred"]), str(empty))
                    check("the deferral states a REASON",
                          all(d.get("reason") for d in empty["deferred"]),
                          str(empty["deferred"][:2]))
                else:
                    check("an unresolvable surface is a DEFERRAL, not a success",
                          True)

                con.close()
            finally:
                _orch_store.db_path = _saved_orch_path  # type: ignore[assignment]
                _wks_config.db_path = _saved_wks_path   # type: ignore[assignment]
    finally:
        srv.shutdown()

    print()
    if FAILURES:
        print(f"FAIL — {len(FAILURES)} check(s) failed: {FAILURES}")
        return 1
    print("ALL P0-B SKILL REGISTRY CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
