"""Validate a hunting scope and bootstrap a local testing session.

This command only validates configuration and prepares local session metadata.  It
never contacts the supplied target.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "runtime" / "registry.json"
SETTINGS = ROOT / "settings.json"
LOADER = ROOT / "runtime" / "opencode" / "loader.md"
SKILLS_ROOT = ROOT / "skills"
TESTING_ROOT = ROOT / "testing"

STANDARD_DIRECTORIES = (
    "notes",
    "requests",
    "responses",
    "screenshots",
    "scripts",
    "scans",
    "wordlists",
    "urls",
    "subdomains",
    "evidence",
    "reports",
)

# DNS hostnames only.  URLs, ports, paths, IP literals, and wildcards are not
# concrete hostnames and are therefore rejected.
_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
_PLACEHOLDER_AUTHORIZATION = {
    "",
    "-",
    "none",
    "n/a",
    "na",
    "null",
    "unknown",
    "unspecified",
    "pending",
    "todo",
    "tbd",
    "authorization",
    "authorized",
}
_SENSITIVE_AUTHORIZATION = re.compile(
    r"(?:bearer\s+|token|secret|password|passwd|credential|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)
_JWT_LIKE = re.compile(r"^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$")


class PreflightError(Exception):
    """A validation failure with a stable machine-readable result code."""

    def __init__(self, result: str, reason: str):
        super().__init__(reason)
        self.result = result
        self.reason = reason


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _is_concrete_hostname(value: str) -> bool:
    """Return true only for an explicit, concrete DNS hostname."""
    candidate = value.strip()
    if not candidate or candidate != value:
        return False
    if "*" in candidate or "?" in candidate or "/" in candidate or "\\" in candidate:
        return False
    if "://" in candidate or "@" in candidate or ":" in candidate or candidate.endswith("."):
        return False
    if len(candidate) > 253 or "." not in candidate:
        return False
    labels = candidate.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        return False
    return True


def _parse_scope(raw_scope: str | None, target: str) -> list[str]:
    if raw_scope is None:
        return [target]
    scope = [item.strip() for item in raw_scope.split(",") if item.strip()]
    if not scope:
        raise PreflightError("BLOCKED_AUTHORIZATION", "scope must name at least one exact hostname")
    normalized = [item.lower() for item in scope]
    if len(normalized) != len(set(normalized)):
        raise PreflightError("BLOCKED_AUTHORIZATION", "scope contains duplicate hostnames")
    for item in scope:
        if not _is_concrete_hostname(item):
            raise PreflightError(
                "BLOCKED_AUTHORIZATION",
                f"scope entry is not an exact concrete hostname: {item!r}",
            )
    if target.lower() not in normalized:
        raise PreflightError(
            "BLOCKED_AUTHORIZATION",
            "the exact target is not explicitly present in the supplied scope",
        )
    # Membership is exact.  Parent domains never imply subdomain access.
    return sorted(normalized)


def _validate_authorization(reference: str | None) -> str:
    if reference is None or not reference.strip():
        raise PreflightError(
            "BLOCKED_AUTHORIZATION", "an explicit authorization reference is required"
        )
    value = reference.strip()
    if value.lower() in _PLACEHOLDER_AUTHORIZATION or "*" in value or "?" in value:
        raise PreflightError(
            "BLOCKED_AUTHORIZATION", "authorization reference must be explicit and non-placeholder"
        )
    if len(value) < 3:
        raise PreflightError(
            "BLOCKED_AUTHORIZATION", "authorization reference must be explicit and non-placeholder"
        )
    return value


def _redact_authorization(reference: str) -> str:
    if _SENSITIVE_AUTHORIZATION.search(reference) or _JWT_LIKE.match(reference):
        digest = hashlib.sha256(reference.encode("utf-8")).hexdigest()[:12]
        return f"redacted:sha256:{digest}"
    return reference


def _validate_configuration() -> None:
    required_files = (REGISTRY, SETTINGS, LOADER)
    for path in required_files:
        if not path.is_file():
            raise PreflightError(
                "BLOCKED_CONFIGURATION", f"required configuration file is missing: {path.relative_to(ROOT)}"
            )
    if not SKILLS_ROOT.is_dir():
        raise PreflightError(
            "BLOCKED_CONFIGURATION", "required skills directory is missing: skills"
        )


def _resolve_skill_paths(scenario: str, mode: str) -> list[str]:
    resolver = ROOT / "scripts" / "skill_registry.py"
    if not resolver.is_file():
        raise PreflightError(
            "BLOCKED_SKILL_RESOLUTION", "skill resolver is missing: scripts/skill_registry.py"
        )
    command = [
        sys.executable,
        str(resolver),
        "resolve",
        "--scenario",
        scenario,
        "--mode",
        mode,
        "--paths-only",
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise PreflightError("BLOCKED_SKILL_RESOLUTION", f"skill resolver failed: {exc}") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "no usable route"
        raise PreflightError("BLOCKED_SKILL_RESOLUTION", detail)

    candidates: list[str] = []
    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # The public paths-only contract emits one repo-relative path per line.
        # Accept a JSON string as well so the preflight remains compatible with
        # resolver implementations that emit one JSON value per line.
        if line.startswith('"') and line.endswith('"'):
            try:
                decoded = json.loads(line)
            except json.JSONDecodeError:
                decoded = None
            if isinstance(decoded, str):
                line = decoded
        candidates.append(line)

    usable: list[str] = []
    for candidate in candidates:
        relative = Path(candidate)
        if relative.is_absolute() or ".." in relative.parts:
            continue
        resolved = (ROOT / relative).resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            continue
        if resolved.is_file():
            usable.append(relative.as_posix())

    if not usable:
        raise PreflightError(
            "BLOCKED_SKILL_RESOLUTION",
            f"scenario {scenario!r} has no usable skill route for mode {mode!r}",
        )
    return sorted(set(usable))


def _workspace_path(raw_workspace: str) -> Path:
    candidate = Path(raw_workspace).expanduser()
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    resolved = candidate.resolve(strict=False)
    testing_root = TESTING_ROOT.resolve(strict=False)
    try:
        relative = resolved.relative_to(testing_root)
    except ValueError as exc:
        raise PreflightError(
            "BLOCKED_AUTHORIZATION", "workspace must be located under testing/"
        ) from exc
    if not relative.parts:
        raise PreflightError(
            "BLOCKED_AUTHORIZATION", "workspace must be a target directory under testing/"
        )
    return resolved


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _load_or_bootstrap_session(
    workspace: Path,
    *,
    target: str,
    scenario: str,
    mode: str,
    authorization_ref: str,
    scope: list[str],
    skill_paths: list[str],
) -> tuple[dict[str, Any], bool]:
    session_path = workspace / "session.json"
    if session_path.exists():
        if not session_path.is_file():
            raise PreflightError(
                "BLOCKED_CONFIGURATION", "existing session record is not a regular file"
            )
        try:
            with session_path.open("r", encoding="utf-8") as stream:
                existing = json.load(stream)
        except (OSError, json.JSONDecodeError) as exc:
            raise PreflightError(
                "BLOCKED_CONFIGURATION", f"existing session record is unreadable: {exc}"
            ) from exc
        if not isinstance(existing, dict):
            raise PreflightError(
                "BLOCKED_CONFIGURATION", "existing session record must be a JSON object"
            )
        return existing, False

    for directory in STANDARD_DIRECTORIES:
        (workspace / directory).mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": _now(),
        "target": target,
        "scenario": scenario,
        "mode": mode,
        "authorization_ref": _redact_authorization(authorization_ref),
        "resolved_skill_paths": skill_paths,
        "boundaries": {
            "in_scope": scope,
            "target": target,
            "active_target_access": False,
            "validation_only": True,
            "workspace": workspace.relative_to(ROOT).as_posix(),
        },
    }
    _atomic_write_json(session_path, record)
    return record, True


def _emit(result: str, **details: Any) -> None:
    payload: dict[str, Any] = {
        "status": "OK" if result == "OK" else "BLOCKED",
        "result": result,
        "code": result,
    }
    payload.update(details)
    print(json.dumps(payload, sort_keys=True))


def _dispatch_plan() -> tuple[dict[str, Any], list[str]]:
    """The collection dispatch plan, read from the canonical registry.

    MEASURED DEFECT: `.opencode/commands/hunt.md:45` says "The complete
    staged dispatch plan is authoritative in runtime/registry.json and is
    printed by scripts/runtime_preflight.py". MEASURED: the registry had no
    dispatch plan and the preflight printed nothing about it. The preflight
    is the hunt's BOOT step, so the plan it prints is the plan the
    orchestrator acts on.

    The plan is read from the registry, not restated here, so the preflight
    and the dispatcher cannot disagree about who runs.

    A missing or stale plan is REPORTED, not fatal here. The preflight's
    contract is to validate scope, authorization and skill resolution; the
    registry's own consistency is gated by `scripts/skill_registry.py check`,
    which exits non-zero on a missing `collection_agents` block. Blocking the
    whole boot here would also break a caller that uses the preflight purely
    to validate a scope — and MEASURED: the contract test in
    `scripts/test_runtime_contract.py` drives the preflight against a
    deliberately minimal fixture registry.

    Returns (plan, warnings).
    """
    warnings: list[str] = []
    try:
        registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        warnings.append(f"cannot read the registry for the dispatch plan: {exc}")
        return {"available": False, "stages": [], "max_concurrent": 3}, warnings

    block = registry.get("collection_agents")
    if not isinstance(block, dict) or not block:
        warnings.append(
            "runtime/registry.json has no collection_agents block; run "
            "`python scripts/skill_registry.py generate`")
        return {"available": False, "stages": [], "max_concurrent": 3}, warnings

    plan: list[dict[str, Any]] = []
    for role_key in ("recon-agent", "dorking-agent", "understand-agent",
                     "js-agent", "fuzzing-agent"):
        rec = block.get(role_key)
        if rec is None:
            warnings.append(
                f"runtime/registry.json does not declare the collection "
                f"agent {role_key!r}")
            continue
        plan.append({
            "role": role_key,
            "contact": rec.get("contact"),
            "waf_gated": bool(rec.get("waf_gated")),
            "max_spawns_per_session": rec.get("max_spawns_per_session"),
            "timeout_s": rec.get("timeout_s"),
            "exploit_capable": bool(rec.get("exploit_capable")),
        })

    return {
        "available": len(plan) == 5,
        "stages": plan,
        "max_concurrent": 3,
        "exploit_first": ("the orchestrator starts testing the first "
                          "value-bearing surface immediately; collection "
                          "results are consumed as they arrive"),
        "notes": ("collection agents are not exploiters — the orchestrator "
                  "performs all exploitation and validation"),
    }, warnings


def run_preflight(args: argparse.Namespace) -> int:
    try:
        target = args.target.strip() if isinstance(args.target, str) else ""
        if not _is_concrete_hostname(target):
            raise PreflightError(
                "BLOCKED_AUTHORIZATION",
                "target must be one exact concrete hostname (no URL, wildcard, or suffix inference)",
            )
        authorization_ref = _validate_authorization(args.authorization_ref)
        scope = _parse_scope(args.in_scope, target)
        workspace = _workspace_path(args.workspace)
        _validate_configuration()
        skill_paths = _resolve_skill_paths(args.scenario, args.mode)
        dispatch_plan, warnings = _dispatch_plan()

        session: dict[str, Any] | None = None
        created = False
        if args.ensure_session:
            session, created = _load_or_bootstrap_session(
                workspace,
                target=target,
                scenario=args.scenario,
                mode=args.mode,
                authorization_ref=authorization_ref,
                scope=scope,
                skill_paths=skill_paths,
            )

        result: dict[str, Any] = {
            "target": target,
            "scenario": args.scenario,
            "mode": args.mode,
            "workspace": workspace.relative_to(ROOT).as_posix(),
            "resolved_skill_paths": skill_paths,
            "dispatch_plan": dispatch_plan,
            "warnings": warnings,
            "boundaries": {
                "in_scope": scope,
                "target": target,
                "active_target_access": False,
                "validation_only": True,
            },
            "session_created": created,
        }
        if session is not None:
            result["session"] = session
        _emit("OK", **result)
        return 0
    except PreflightError as exc:
        _emit(exc.result, reason=exc.reason)
        return 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate scope/configuration and optionally bootstrap a local testing session."
    )
    parser.add_argument("--target", required=True, help="exact concrete target hostname")
    parser.add_argument("--scenario", required=True, help="surface used for skill resolution")
    parser.add_argument(
        "--mode",
        required=True,
        # MEASURED 2026-10-31 (operator-docs audit): `scan.md` and
        # `recon.md` invoke `--mode scan` / `--mode recon`, and both were
        # rejected here with "invalid choice". The mode vocabulary is now
        # the same one `scripts/skill_registry.py` accepts, so the two tools
        # cannot disagree about what a mode is -- and a command file that
        # names a mode the tools refuse is a broken invocation, not a doc
        # preference.
        choices=("hunt", "test", "report", "update", "learn", "scan", "recon"),
        help=("resolution mode — 'hunt'/'test'/'scan'/'recon' for the "
              "active-hunting pass, 'report' for validation and reporting, "
              "'update'/'learn' for the write-up intelligence pass"),
    )
    parser.add_argument(
        "--workspace", required=True, help="target workspace beneath testing/"
    )
    parser.add_argument(
        "--ensure-session", action="store_true", help="create local session metadata if absent"
    )
    parser.add_argument(
        "--authorization-ref", help="explicit authorization reference (ticket, contract, or approval id)"
    )
    parser.add_argument(
        "--in-scope", help="comma-separated exact hostnames explicitly authorized for testing"
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    return run_preflight(_parser().parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
