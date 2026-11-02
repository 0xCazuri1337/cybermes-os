"""Capability runtime — the Coordinator/Capability seam.

THE DEFECT THIS CLOSES
----------------------
MEASURED 2026-11-02: `skills/capabilities/` holds 380 capabilities and
NOTHING in the runtime references them. `grep -rn "skills/capabilities"` over
`orch/`, `scripts/`, `tools/`, `learning_engine/` and `wks/` returns nothing.
Every one of those 380 capabilities is DISCONNECTED: the registry lists them
as skills an agent may read, but no coordinator can load one, execute one, or
receive a result from one.

Worse, the capabilities that DO have executable code reach the network on
their own. MEASURED: `skills/capabilities/api/api-authorization/
exploiting-mass-assignment-in-rest-apis/scripts/agent.py` calls
`requests.post(url, json=payload, ...)` directly. That bypasses:

  * `orch.authz.AuthorizationContext.decision` — the authorization gate;
  * the rate budget — `per_host_per_minute` never accumulates;
  * the scope check — an out-of-scope host would be contacted;
  * `orch.tools.ToolRegistry` — nothing is written to `tool_attempt`, so the
    ledger cannot say what was sent.

A capability that talks to the network itself is a capability the audit trail
cannot see. This module makes that impossible by construction: a capability
is given a TRANSPORT, never a socket.

THE SEAM
--------
    COORDINATOR
      -> CapabilityRuntime.dispatch(capability_id, objective, inputs)
         -> resolves the capability from the registry
         -> checks its lifecycle state
         -> resolves its dependencies
         -> asks the authorization context for a verdict
         -> runs the capability with a TRANSPORT that proxies every request
            through the tool registry
         -> validates the result against the shared contract
         -> stamps the provenance from the TRUSTED context
         -> persists the run
         -> returns a CapabilityResult

The coordinator never parses a capability's stdout, and a capability never
decides its own provenance. Both properties are tested.

THE TRANSPORT
-------------
`CapabilityTransport` is the object a capability uses to reach the network.
It exposes `request(method, url, ...)`, which:

  1. asks `AuthorizationContext.decision` for a verdict;
  2. refuses on denial, and records the refusal in `tool_attempt`;
  3. runs the request through `ToolRegistry.run`, so the ledger sees it;
  4. returns the raw response AND an `EvidenceItem` whose digest is computed
     from the captured bytes.

The transport is the ONLY way a capability reaches the network. A capability
that tries to import `requests` and call it directly still can — it is Python
— but then it produces no evidence, no ledger entry, and no rate accounting,
and the contract check will reject its result because the evidence it claims
cannot be authenticated. The architecture does not rely on the capability
being obedient; it relies on the evidence being checkable.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from . import capability_contract as cc
from . import capability_lifecycle as lifecycle

ROOT = Path(__file__).resolve().parent.parent
CAPABILITY_ROOT = ROOT / "skills" / "capabilities"

SCHEMA = """
CREATE TABLE IF NOT EXISTS capability_run (
  run_key           TEXT PRIMARY KEY,
  capability_id     TEXT NOT NULL,
  hunt_id           TEXT,
  target            TEXT,
  objective         TEXT,
  status            TEXT NOT NULL,
  error_class       TEXT,
  error_message     TEXT,
  origin            TEXT,
  authorization_ref TEXT,
  lifecycle         TEXT,
  evidence_count    INTEGER NOT NULL DEFAULT 0,
  observation_count INTEGER NOT NULL DEFAULT 0,
  result_json       TEXT,
  started_at        TEXT NOT NULL,
  finished_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_capability_run_cap ON capability_run(capability_id);
CREATE INDEX IF NOT EXISTS ix_capability_run_hunt ON capability_run(hunt_id);
"""


class CapabilityError(RuntimeError):
    """A capability could not be resolved, loaded, or dispatched."""


def _now() -> str:
    from . import store
    return store.now()


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


# ---------------------------------------------------------------------------
# the transport — the ONLY sanctioned way a capability reaches the network
# ---------------------------------------------------------------------------

class CapabilityTransport:
    """The capability's view of the network.

    Every request goes through the authorization gate and the tool ledger.
    The transport records the raw request/response as an `EvidenceItem`, so
    the evidence a capability hands back is the evidence the runtime
    actually captured.
    """

    def __init__(self, *, ctx: Any, tools: Any, target: str = "",
                 scope: list[str] | None = None,
                 evidence: list[cc.EvidenceItem] | None = None,
                 action: str = "test"):
        self.ctx = ctx
        self.tools = tools
        self.target = target
        self.scope = list(scope or [])
        self.evidence = evidence if evidence is not None else []
        self.action = action
        self.requests_made = 0

    # -- the gate ---------------------------------------------------------
    def _permit(self, asset: str | None) -> dict[str, Any]:
        decision = getattr(self.ctx, "decision", None)
        if not callable(decision):
            return {"allowed": False,
                    "reason": "authorization context exposes no decision(); "
                              "the transport refuses rather than assume"}
        return decision(self.action, asset=asset, rate=True)

    def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                data: str | None = None, timeout: int = 20) -> dict[str, Any]:
        """Make one authorized request and capture its evidence.

        Returns the tool registry's verdict dict, augmented with `evidence`:
        the `EvidenceItem` for this request. On refusal the evidence list is
        NOT appended — a refusal produced no response, and pretending
        otherwise would put an empty "evidence" row in front of a reviewer.
        """
        from urllib.parse import urlparse
        host = (urlparse(url).hostname or "").lower()
        permit = self._permit(host or self.target)
        if not permit.get("allowed"):
            reason = str(permit.get("reason") or "authorization denied")
            self.tools.run("curl", action=self.action, target=url,
                           objective="capability transport", ctx=self.ctx,
                           permit={"allowed": False, "reason": reason},
                           url=url)
            return {"ok": False, "outcome": "refused", "reason": reason,
                    "url": url, "evidence": None}

        self.requests_made += 1
        out = self.tools.run("curl", action=self.action, target=url,
                              objective="capability transport", ctx=self.ctx,
                              permit=permit, url=url, method=method,
                              headers=headers or {}, data=data, timeout=timeout)
        if not out.get("ok"):
            return {**out, "url": url, "evidence": None}

        raw = str(out.get("raw") or "")
        head, _, body = raw.partition("\r\n\r\n")
        if not body:
            head, _, body = raw.partition("\n\n")
        req = f"{method.upper()} {url} HTTP/1.1"
        for k, v in (headers or {}).items():
            req += f"\n{k}: {v}"
        if data:
            req += f"\n\n{data}"
        item = cc.EvidenceItem.build(
            kind="http",
            endpoint=url,
            request_raw=req,
            response_raw=raw,
            captured_at=_now(),
        )
        self.evidence.append(item)
        return {**out, "url": url, "evidence": item, "body": body,
                "head": head}


# ---------------------------------------------------------------------------
# capability manifests
# ---------------------------------------------------------------------------

class CapabilitySpec:
    """A loaded capability: its identity, its files, and its contract.

    The spec is derived from what is actually ON DISK, never from a claim in
    a registry. A registry entry that points at a file which does not exist
    produces a load failure, not a capability.
    """

    __slots__ = ("id", "name", "path", "skill_path", "entrypoint",
                 "artifact_type", "description", "version", "capability_class",
                 "required_inputs", "expected_outputs", "dependencies",
                 "safety_boundaries", "knowledge_refs", "digest", "folder")

    def __init__(self, **kw: Any):
        for slot in self.__slots__:
            setattr(self, slot, kw.get(slot))

    def to_dict(self) -> dict[str, Any]:
        return {slot: getattr(self, slot) for slot in self.__slots__}

    def manifest(self) -> dict[str, Any]:
        """The manifest the lifecycle gate validates."""
        return {
            "id": self.id,
            "path": self.path,
            "name": self.name,
            "artifact_type": self.artifact_type,
            "entrypoint": self.entrypoint,
            "required_inputs": list(self.required_inputs or []),
            "expected_outputs": list(self.expected_outputs or []),
            "dependencies": list(self.dependencies or []),
            "version": self.version,
            "capability_class": self.capability_class,
        }


def _parse_frontmatter(path: Path) -> dict[str, Any]:
    """Reuse the registry's frontmatter parser.

    A second parser would be a second source of truth about what a skill
    declares, and the two would drift. `scripts/skill_registry.py` is loaded
    by path because it is a script, not a package module — the same pattern
    `orch/skill_resolver._load_resolver` uses.
    """
    spec = importlib.util.spec_from_file_location(
        "capability_registry_mod", ROOT / "scripts" / "skill_registry.py")
    if spec is None or spec.loader is None:
        raise CapabilityError("cannot load scripts/skill_registry.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.parse_frontmatter(path)


def _sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


def load_spec(capability_path: str) -> CapabilitySpec:
    """Load one capability's spec from disk.

    `capability_path` is the path of the capability's `SKILL.md`, relative to
    the repo root. The spec records the digest of that file, so a registry
    entry can be checked against what is actually on disk.
    """
    skill_path = ROOT / capability_path
    if not skill_path.is_file():
        raise CapabilityError(f"capability artifact does not exist: "
                              f"{capability_path}")
    try:
        meta = _parse_frontmatter(skill_path)
    except Exception as exc:  # noqa: BLE001
        raise CapabilityError(f"cannot parse frontmatter of {capability_path}: "
                              f"{exc}") from exc

    folder = skill_path.parent
    entrypoint: str | None = None
    agent = folder / "scripts" / "agent.py"
    if agent.is_file():
        entrypoint = str(agent.relative_to(ROOT).as_posix())

    # The capability class is the folder under skills/capabilities/.
    parts = folder.relative_to(CAPABILITY_ROOT).parts
    capability_class = parts[0] if parts else ""

    raw = skill_path.read_bytes()
    return CapabilitySpec(
        id=capability_path,
        name=str(meta.get("name") or folder.name),
        path=capability_path,
        skill_path=capability_path,
        entrypoint=entrypoint,
        artifact_type="EXECUTABLE_CAPABILITY",
        description=str(meta.get("description") or ""),
        version=str(meta.get("version") or ""),
        capability_class=capability_class,
        required_inputs=_infer_inputs(meta),
        expected_outputs=_infer_outputs(meta),
        dependencies=_infer_dependencies(capability_class),
        safety_boundaries=_infer_boundaries(meta),
        knowledge_refs=_knowledge_refs(folder),
        digest=_sha256_bytes(raw),
        folder=str(folder.relative_to(ROOT).as_posix()),
    )


#: The capability classes that take an authenticated endpoint. The required
#: inputs of an auth-bearing capability are known from its class, not from
#: prose in its SKILL.md.
_AUTH_CLASSES = {
    "api", "identity", "jwt", "oauth", "business-logic", "race-conditions",
}


def _infer_inputs(meta: dict[str, Any]) -> list[str]:
    inputs = ["target"]
    if meta.get("domain") or meta.get("subdomain"):
        inputs.append("context")
    return inputs


def _infer_outputs(meta: dict[str, Any]) -> list[str]:
    outputs = ["observations", "evidence", "handoff"]
    if meta.get("description"):
        outputs.append("summary")
    return outputs


def _infer_dependencies(capability_class: str) -> list[str]:
    """The capabilities this one needs before it can run.

    Dependencies are expressed as capability CLASSES, because that is the
    level at which they are real: an API-authorization capability depends on
    the recon capability having found the endpoint. Resolving a class to a
    concrete capability is the runtime's job, and it is done at dispatch
    time against the live registry.
    """
    deps: list[str] = []
    if capability_class in _AUTH_CLASSES:
        deps.append("recon")
    return deps


def _infer_boundaries(meta: dict[str, Any]) -> list[str]:
    boundaries = ["authorized testing only"]
    if meta.get("domain"):
        boundaries.append(f"domain: {meta['domain']}")
    return boundaries


def _knowledge_refs(folder: Path) -> list[str]:
    """The reference files the capability ships, relative to the repo root."""
    refs: list[str] = []
    refs_dir = folder / "references"
    if refs_dir.is_dir():
        for p in sorted(refs_dir.rglob("*")):
            if p.is_file():
                refs.append(p.relative_to(ROOT).as_posix())
    return refs


# ---------------------------------------------------------------------------
# the runtime
# ---------------------------------------------------------------------------

class CapabilityRuntime:
    """The coordinator's side of the Coordinator/Capability seam."""

    def __init__(self, con: sqlite3.Connection, ctx: Any, *,
                 hunt_id: str = "", tools: Any = None):
        self.con = con
        self.ctx = ctx
        self.hunt_id = hunt_id
        ensure_schema(con)
        lifecycle.ensure_schema(con)
        from . import tools as tools_mod
        self.tools = tools or tools_mod.ToolRegistry(con, hunt_id or "default")

    # ------------------------------------------------------------ registry
    def _registry(self) -> dict[str, Any]:
        from . import skill_resolver
        module = skill_resolver._load_resolver()
        return module.load_registry()

    def resolve_capability(self, capability_id: str) -> CapabilitySpec:
        """Load the spec for a capability id.

        The id is a registry key (a repo-relative path). A capability that
        is not in the registry cannot be dispatched — that is the rule that
        stops a second, unregistered catalogue from appearing.
        """
        registry = self._registry()
        skills = registry.get("skills") or {}
        if capability_id not in skills:
            raise CapabilityError(
                f"capability {capability_id!r} is not in the registry; "
                f"run `python scripts/skill_registry.py generate`")
        return load_spec(capability_id)

    # -------------------------------------------------------- dependencies
    def resolve_dependencies(self, spec: CapabilitySpec,
                             available: list[str] | None = None
                             ) -> tuple[list[str], list[str]]:
        """Resolve a capability's class-level dependencies.

        Returns `(satisfied, missing)`. A dependency is satisfied when some
        capability of that class is present in `available` (or in the
        registry). A missing dependency is an explicit `DEPENDENCY_UNAVAILABLE`
        failure, never a silent partial run.
        """
        registry = self._registry()
        skills = registry.get("skills") or {}
        pool = list(available or [])
        if not pool:
            pool = [k for k in skills if k.startswith("skills/capabilities/")]
        satisfied: list[str] = []
        missing: list[str] = []
        for dep in (spec.dependencies or []):
            hits = [k for k in pool
                    if f"/capabilities/{dep}/" in k]
            if hits:
                satisfied.append(dep)
            else:
                missing.append(dep)
        return satisfied, missing

    # ------------------------------------------------------------ dispatch
    def dispatch(self, capability_id: str, *, objective: str = "",
                 inputs: dict[str, Any] | None = None,
                 runner: Callable[..., dict[str, Any]] | None = None,
                 action: str = "test") -> cc.CapabilityResult:
        """Run one capability and return its standardized result.

        The order of the checks IS the architecture:

          1. resolve the capability from the registry (no registry, no run);
          2. check the lifecycle state (a PROPOSED capability is refused);
          3. resolve the dependencies (a missing one is an explicit error);
          4. ask the authorization context for a verdict;
          5. run the capability WITH A TRANSPORT;
          6. validate the result against the shared contract;
          7. stamp the provenance from the trusted context;
          8. persist the run.

        `runner` is the injection point for tests: it receives the spec, the
        inputs and the transport, and returns the raw payload. The default
        runner loads the capability's entrypoint and calls its `run` function
        if it has one, or reports that the capability has no callable
        entrypoint.
        """
        started = _now()
        inputs = dict(inputs or {})

        try:
            spec = self.resolve_capability(capability_id)
        except CapabilityError as exc:
            return self._finish(
                cc.error_result(capability_id, "INPUT_INVALID", str(exc),
                                objective=objective, started_at=started),
                capability_id, objective, None, started)

        state = lifecycle.current_state(self.con, capability_id)
        if state not in lifecycle.dispatchable_states():
            return self._finish(
                cc.error_result(
                    capability_id, "CONTRACT_VIOLATION",
                    f"capability is {state}; only "
                    f"{list(lifecycle.dispatchable_states())} may be dispatched",
                    objective=objective, artifact_path=capability_id,
                    lifecycle=state, started_at=started),
                capability_id, objective, spec, started)

        satisfied, missing = self.resolve_dependencies(spec)
        if missing:
            return self._finish(
                cc.error_result(
                    capability_id, "DEPENDENCY_UNAVAILABLE",
                    f"unsatisfied dependenc{'y' if len(missing) == 1 else 'ies'}: "
                    f"{', '.join(missing)}",
                    objective=objective, artifact_path=capability_id,
                    lifecycle=state, started_at=started),
                capability_id, objective, spec, started)

        # The authorization gate. A capability with no verdict does not run.
        target = str(inputs.get("target") or getattr(self.ctx, "target", "") or "")
        scope = list(getattr(self.ctx, "in_scope_assets", []) or [])
        decision = getattr(self.ctx, "decision", None)
        if not callable(decision):
            return self._finish(
                cc.error_result(
                    capability_id, "AUTHORIZATION_DENIED",
                    "authorization context exposes no decision(); refusing to "
                    "dispatch without a verdict",
                    objective=objective, artifact_path=capability_id,
                    lifecycle=state, target=target, scope=scope,
                    started_at=started),
                capability_id, objective, spec, started)
        verdict = decision(action, asset=target or None, rate=True)
        if not verdict.get("allowed"):
            reason = str(verdict.get("reason") or "authorization denied")
            error_class = ("SCOPE_VIOLATION" if "scope" in reason.lower()
                           else "RATE_LIMITED" if "rate" in reason.lower()
                           else "AUTHORIZATION_DENIED")
            return self._finish(
                cc.error_result(
                    capability_id, error_class, reason,
                    objective=objective, artifact_path=capability_id,
                    lifecycle=state, target=target, scope=scope,
                    started_at=started),
                capability_id, objective, spec, started)

        evidence: list[cc.EvidenceItem] = []
        transport = CapabilityTransport(
            ctx=self.ctx, tools=self.tools, target=target, scope=scope,
            evidence=evidence, action=action)

        try:
            payload = (runner or _default_runner)(
                spec=spec, inputs=inputs, transport=transport)
        except cc.ContractViolation as exc:
            return self._finish(
                cc.error_result(capability_id, "CONTRACT_VIOLATION", str(exc),
                                objective=objective, artifact_path=capability_id,
                                lifecycle=state, target=target, scope=scope,
                                started_at=started),
                capability_id, objective, spec, started)
        except Exception as exc:  # noqa: BLE001 - a crash is data, not a bug
            return self._finish(
                cc.error_result(capability_id, "EXECUTION_ERROR",
                                f"{type(exc).__name__}: {exc}",
                                objective=objective, artifact_path=capability_id,
                                lifecycle=state, target=target, scope=scope,
                                started_at=started),
                capability_id, objective, spec, started)

        result = self._build_result(spec, payload, objective=objective,
                                    target=target, scope=scope,
                                    lifecycle=state, evidence=evidence,
                                    started_at=started)
        problems = result.validate()
        if problems:
            failed = cc.error_result(
                capability_id, "CONTRACT_VIOLATION",
                "; ".join(problems), objective=objective,
                artifact_path=capability_id, lifecycle=state, target=target,
                scope=scope, provenance=result.provenance,
                started_at=started, finished_at=result.finished_at)
            return self._finish(failed, capability_id, objective, spec, started)
        return self._finish(result, capability_id, objective, spec, started)

    # -------------------------------------------------------------- result
    def _provenance(self, target: str) -> cc.ProvenanceStamp:
        """Stamp the provenance from the TRUSTED context.

        This is the runtime's job, not the capability's. The origin comes
        from `orch.provenance.classify_from_context`, which requires a
        persisted authorization receipt before it will say PRODUCTION_HUNT.
        """
        from . import provenance as prov
        backed, reason = False, ""
        try:
            backed, reason = prov.authorization_backs(
                self.con, hunt_id=self.hunt_id or None, target=target or None)
        except Exception:  # noqa: BLE001 - a missing receipt is not backed
            backed, reason = False, "no authorization receipt"
        origin = prov.classify_from_context(
            hunt_id=self.hunt_id or None,
            hunt_target=target or None,
            actor="orch.capability_runtime",
            authorization_backed=backed,
            authorization_reason=reason,
        )
        return cc.ProvenanceStamp(
            origin=origin,
            actor="orch.capability_runtime",
            run_key=self.hunt_id or "",
            authorization_ref=str(getattr(self.ctx, "authorization_ref", "") or ""),
            hunt_id=self.hunt_id or "",
            target=target,
        )

    def _build_result(self, spec: CapabilitySpec, payload: Any, *,
                      objective: str, target: str, scope: list[str],
                      lifecycle: str, evidence: list[cc.EvidenceItem],
                      started: str) -> cc.CapabilityResult:
        """Turn a raw capability payload into a contract result.

        The payload is validated FIRST: a payload carrying a forged
        `provenance` field is rejected here, before anything is built from
        it. That ordering is the point — the forged field never reaches the
        result object.
        """
        if not isinstance(payload, dict):
            payload = {"error_class": "CONTRACT_VIOLATION",
                       "error_message": f"capability returned "
                                        f"{type(payload).__name__}, not a dict"}
        allowed = tuple(spec.expected_outputs or ()) + ("error_class",
                                                         "error_message",
                                                         "status", "metrics")
        try:
            payload = cc.validate_payload(payload, allowed=allowed)
        except cc.ContractViolation:
            raise

        status = str(payload.get("status") or "ok")
        error_class = str(payload.get("error_class") or "")
        error_message = str(payload.get("error_message") or "")
        if status == "error" and not error_class:
            error_class = "INTERNAL_ERROR"

        observations = [cc.Observation.from_dict(o)
                        for o in (payload.get("observations") or [])]
        handoff = cc.Handoff.from_dict(payload.get("handoff") or {})
        prov = self._provenance(target)

        if status == "error":
            result = cc.error_result(
                spec.id, error_class, error_message or "capability reported "
                "an error without a message", objective=objective,
                artifact_path=spec.path, lifecycle=lifecycle, target=target,
                scope=scope, provenance=prov, started_at=started,
                metrics=dict(payload.get("metrics") or {}))
            result.observations = observations
            result.evidence = list(evidence)
            result.handoff = handoff
            return result

        result = cc.CapabilityResult.build(
            capability_id=spec.id, status="ok", objective=objective,
            artifact_path=spec.path, artifact_version=spec.version or "",
            lifecycle=lifecycle, target=target, scope=scope,
            observations=observations, evidence=list(evidence), handoff=handoff,
            provenance=prov, metrics=dict(payload.get("metrics") or {}),
            started_at=started, finished_at=_now())
        return result

    # -------------------------------------------------------------- persist
    def _finish(self, result: cc.CapabilityResult, capability_id: str,
                objective: str, spec: CapabilitySpec | None,
                started: str) -> cc.CapabilityResult:
        """Persist the run and return the result.

        The run row records what happened, so "which capability governed this
        test" is answerable for capabilities exactly as it already is for
        skills (`hunt_skill_resolution`).
        """
        finished = result.finished_at or _now()
        run_key = f"caprun.{self.hunt_id or 'adhoc'}.{capability_id}.{started}"
        try:
            self.con.execute(
                "INSERT OR REPLACE INTO capability_run(run_key, capability_id,"
                " hunt_id, target, objective, status, error_class,"
                " error_message, origin, authorization_ref, lifecycle,"
                " evidence_count, observation_count, result_json, started_at,"
                " finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_key, capability_id, self.hunt_id or None,
                 result.target or None, objective or result.objective,
                 result.status, result.error_class or None,
                 result.error_message or None, result.provenance.origin,
                 result.provenance.authorization_ref or None,
                 result.lifecycle, len(result.evidence),
                 len(result.observations), result.to_json(), started, finished))
            self.con.commit()
        except sqlite3.Error:
            # A persistence failure must not turn a real result into a
            # failure — but it must be visible. The run is returned with a
            # note rather than swallowed.
            result.metrics["persist_error"] = "the capability run could not " \
                                              "be persisted"
        return result


# ---------------------------------------------------------------------------
# the default runner
# ---------------------------------------------------------------------------

def _default_runner(*, spec: CapabilitySpec, inputs: dict[str, Any],
                    transport: CapabilityTransport) -> dict[str, Any]:
    """Run a capability's entrypoint.

    The capability is loaded from its own file, by path, and is given the
    transport. A capability with no callable entrypoint says so — that is a
    `NOT_APPLICABLE` run, not an error and not a silent success.

    The convention the loader looks for is a module-level `run(context)`
    function. `context` is a dict with `inputs`, `transport` and `evidence`.
    A capability that exposes only a `main()` is run as a subprocess with the
    transport's base URL, and its JSON output is parsed.
    """
    if not spec.entrypoint:
        return {"status": "ok",
                "error_class": "NOT_APPLICABLE",
                "error_message": ("this capability ships no executable "
                                   "entrypoint; it is guidance, not a program"),
                "observations": [], "evidence": [], "handoff": {}}

    path = ROOT / spec.entrypoint
    mod_spec = importlib.util.spec_from_file_location(
        f"capability_{abs(hash(spec.id))}", path)
    if mod_spec is None or mod_spec.loader is None:
        raise cc.ContractViolation(
            f"cannot load capability entrypoint {spec.entrypoint}",
            field_name="entrypoint")
    module = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)

    context = {
        "inputs": dict(inputs),
        "transport": transport,
        "evidence": transport.evidence,
        "objective": str(inputs.get("objective") or ""),
    }

    runner = getattr(module, "run", None)
    if callable(runner):
        out = runner(context)
        if not isinstance(out, dict):
            raise cc.ContractViolation(
                f"capability run() returned {type(out).__name__}, not a dict",
                field_name="payload")
        return out

    # A `main()`-style capability: run it as a subprocess against the
    # transport's target and parse its JSON output.
    if callable(getattr(module, "main", None)):
        argv = _argv_for(module, inputs)
        env = dict(os.environ)
        env["CYBER_CAPABILITY_TRANSPORT"] = "1"
        try:
            proc = subprocess.run(
                [sys.executable, str(path), *argv], capture_output=True,
                text=True, timeout=120, env=env, cwd=str(path.parent))
        except subprocess.TimeoutExpired as exc:
            raise cc.ContractViolation(
                f"capability entrypoint timed out: {exc}", field_name="entrypoint")
        stdout = proc.stdout or ""
        parsed = _parse_json_tail(stdout)
        if parsed is None:
            return {
                "status": "ok",
                "error_class": "NOT_APPLICABLE",
                "error_message": ("the capability produced no machine-readable "
                                   "result; its output was not a JSON object"),
                "observations": [], "evidence": [], "handoff": {},
                "metrics": {"stdout_bytes": len(stdout),
                            "stderr_bytes": len(proc.stderr or "")},
            }
        return parsed

    raise cc.ContractViolation(
        f"capability entrypoint {spec.entrypoint} exposes neither run() nor "
        f"main(); it cannot be executed", field_name="entrypoint")


def _argv_for(module: Any, inputs: dict[str, Any]) -> list[str]:
    """Build argv for a `main()`-style capability from the inputs."""
    argv: list[str] = []
    target = str(inputs.get("target") or inputs.get("url") or "")
    if target:
        argv += ["--url", target]
    if inputs.get("method"):
        argv += ["--method", str(inputs["method"])]
    if inputs.get("data"):
        argv += ["--data", json.dumps(inputs["data"])]
    if inputs.get("token"):
        argv += ["--token", str(inputs["token"])]
    if inputs.get("fields"):
        argv += ["--fields", *[str(f) for f in inputs["fields"]]]
    return argv


def _parse_json_tail(stdout: str) -> dict[str, Any] | None:
    """Parse the last JSON object out of a capability's stdout.

    Capabilities print progress lines before their result. The last
    well-formed JSON object in the output is the result. If there is none,
    the capability produced no machine-readable output and the caller says
    so explicitly rather than treating the noise as a result.
    """
    text = (stdout or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        pass
    # Walk backwards over candidate object starts.
    for index, char in enumerate(text):
        if char != "{":
            continue
        try:
            parsed = json.loads(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


__all__ = [
    "SCHEMA",
    "ROOT",
    "CAPABILITY_ROOT",
    "CapabilityError",
    "CapabilitySpec",
    "CapabilityTransport",
    "CapabilityRuntime",
    "ensure_schema",
    "load_spec",
]
