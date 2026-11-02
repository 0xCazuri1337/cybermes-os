"""Shared Evidence Contract — the wire format between a capability and a coordinator.

WHY THIS EXISTS
---------------
The capability corpus in this repository is 380 `scripts/agent.py` files that
each grew their own CLI. MEASURED: of the first 60, 46 had `argparse` and 14
had no argument parser at all; the flags they accepted had almost nothing in
common (`--output` appeared 33 times, `--url` 15, `--token` 10, and the rest
were singletons). Two facts follow from that:

  1. A coordinator cannot call them uniformly, so it never did.
  2. They speak for themselves on the network. The mass-assignment capability
     calls `requests.post` directly. That bypasses `orch.authz`, the rate
     budget, the scope check, and the tool ledger — the four things that make
     a request belong to an engagement.

A contract is the only thing that fixes both at once: every capability returns
the SAME shape, and every capability reaches the network THROUGH the runtime
rather than around it.

WHAT THE CONTRACT GUARANTEES
-----------------------------
  * Raw evidence is authentic — the digests are computed from the bytes the
    runtime actually captured, never from a value the capability supplied.
  * Provenance is correct — provenance is stamped by the trusted runtime from
    the validated execution context. A capability that supplies its own
    `provenance` field cannot forge `PRODUCTION_HUNT`; the field is REJECTED,
    not overwritten, so the attempt is visible.
  * Handoffs are structured — a capability declares what it produced and what
    the next step needs, and the coordinator reads that rather than guessing.
  * Failures are explicit — an error carries a class from a FIXED vocabulary,
    so "the capability failed" and "the capability found nothing" are
    distinguishable. A clean negative is NOT an error.
  * Nothing auto-promotes — the contract carries a candidate result. Whether
    that becomes a finding is decided by `orch.validate`, which this module
    never calls and never bypasses.

CONVENTIONS
-----------
This repository uses plain dicts as the wire format, dataclasses for payloads,
and tuple vocabularies for enumerations — there is no `Enum` anywhere in
`orch/`. This module follows that convention exactly. `to_dict()` on each
dataclass produces the wire form; `from_dict()` reads it back.

The contract version is `capability-evidence/v1`. A change to the field set
is a new version, not a silent reinterpretation.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# vocabularies (fixed tuples, matching the repo's convention)
# ---------------------------------------------------------------------------

CONTRACT_VERSION = "capability-evidence/v1"

#: The five artifact types. A capability is ONE of them, decided by evidence
#: about the file — never by the directory it happens to live in.
ARTIFACT_TYPES = (
    "EXECUTABLE_CAPABILITY",
    "KNOWLEDGE_RESOURCE",
    "PROCEDURE",
    "WORKFLOW",
    "TOOL_INTEGRATION",
    "COORDINATOR",
)

#: Capability lifecycle. Deliberately separate from finding validity: a
#: capability can be ACTIVE while every finding it ever produced was rejected,
#: and a finding can be VALIDATED that was found by a deprecated capability.
LIFECYCLE_STATES = (
    "PROPOSED",
    "VALIDATED",
    "ACTIVE",
    "DEPRECATED",
)

#: Allowed lifecycle transitions. `PROPOSED -> ACTIVE` is absent on purpose:
#: a capability that skips validation was never validated.
LIFECYCLE_TRANSITIONS = {
    "PROPOSED": ("VALIDATED", "DEPRECATED"),
    "VALIDATED": ("ACTIVE", "PROPOSED", "DEPRECATED"),
    "ACTIVE": ("DEPRECATED",),
    "DEPRECATED": (),
}

#: Terminal status of a capability run.
RUN_STATUSES = (
    "ok",          # ran, produced evidence (possibly a clean negative)
    "error",       # refused, failed, or violated the contract
)

#: The FIXED error vocabulary. A capability that fails says WHICH of these
#: it hit. `NOT_APPLICABLE` and `NO_SIGNAL` are NOT errors — they are
#: successful runs with nothing to report, and conflating them with failure
#: is how a hunt ends up reporting failures it never had.
ERROR_CLASSES = (
    "AUTHORIZATION_DENIED",
    "SCOPE_VIOLATION",
    "RATE_LIMITED",
    "INPUT_INVALID",
    "CONTRACT_VIOLATION",
    "DEPENDENCY_UNAVAILABLE",
    "DEPENDENCY_FAILED",
    "TOOL_UNAVAILABLE",
    "EXECUTION_ERROR",
    "TIMEOUT",
    "NOT_APPLICABLE",
    "INTERNAL_ERROR",
)

#: Capability permission levels, borrowed from `orch.store.CAPABILITY_LEVELS`
#: because they already exist there and a second vocabulary would drift.
CAPABILITY_LEVELS = ("READ", "ANALYZE", "WRITE", "EXECUTE", "DESTRUCTIVE")

#: The levels a capability may declare. A capability that declares EXECUTE
#: reaches the network; one that declares only READ/ANALYZE may not.
DECLARABLE_LEVELS = ("READ", "ANALYZE", "EXECUTE")

_SECRET_KEY = re.compile(
    r"(authorization|cookie|set-cookie|api[-_]?key|token|secret|password|"
    r"session|bearer)", re.IGNORECASE)


def _digest(data: bytes | str) -> str:
    """SHA-256 of the exact bytes. Never of a normalised rendering."""
    if isinstance(data, str):
        data = data.encode("utf-8", "surrogatepass")
    return hashlib.sha256(data).hexdigest()


def redact(value: str) -> str:
    """Redact obvious credentials from a header block.

    Evidence is stored and shared; a raw Authorization header in an evidence
    row is a credential in a database. Redaction happens at capture time so
    the secret is never persisted in the first place.
    """
    out: list[str] = []
    for line in (value or "").splitlines():
        if ":" not in line:
            out.append(line)
            continue
        name, _, rest = line.partition(":")
        if _SECRET_KEY.search(name):
            out.append(f"{name}: [REDACTED]")
        else:
            out.append(f"{name}:{rest}")
    return "\n".join(out)


class ContractViolation(ValueError):
    """A capability produced an artifact that does not satisfy the contract.

    This is a `ValueError` subclass because the repository's other contract
    errors are (`agentkit.ResultContractError` is a `ValueError`). The
    violation carries the field that broke so the coordinator can say WHICH
    rule failed rather than "invalid result".
    """

    def __init__(self, message: str, *, field_name: str = ""):
        super().__init__(message)
        self.field_name = field_name


# ---------------------------------------------------------------------------
# payload dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EvidenceItem:
    """One captured request/response pair.

    The digests are computed by the runtime from the bytes it captured. A
    capability cannot supply them: `EvidenceItem.build()` computes them, and
    the constructor takes the already-captured bytes.

    `request_raw`/`response_raw` are the REDACTED renderings; `sha256` is the
    digest of the redacted bytes that are actually stored, so a verifier can
    recompute it from what is in the row.
    """

    kind: str
    endpoint: str
    request_raw: str = ""
    response_raw: str = ""
    payload: str = ""
    captured_at: str = ""
    sha256: str = ""
    content_type: str = ""

    @classmethod
    def build(cls, *, kind: str, endpoint: str, request_raw: str = "",
              response_raw: str = "", payload: str = "",
              captured_at: str = "", content_type: str = "") -> "EvidenceItem":
        """Construct an item whose digest is computed from the stored bytes."""
        req = redact(request_raw)
        resp = redact(response_raw)
        blob = req + "\n--\n" + resp
        return cls(kind=kind, endpoint=endpoint, request_raw=req,
                   response_raw=resp, payload=payload,
                   captured_at=captured_at, sha256=_digest(blob),
                   content_type=content_type)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "endpoint": self.endpoint,
            "request_raw": self.request_raw,
            "response_raw": self.response_raw,
            "payload": self.payload,
            "captured_at": self.captured_at,
            "sha256": self.sha256,
            "content_type": self.content_type,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EvidenceItem":
        return cls(
            kind=str(raw.get("kind") or ""),
            endpoint=str(raw.get("endpoint") or ""),
            request_raw=str(raw.get("request_raw") or ""),
            response_raw=str(raw.get("response_raw") or ""),
            payload=str(raw.get("payload") or ""),
            captured_at=str(raw.get("captured_at") or ""),
            sha256=str(raw.get("sha256") or ""),
            content_type=str(raw.get("content_type") or ""),
        )


@dataclass
class ProvenanceStamp:
    """Where a result came from, and what that permits.

    The fields here are stamped by the TRUSTED runtime from the validated
    execution context. `origin` is one of `orch.provenance.ALL_PROVENANCE`.
    A capability-supplied provenance field is rejected before this is built —
    see `CapabilityResult.build`.
    """

    origin: str = "UNKNOWN"
    actor: str = ""
    run_key: str = ""
    authorization_ref: str = ""
    hunt_id: str = ""
    target: str = ""
    validator_run: str = ""
    claimed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "actor": self.actor,
            "run_key": self.run_key,
            "authorization_ref": self.authorization_ref,
            "hunt_id": self.hunt_id,
            "target": self.target,
            "validator_run": self.validator_run,
            "claimed": self.claimed,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ProvenanceStamp":
        return cls(
            origin=str(raw.get("origin") or "UNKNOWN"),
            actor=str(raw.get("actor") or ""),
            run_key=str(raw.get("run_key") or ""),
            authorization_ref=str(raw.get("authorization_ref") or ""),
            hunt_id=str(raw.get("hunt_id") or ""),
            target=str(raw.get("target") or ""),
            validator_run=str(raw.get("validator_run") or ""),
            claimed=bool(raw.get("claimed")),
        )


@dataclass
class Handoff:
    """What this capability produced, and what the next step needs.

    The coordinator reads the handoff instead of inferring the shape of the
    result. `consumes` names the inputs a downstream capability needs, so a
    missing input is an explicit failure rather than a silent misrouting.
    """

    artifact: str = ""
    produces: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    next_hint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": self.artifact,
            "produces": list(self.produces),
            "consumes": list(self.consumes),
            "next_hint": self.next_hint,
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Handoff":
        return cls(
            artifact=str(raw.get("artifact") or ""),
            produces=[str(x) for x in (raw.get("produces") or [])],
            consumes=[str(x) for x in (raw.get("consumes") or [])],
            next_hint=str(raw.get("next_hint") or ""),
            metadata=dict(raw.get("metadata") or {}),
        )


@dataclass
class Observation:
    """A structured observation produced by a capability.

    An observation is NOT a finding. It is the input the coordinator hands to
    the existing finding-validation path, which decides what happens next.
    """

    statement: str
    kind: str = "observation"
    class_id: str = ""
    confidence: float = 0.0
    signals: list[str] = field(default_factory=list)
    endpoint: str = ""
    evidence_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "statement": self.statement,
            "kind": self.kind,
            "class_id": self.class_id,
            "confidence": round(float(self.confidence), 4),
            "signals": list(self.signals),
            "endpoint": self.endpoint,
            "evidence_refs": list(self.evidence_refs),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Observation":
        return cls(
            statement=str(raw.get("statement") or ""),
            kind=str(raw.get("kind") or "observation"),
            class_id=str(raw.get("class_id") or ""),
            confidence=float(raw.get("confidence") or 0.0),
            signals=[str(x) for x in (raw.get("signals") or [])],
            endpoint=str(raw.get("endpoint") or ""),
            evidence_refs=[str(x) for x in (raw.get("evidence_refs") or [])],
            metadata=dict(raw.get("metadata") or {}),
        )


# ---------------------------------------------------------------------------
# the result artifact
# ---------------------------------------------------------------------------

@dataclass
class CapabilityResult:
    """The standardized result every capability returns.

    This is the whole point of the module: one shape, one vocabulary, one
    validation rule. A coordinator can consume any capability's result
    without knowing which capability produced it.
    """

    capability_id: str
    status: str = "ok"
    error_class: str = ""
    error_message: str = ""
    objective: str = ""
    artifact_path: str = ""
    artifact_version: str = ""
    lifecycle: str = "PROPOSED"
    target: str = ""
    scope: list[str] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    handoff: Handoff = field(default_factory=Handoff)
    provenance: ProvenanceStamp = field(default_factory=ProvenanceStamp)
    metrics: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    finished_at: str = ""
    contract_version: str = CONTRACT_VERSION

    # ---------------------------------------------------------------- build
    @classmethod
    def build(cls, *, capability_id: str, status: str = "ok",
              error_class: str = "", error_message: str = "",
              objective: str = "", artifact_path: str = "",
              artifact_version: str = "", lifecycle: str = "PROPOSED",
              target: str = "", scope: list[str] | None = None,
              observations: list[Observation] | None = None,
              evidence: list[EvidenceItem] | None = None,
              handoff: Handoff | None = None,
              provenance: ProvenanceStamp | None = None,
              metrics: dict[str, Any] | None = None,
              started_at: str = "", finished_at: str = "") -> "CapabilityResult":
        """Build a result with the provenance STAMPED by the trusted runtime.

        `provenance` is a parameter, not a caller-supplied field on the
        capability's own output: the runtime passes the validated execution
        context here. A capability that tries to set provenance itself is
        caught by `validate_payload`, which rejects the forged field.
        """
        return cls(
            capability_id=capability_id,
            status=status,
            error_class=error_class,
            error_message=error_message,
            objective=objective,
            artifact_path=artifact_path,
            artifact_version=artifact_version,
            lifecycle=lifecycle,
            target=target,
            scope=list(scope or []),
            observations=list(observations or []),
            evidence=list(evidence or []),
            handoff=handoff or Handoff(),
            provenance=provenance or ProvenanceStamp(),
            metrics=dict(metrics or {}),
            started_at=started_at,
            finished_at=finished_at,
        )

    # ------------------------------------------------------------- validate
    def validate(self) -> list[str]:
        """Every problem with this result, as human-readable strings.

        Returns a LIST rather than raising, because a coordinator wants to
        report ALL the reasons a capability's output was unusable, not just
        the first one.
        """
        problems: list[str] = []
        if self.contract_version != CONTRACT_VERSION:
            problems.append(
                f"contract_version {self.contract_version!r} is not "
                f"{CONTRACT_VERSION!r}")
        if not self.capability_id:
            problems.append("capability_id is empty")
        if self.status not in RUN_STATUSES:
            problems.append(
                f"status {self.status!r} is not one of {RUN_STATUSES}")
        if self.status == "error":
            if self.error_class not in ERROR_CLASSES:
                problems.append(
                    f"error_class {self.error_class!r} is not one of "
                    f"{ERROR_CLASSES}")
            if not self.error_message:
                problems.append("an error result must carry error_message")
        elif self.error_class:
            problems.append(
                f"a successful result must not carry error_class "
                f"{self.error_class!r}")
        if self.lifecycle not in LIFECYCLE_STATES:
            problems.append(
                f"lifecycle {self.lifecycle!r} is not one of {LIFECYCLE_STATES}")
        for i, obs in enumerate(self.observations):
            if not obs.statement:
                problems.append(f"observation[{i}] has no statement")
        for i, ev in enumerate(self.evidence):
            if not ev.kind:
                problems.append(f"evidence[{i}] has no kind")
            if not ev.endpoint:
                problems.append(f"evidence[{i}] has no endpoint")
            if ev.sha256 and ev.request_raw or ev.sha256 and ev.response_raw:
                # Recompute and compare — a digest that does not match the
                # stored bytes means the evidence was edited after capture.
                blob = ev.request_raw + "\n--\n" + ev.response_raw
                if _digest(blob) != ev.sha256:
                    problems.append(
                        f"evidence[{i}] digest does not match its stored bytes")
        if self.provenance.origin == "UNKNOWN" and self.status == "ok":
            problems.append(
                "a successful result must carry a provenance origin; UNKNOWN "
                "is not a provenance")
        return problems

    def assert_valid(self) -> "CapabilityResult":
        """Raise `ContractViolation` if this result breaks the contract."""
        problems = self.validate()
        if problems:
            raise ContractViolation(
                "capability result violates the shared contract: "
                + "; ".join(problems),
                field_name="result")
        return self

    # ----------------------------------------------------------------- wire
    def to_dict(self) -> dict[str, Any]:
        return {
            "contract_version": self.contract_version,
            "capability_id": self.capability_id,
            "status": self.status,
            "error_class": self.error_class,
            "error_message": self.error_message,
            "objective": self.objective,
            "artifact_path": self.artifact_path,
            "artifact_version": self.artifact_version,
            "lifecycle": self.lifecycle,
            "target": self.target,
            "scope": list(self.scope),
            "observations": [o.to_dict() for o in self.observations],
            "evidence": [e.to_dict() for e in self.evidence],
            "handoff": self.handoff.to_dict(),
            "provenance": self.provenance.to_dict(),
            "metrics": dict(self.metrics),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CapabilityResult":
        return cls(
            capability_id=str(raw.get("capability_id") or ""),
            status=str(raw.get("status") or "ok"),
            error_class=str(raw.get("error_class") or ""),
            error_message=str(raw.get("error_message") or ""),
            objective=str(raw.get("objective") or ""),
            artifact_path=str(raw.get("artifact_path") or ""),
            artifact_version=str(raw.get("artifact_version") or ""),
            lifecycle=str(raw.get("lifecycle") or "PROPOSED"),
            target=str(raw.get("target") or ""),
            scope=[str(x) for x in (raw.get("scope") or [])],
            observations=[Observation.from_dict(x)
                          for x in (raw.get("observations") or [])],
            evidence=[EvidenceItem.from_dict(x)
                      for x in (raw.get("evidence") or [])],
            handoff=Handoff.from_dict(raw.get("handoff") or {}),
            provenance=ProvenanceStamp.from_dict(raw.get("provenance") or {}),
            metrics=dict(raw.get("metrics") or {}),
            started_at=str(raw.get("started_at") or ""),
            finished_at=str(raw.get("finished_at") or ""),
            contract_version=str(raw.get("contract_version")
                                 or CONTRACT_VERSION),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    # --------------------------------------------------------------- helpers
    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def evidence_digests(self) -> list[str]:
        return [e.sha256 for e in self.evidence if e.sha256]


# ---------------------------------------------------------------------------
# payload validation — what a capability may and may not send back
# ---------------------------------------------------------------------------

#: Fields a capability is forbidden to supply, because the trusted runtime
#: owns them. A forbidden field is REJECTED (not silently dropped) so the
#: attempt to forge it is visible in the error.
FORBIDDEN_PAYLOAD_FIELDS = (
    "provenance",
    "origin",
    "authorization_ref",
    "validator_run",
    "run_key",
    "hunt_id",
    "contract_version",
)


def validate_payload(payload: Any, *, allowed: tuple[str, ...] = ()) -> dict[str, Any]:
    """Validate a raw capability payload before it becomes a result.

    `allowed` is the set of keys the calling capability declared it produces.
    An unknown key is a contract violation: it means the capability returned
    something the coordinator cannot interpret, and silently dropping it would
    hide a real mismatch between the capability and its contract.

    FORBIDDEN fields are refused explicitly. A capability that returns its own
    `provenance` is trying to forge production provenance; the correct answer
    is a refusal with the reason, not a quiet overwrite.
    """
    if not isinstance(payload, dict):
        raise ContractViolation(
            f"capability payload must be a dict, got "
            f"{type(payload).__name__}", field_name="payload")
    forbidden = [f for f in FORBIDDEN_PAYLOAD_FIELDS if f in payload]
    if forbidden:
        raise ContractViolation(
            "capability payload carries runtime-owned field(s) "
            f"{sorted(forbidden)}; provenance is stamped by the runtime and "
            "cannot be supplied by a capability",
            field_name="provenance")
    unknown = sorted(set(payload) - set(allowed))
    if unknown:
        raise ContractViolation(
            f"capability payload has undeclared key(s) {unknown}; the "
            f"capability declared {sorted(allowed)}",
            field_name="payload")
    return payload


def error_result(capability_id: str, error_class: str, message: str, *,
                 objective: str = "", artifact_path: str = "",
                 lifecycle: str = "PROPOSED", target: str = "",
                 scope: list[str] | None = None,
                 provenance: ProvenanceStamp | None = None,
                 started_at: str = "", finished_at: str = "",
                 metrics: dict[str, Any] | None = None) -> CapabilityResult:
    """Build an explicit error artifact.

    A capability that fails produces this, and it is ALWAYS a result — never
    an exception that escapes into the coordinator, and never a silent
    success. `error_class` must come from `ERROR_CLASSES`; an unknown class
    is coerced to `INTERNAL_ERROR` rather than inventing a new vocabulary
    member at runtime.
    """
    if error_class not in ERROR_CLASSES:
        error_class = "INTERNAL_ERROR"
        message = (f"[unclassified error] {message} "
                   f"(not in the fixed error vocabulary)")
    return CapabilityResult.build(
        capability_id=capability_id,
        status="error",
        error_class=error_class,
        error_message=message,
        objective=objective,
        artifact_path=artifact_path,
        lifecycle=lifecycle,
        target=target,
        scope=list(scope or []),
        provenance=provenance,
        metrics=metrics,
        started_at=started_at,
        finished_at=finished_at,
    )


__all__ = [
    "CONTRACT_VERSION",
    "ARTIFACT_TYPES",
    "LIFECYCLE_STATES",
    "LIFECYCLE_TRANSITIONS",
    "RUN_STATUSES",
    "ERROR_CLASSES",
    "CAPABILITY_LEVELS",
    "DECLARABLE_LEVELS",
    "FORBIDDEN_PAYLOAD_FIELDS",
    "ContractViolation",
    "EvidenceItem",
    "ProvenanceStamp",
    "Handoff",
    "Observation",
    "CapabilityResult",
    "validate_payload",
    "error_result",
    "redact",
]
