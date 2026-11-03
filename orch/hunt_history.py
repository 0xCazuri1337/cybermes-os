"""Hunt history & closed-loop knowledge feedback (Phase 5).

Directory layout (under WKS_ROOT/hunts by default, overridable via HUNTS_ROOT)::

    hunts/
      targets/<target_slug>/sessions/<session_id>/
        session.json
        timeline.jsonl
        hypotheses.json
        results.json
        negative_results.json
        dead_ends.json
        findings.json
        knowledge_candidates.json
        authorization.json
        evidence/
          raw/<id>.enc          (encrypted at rest)
          sanitized/<id>.json
          manifests/<id>.json
      index.json
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import sqlite3
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from wks import config as wks_config

# ---------------------------------------------------------------------------
# Outcome taxonomy
# ---------------------------------------------------------------------------
OUTCOMES = (
    "POSITIVE_SIGNAL", "NEGATIVE_RESULT", "INCONCLUSIVE", "EXECUTION_ERROR",
    "BLOCKED", "OUT_OF_SCOPE", "ABANDONED", "FALSE_POSITIVE",
)

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
def hunts_root() -> Path:
    env = os.environ.get("HUNTS_ROOT")
    if env:
        return Path(env)
    return wks_config.root() / "hunts"

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "unknown").lower()).strip("-") or "unknown"

def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def _sha256_file(p: Path) -> str:
    return _sha256_bytes(p.read_bytes())

# ---------------------------------------------------------------------------
# Encryption (AES-GCM, unique nonce per call, fail-closed without key)
# ---------------------------------------------------------------------------
def _key_bytes() -> bytes:
    key = os.environ.get("HUNT_EVIDENCE_KEY", "")
    if not key:
        raise RuntimeError("HUNT_EVIDENCE_KEY is required (fail-closed)")
    # Accept raw 32-byte or base64 / hex-ish; normalize to 32 bytes.
    try:
        raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
        if len(raw) == 32:
            return raw
    except Exception:
        pass
    # Fallback: sha256 of the provided string
    return hashlib.sha256(key.encode()).digest()

def encrypt_raw(data: bytes) -> dict[str, Any]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _key_bytes()
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, data, None)
    return {
        "algorithm": "AES-256-GCM",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
        "sha256_plaintext": _sha256_bytes(data),
    }

def decrypt_raw(blob: dict[str, Any]) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = _key_bytes()
    nonce = base64.b64decode(blob["nonce"])
    ct = base64.b64decode(blob["ciphertext"])
    pt = AESGCM(key).decrypt(nonce, ct, None)
    if _sha256_bytes(pt) != blob.get("sha256_plaintext"):
        raise ValueError("integrity mismatch on decrypt")
    return pt

# Back-compat alias names
def encrypt_evidence(data): return encrypt_raw(data if isinstance(data, (bytes, bytearray)) else json.dumps(data).encode())
def decrypt_evidence(blob): return decrypt_raw(blob)

# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
_SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._\-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(set-cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([?&](?:token|api_key|apikey|secret|password|passwd|auth)=)[^&\s]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(\"(?:token|api_key|apikey|secret|password|passwd|auth)\"\s*:\s*\")[^\"]*(\")"), r"\1[REDACTED]\2"),
]

def sanitize_text(text: str) -> str:
    out = text
    for pat, repl in _SECRET_PATTERNS:
        out = pat.sub(repl, out)
    return out

def sanitize_evidence(obj: Any) -> Any:
    if isinstance(obj, str):
        return sanitize_text(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if lk in ("authorization", "cookie", "set-cookie", "x-api-key", "token", "password", "secret"):
                out[k] = "[REDACTED]"
            else:
                out[k] = sanitize_evidence(v)
        return out
    if isinstance(obj, list):
        return [sanitize_evidence(x) for x in obj]
    return obj

# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------
@dataclass
class HuntSession:
    session_id: str
    target: str
    created_at: str = field(default_factory=_now)
    closed_at: str | None = None
    outcome: str | None = None
    authorization: dict[str, Any] = field(default_factory=dict)
    scope: dict[str, Any] = field(default_factory=dict)
    interrupted: bool = False
    recovered: bool = False

    @property
    def target_slug(self) -> str:
        return _slug(self.target)

    @property
    def root(self) -> Path:
        return hunts_root() / "targets" / self.target_slug / "sessions" / self.session_id

    def paths(self) -> dict[str, Path]:
        base = self.root
        ev = base / "evidence"
        return {
            "session": base / "session.json",
            "timeline": base / "timeline.jsonl",
            "hypotheses": base / "hypotheses.json",
            "results": base / "results.json",
            "negative_results": base / "negative_results.json",
            "dead_ends": base / "dead_ends.json",
            "findings": base / "findings.json",
            "knowledge_candidates": base / "knowledge_candidates.json",
            "authorization": base / "authorization.json",
            "evidence_raw": ev / "raw",
            "evidence_sanitized": ev / "sanitized",
            "evidence_manifests": ev / "manifests",
        }

    def ensure_dirs(self) -> None:
        for p in self.paths().values():
            if p.suffix == "":
                p.mkdir(parents=True, exist_ok=True)
            else:
                p.parent.mkdir(parents=True, exist_ok=True)
        for key in ("evidence_raw", "evidence_sanitized", "evidence_manifests"):
            self.paths()[key].mkdir(parents=True, exist_ok=True)

    def save(self) -> str:
        self.ensure_dirs()
        p = self.paths()["session"]
        p.write_text(json.dumps(asdict(self), indent=2, default=str), encoding="utf-8")
        return str(p)

    @classmethod
    def load(cls, path: Path) -> "HuntSession":
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls(**data)

# ---------------------------------------------------------------------------
# History manager
# ---------------------------------------------------------------------------
class HuntHistory:
    def __init__(self, session: HuntSession):
        self.session = session
        self.session.ensure_dirs()

    # --- timeline
    def log_event(self, event: str, **fields) -> dict[str, Any]:
        rec = {"at": _now(), "event": event, **fields}
        p = self.session.paths()["timeline"]
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        return rec

    def timeline(self, limit: int = 1000) -> list[dict[str, Any]]:
        p = self.session.paths()["timeline"]
        if not p.exists():
            return []
        rows = []
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    continue
        return rows[-limit:]

    # --- list containers
    def _append(self, key: str, item: dict[str, Any]) -> None:
        p = self.session.paths()[key]
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
        data.append(item)
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")

    def _read(self, key: str) -> list[dict[str, Any]]:
        p = self.session.paths()[key]
        if not p.exists():
            return []
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return []

    def add_hypothesis(self, hypothesis: dict[str, Any]) -> dict[str, Any]:
        self._append("hypotheses", hypothesis)
        self.log_event("hypothesis", **hypothesis)
        return hypothesis

    def add_result(self, result: dict[str, Any]) -> dict[str, Any]:
        self._append("results", result)
        self.log_event("result", **result)
        return result

    def add_negative_result(self, item: dict[str, Any]) -> dict[str, Any]:
        self._append("negative_results", item)
        self.log_event("negative_result", **item)
        return item

    def add_dead_end(self, item: dict[str, Any]) -> dict[str, Any]:
        self._append("dead_ends", item)
        self.log_event("dead_end", **item)
        return item

    def add_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        self._append("findings", finding)
        self.log_event("finding", **finding)
        return finding

    # --- evidence
    def add_evidence(self, evidence_id: str, raw: Any, sanitized: Any = None,
                     metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        raw_bytes = raw if isinstance(raw, (bytes, bytearray)) else json.dumps(raw, default=str).encode()
        blob = encrypt_raw(raw_bytes)
        raw_path = self.session.paths()["evidence_raw"] / f"{evidence_id}.enc"
        raw_path.write_text(json.dumps(blob, indent=2), encoding="utf-8")

        san = sanitize_evidence(sanitized if sanitized is not None else raw)
        san_path = self.session.paths()["evidence_sanitized"] / f"{evidence_id}.json"
        san_path.write_text(json.dumps(san, indent=2, default=str), encoding="utf-8")

        manifest = {
            "evidence_id": evidence_id,
            "session_id": self.session.session_id,
            "target": self.session.target,
            "created_at": _now(),
            "raw_path": str(raw_path),
            "sanitized_path": str(san_path),
            "raw_sha256_plaintext": blob["sha256_plaintext"],
            "sanitized_sha256": _sha256_file(san_path),
            "raw_encrypted_sha256": _sha256_file(raw_path),
            "metadata": metadata or {},
        }
        man_path = self.session.paths()["evidence_manifests"] / f"{evidence_id}.json"
        man_path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        self.log_event("evidence", evidence_id=evidence_id, manifest=manifest)
        return manifest

    def verify_evidence(self, evidence_id: str) -> dict[str, Any]:
        raw_path = self.session.paths()["evidence_raw"] / f"{evidence_id}.enc"
        san_path = self.session.paths()["evidence_sanitized"] / f"{evidence_id}.json"
        man_path = self.session.paths()["evidence_manifests"] / f"{evidence_id}.json"
        if not (raw_path.exists() and san_path.exists() and man_path.exists()):
            return {"ok": False, "reason": "missing files"}
        manifest = json.loads(man_path.read_text(encoding="utf-8"))
        # decrypt + integrity
        blob = json.loads(raw_path.read_text(encoding="utf-8"))
        try:
            pt = decrypt_raw(blob)
            dec_ok = True
        except Exception as e:
            return {"ok": False, "reason": f"decrypt failed: {e}"}
        raw_ok = _sha256_bytes(pt) == manifest.get("raw_sha256_plaintext")
        san_ok = _sha256_file(san_path) == manifest.get("sanitized_sha256")
        raw_file_ok = _sha256_file(raw_path) == manifest.get("raw_encrypted_sha256")
        return {"ok": raw_ok and san_ok and raw_file_ok and dec_ok,
                "raw_integrity": raw_ok,
                "sanitized_integrity": san_ok,
                "encrypted_file_integrity": raw_file_ok,
                "decryption": dec_ok}

    def verify_all(self) -> dict[str, Any]:
        ids = [p.stem for p in self.session.paths()["evidence_manifests"].glob("*.json")]
        results = {eid: self.verify_evidence(eid) for eid in ids}
        return {"session_id": self.session.session_id,
                "all_ok": all(r.get("ok") for r in results.values()) if results else True,
                "evidence": results}

    # --- close / outcome
    def close(self, outcome: str, summary: str = "") -> dict[str, Any]:
        if outcome not in OUTCOMES:
            raise ValueError(f"unknown outcome {outcome!r}")
        self.session.outcome = outcome
        self.session.closed_at = _now()
        self.session.save()
        self.log_event("session_closed", outcome=outcome, summary=summary)
        return {"session_id": self.session.session_id, "outcome": outcome,
                "closed_at": self.session.closed_at}

    # --- search over sanitized history
    def search(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        q = query.lower()
        hits = []
        # timeline
        for rec in self.timeline():
            if q in json.dumps(rec, default=str).lower():
                hits.append({"where": "timeline", "record": rec})
        # containers
        for key in ("hypotheses", "results", "negative_results", "dead_ends", "findings"):
            for item in self._read(key):
                if q in json.dumps(item, default=str).lower():
                    hits.append({"where": key, "record": item})
        # sanitized evidence
        for p in self.session.paths()["evidence_sanitized"].glob("*.json"):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            if q in json.dumps(data, default=str).lower():
                hits.append({"where": "evidence_sanitized", "file": str(p), "record": data})
        return hits[:limit]

    # --- candidate extraction
    def extract_candidates(self) -> list[dict[str, Any]]:
        cands = []
        for f in self._read("findings"):
            cands.append({
                "item_key": f.get("finding_key") or f.get("key") or f"hunt.{self.session.session_id}.finding.{len(cands)+1}",
                "class_id": f.get("class_id", "unknown"),
                "claim": f.get("title") or f.get("claim") or str(f),
                "kind": f.get("kind", "finding"),
                "sources": f.get("sources", [{"url": "hunt://session", "quote": "synthetic"}]),
                "origin": "HUNT",
                "body": f,
            })
        # negative results as candidates too
        for nr in self._read("negative_results"):
            cands.append({
                "item_key": nr.get("key") or f"hunt.{self.session.session_id}.negative.{len(cands)+1}",
                "class_id": nr.get("class_id", "unknown"),
                "claim": nr.get("claim") or str(nr),
                "kind": "negative_result",
                "sources": nr.get("sources", [{"url": "hunt://session", "quote": "synthetic"}]),
                "origin": "HUNT",
                "body": nr,
            })
        path = self.session.paths()["knowledge_candidates"]
        path.write_text(json.dumps(cands, indent=2, default=str), encoding="utf-8")
        return cands

    def push_candidates(self, con: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
        cands = self.extract_candidates()
        if con is None:
            try:
                from wks import store as wks_store
                con = wks_store.open_db(create=True)
            except Exception:
                return cands
        try:
            from wks import unified_ingest
            out = []
            for c in cands:
                try:
                    v = unified_ingest.ingest_candidate(con, c, origin="HUNT")
                    out.append(v)
                except Exception as e:
                    out.append({"error": str(e), "candidate": c})
            try:
                con.commit()
            except Exception:
                pass
            return out
        except Exception:
            return cands

    # --- fp submission
    def submit_fp(self, class_id: str, hypothesis: str, test: str,
                  invalidated_by: str, rule: str, looked_because: str = "",
                  missed: str = "") -> int:
        try:
            from wks import fp as wks_fp
            import argparse
            ns = argparse.Namespace(
                cmd="log", class_id=class_id, key=None, hypothesis=hypothesis,
                looked_because=looked_because, test=test, invalidated_by=invalidated_by,
                missed=missed, rule=rule, skill_updated=None,
            )
            return wks_fp.log(ns)
        except Exception:
            return 1

    # --- recovery
    def is_interrupted(self) -> bool:
        return self.session.closed_at is None

    def recover(self) -> dict[str, Any]:
        self.session.interrupted = True
        self.session.recovered = True
        self.session.save()
        self.log_event("recovered", at=_now())
        return {"session_id": self.session.session_id, "recovered": True,
                "closed": self.session.closed_at is not None}

# ---------------------------------------------------------------------------
# Factory / listing
# ---------------------------------------------------------------------------
def create_session(target: str, session_id: str | None = None,
                   authorization: dict[str, Any] | None = None,
                   scope: dict[str, Any] | None = None) -> HuntSession:
    sid = session_id or f"session-{int(time.time())}-{uuid.uuid4().hex[:8]}"
    s = HuntSession(session_id=sid, target=target,
                    authorization=authorization or {}, scope=scope or {})
    s.ensure_dirs()
    # authorization/scope snapshot
    s.paths()["authorization"].write_text(
        json.dumps({"authorization": s.authorization, "scope": s.scope,
                    "created_at": _now()}, indent=2, default=str),
        encoding="utf-8")
    s.save()
    return s

def load_session(session_id: str, target: str | None = None) -> HuntSession:
    # search
    root = hunts_root() / "targets"
    if target:
        p = root / _slug(target) / "sessions" / session_id / "session.json"
        if p.exists():
            return HuntSession.load(p)
    for p in root.glob(f"*/sessions/{session_id}/session.json"):
        return HuntSession.load(p)
    raise FileNotFoundError(session_id)

def list_sessions(target: str | None = None) -> list[dict[str, Any]]:
    root = hunts_root() / "targets"
    out = []
    if not root.exists():
        return out
    targets = [root / _slug(target)] if target else list(root.iterdir())
    for t in targets:
        sess_root = t / "sessions"
        if not sess_root.exists():
            continue
        for d in sess_root.iterdir():
            sp = d / "session.json"
            if sp.exists():
                try:
                    s = HuntSession.load(sp)
                    out.append({"session_id": s.session_id, "target": s.target,
                                "outcome": s.outcome, "closed_at": s.closed_at,
                                "interrupted": s.interrupted})
                except Exception:
                    continue
    return out

def search_history(query: str, target: str | None = None) -> list[dict[str, Any]]:
    hits = []
    for s in list_sessions(target):
        try:
            hs = HuntHistory(load_session(s["session_id"], s["target"]))
            for h in hs.search(query):
                hits.append({"session_id": s["session_id"], "target": s["target"], **h})
        except Exception:
            continue
    return hits

def rebuild_index() -> dict[str, Any]:
    idx = {"rebuilt_at": _now(), "sessions": list_sessions()}
    p = hunts_root() / "index.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(idx, indent=2, default=str), encoding="utf-8")
    return idx

def export_session(session_id: str, target: str | None = None, dest: str | None = None) -> str:
    s = load_session(session_id, target)
    hs = HuntHistory(s)
    payload = {
        "session": asdict(s),
        "timeline": hs.timeline(),
        "hypotheses": hs._read("hypotheses"),
        "results": hs._read("results"),
        "negative_results": hs._read("negative_results"),
        "dead_ends": hs._read("dead_ends"),
        "findings": hs._read("findings"),
        "knowledge_candidates": hs._read("knowledge_candidates"),
        "evidence_manifests": [json.loads(p.read_text()) for p in s.paths()["evidence_manifests"].glob("*.json")],
    }
    out = Path(dest) if dest else (s.root / "export.json")
    out.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return str(out)

# Back-compat aliases
HuntHistoryManager = HuntHistory
create_hunt_session = create_session
list_hunts = list_sessions
verify_integrity = lambda session_id, target=None: HuntHistory(load_session(session_id, target)).verify_all()
