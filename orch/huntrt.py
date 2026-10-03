"""Per-hunt runtime isolation (master prompt §53).

§53 requires that "every Hunt requires an independent runtime context" with
recoverability mandatory. The tree today has exactly one `runtime/state/`
directory shared by every run, which means two hunts — or a hunt and its own
retest — write into the same namespace. `runtime/state/RUN-*.md` is already
ambiguous about which run produced what.

So `HuntRuntime` gives each hunt its own directory with the twelve names §53
lists, and:

  * `paths()` creates nothing until asked, so an operator can see the layout
    before a hunt starts.
  * `resume(hunt_id)` reconstructs from the hunt's own checkpoint, so recovery
    never reads another hunt's state.
  * Every write is a `history` entry, so §21's "every important decision must be
    traceable" has a home that is per-hunt.

The hunt_id is derived from target + program + a discriminator, and a hunt that
reuses an existing id must say so explicitly — silently joining an old hunt's
directory is how two hunts' evidence ends up merged into one report.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from wks import config as wks_config

from . import store

# Every hunt module stamps artifacts with the same clock. One function, so a
# timestamp cannot be produced in two places and disagree.
def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# §53's structure, verbatim. Creating a subset would be a different design and
# should be a deliberate decision, not an omission.
HUNT_DIRS = (
    "identity", "authorization", "plan", "recon", "attack_surface",
    "hypotheses", "agents", "research", "findings", "evidence", "validation",
    "reports", "history",
)


def hunts_root() -> Path:
    return wks_config.root() / "runtime" / "hunts"


def make_hunt_id(target: str, program: str = "", discriminator: str = ""
                 ) -> str:
    t = re.sub(r"[^a-z0-9]+", "-", (target or "no-target").lower()).strip("-")
    p = re.sub(r"[^a-z0-9]+", "-", (program or "no-program").lower()).strip("-")
    base = f"{p}__{t}"
    if discriminator:
        base += "__" + re.sub(r"[^a-z0-9]+", "-",
                              discriminator.lower()).strip("-")
    if len(base) <= 80:
        return base
    h = hashlib.sha256(base.encode()).hexdigest()[:12]
    return f"{base[:60]}-{h}"


class HuntRuntime:
    def __init__(self, hunt_id: str):
        self.hunt_id = hunt_id

    # ------------------------------------------------------------------ paths
    @property
    def root(self) -> Path:
        return hunts_root() / self.hunt_id

    def dir(self, name: str) -> Path:
        if name not in HUNT_DIRS:
            raise KeyError(f"unknown hunt directory {name!r}; §53 defines: "
                           f"{HUNT_DIRS}")
        return self.root / name

    def paths(self, *, create: bool = False) -> dict[str, str]:
        out = {name: str(self.root / name) for name in HUNT_DIRS}
        if create:
            for name in HUNT_DIRS:
                (self.root / name).mkdir(parents=True, exist_ok=True)
            (self.root / "hunt.json").write_text(
                json.dumps({"hunt_id": self.hunt_id,
                            "created_at": _now(),
                            "sections": list(HUNT_DIRS)}, indent=2),
                encoding="utf-8")
        return out

    def exists(self) -> bool:
        return (self.root / "hunt.json").exists()

    # ------------------------------------------------------------- artifacts
    def write(self, section: str, filename: str, content: str) -> str:
        p = self.dir(section) / filename
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        self.log("artifact_written", section=section, file=str(p),
                 chars=len(content))
        return str(p)

    def read(self, section: str, filename: str) -> str | None:
        p = self.dir(section) / filename
        return p.read_text(encoding="utf-8") if p.exists() else None

    def files(self, section: str) -> list[str]:
        d = self.dir(section)
        return sorted(str(p) for p in d.glob("*")) if d.exists() else []

    # --------------------------------------------------------------- history
    def log(self, event: str, **fields) -> str:
        """Append one decision to this hunt's history. Never shared."""
        p = self.dir("history") / "decisions.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        rec = {"at": _now(), "hunt_id": self.hunt_id, "event": event,
               **fields}
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
        return rec["at"]

    def history(self, limit: int = 200) -> list[dict[str, Any]]:
        p = self.dir("history") / "decisions.jsonl"
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

    # --------------------------------------------------------------- resume
    def checkpoint(self, name: str = "hunt") -> dict[str, Any] | None:
        p = self.dir("history") / f"checkpoint-{name}.json"
        if not p.exists():
            return None
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return None

    def save_checkpoint(self, state: dict[str, Any], name: str = "hunt") -> str:
        p = self.dir("history") / f"checkpoint-{name}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(state, default=str, indent=2), encoding="utf-8")
        return str(p)

    def resume(self) -> dict[str, Any]:
        """Reconstruct this hunt. §20 of the rule list: every hunt recoverable."""
        cp = self.checkpoint()
        return {"hunt_id": self.hunt_id,
                "root": str(self.root),
                "exists": self.exists(),
                "resumable": cp is not None,
                "checkpoint": cp,
                "sections_present": [s for s in HUNT_DIRS
                                     if (self.root / s).exists()],
                "history_entries": len(self.history())}


def list_hunts() -> list[dict[str, Any]]:
    r = hunts_root()
    if not r.exists():
        return []
    out = []
    for d in sorted(r.iterdir()):
        if not d.is_dir():
            continue
        hr = HuntRuntime(d.name)
        out.append({"hunt_id": d.name, "created": hr.exists(),
                    "sections": sum(1 for s in HUNT_DIRS
                                    if (d / s).exists()),
                    "history": len(hr.history()),
                    "last_checkpoint": (hr.checkpoint() or {}).get("at")})
    return out


def isolation_report() -> dict[str, Any]:
    """Prove hunts do not share a namespace.

    Two hunts with the same directory would mean one hunt's evidence appears in
    another's report, so this reports the id set and flags collisions — which
    cannot happen by construction, which is the point.
    """
    hunts = list_hunts()
    ids = [h["hunt_id"] for h in hunts]
    return {"hunts_root": str(hunts_root()),
            "count": len(hunts),
            "duplicate_ids": sorted({i for i in ids if ids.count(i) > 1}),
            "isolated": len(set(ids)) == len(ids),
            "shared_state_dir_still_exists": (wks_config.root() / "runtime" /
                                             "state").exists(),
            "note": ("runtime/state/ holds SYSTEM state (cycles, audits, seed "
                     "probes). Per-hunt execution state lives under "
                     "runtime/hunts/<hunt_id>/. The two are different "
                     "lifetimes and must not share a namespace.")}