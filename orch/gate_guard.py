"""Gate integrity guard (spec §1.5, invariant I6/I1).

Why this exists
---------------
The quality gate is the one component that decides what counts as knowledge.
It is also plain text in a working tree, and during the 2026-10-02 build two of
its files (`config.py`, `quality.py`) were modified by a process outside the
session that authored them. The change happened to be a STRENGTHENING (builder
pages excluded from the publisher count), so nothing failed — but it succeeded
by luck, not by design. If that same edit had set
`MIN_PUBLISHER_HOSTS = 1`, the gate would have accepted two pages from one
author and reported health throughout.

So the gate files are fingerprinted. The fingerprint lives OUTSIDE the tree it
protects, in the database, so editing a gate file cannot edit its own
exemption. `verify()` reports a mismatch as a hard failure with the exact
thresholds before and after, because "the gate changed" without saying how is
the same as no information at all.

Re-baselining is deliberate and loud: it requires an explicit reason, is
recorded as an event, and the previous fingerprint is archived. Silently
accepting the new hash would make the guard decorative.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any

from wks import config as wks_config

from . import store

# The files that define what the gate accepts. Fingerprinted individually so a
# report names WHICH file moved, not merely "something changed".
GATE_FILES = (
    "wks/config.py",      # thresholds, SOURCE_AUTHORITY
    "wks/quality.py",     # the hard gates themselves
    "wks/schema.sql",     # what a row may claim
    "wks/taxonomy.py",    # the normative seed list
    "wks/store.py",       # provenance monotonicity
    # Added after `skillgen` crashed the whole knowledge-gate self-test because
    # `class_dir` raised on an un-mapped class. Anything whose failure takes
    # the GATE down with it belongs here, not just the gate itself.
    "wks/domains.py",     # domain routing; a None here crashed skillgen
)

# Values that must not silently change. A hash alone tells you the file moved;
# this tells you the SAFETY moved, which is the difference between a comment
# edit and someone switching off the 2-host rule.
CRITICAL_SETTINGS = {
    "wks/config.py": (
        ("MIN_PUBLISHER_HOSTS", "int"),
        ("MIN_SOURCES", "int"),
        ("MIN_CLAIM_CHARS", "int"),
        ("MIN_BODY_CHARS_SUPPORTED", "int"),
        ("MATURITY_MIN_ITEMS", "int"),
        ("MATURITY_MIN_HIGH_CONF", "int"),
        ("MATURITY_MIN_FP_RULES", "int"),
        ("MATURITY_MIN_CHAINS", "int"),
    ),
}

FP_TABLE = "gate_fingerprint"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _settings() -> dict[str, Any]:
    """Read the critical settings without importing the module under test.

    Parsed textually on purpose: importing `wks.config` would run whatever the
    (possibly tampered) file contains, and a guard that executes the thing it
    is guarding cannot guard it.
    """
    import re
    out: dict[str, Any] = {}
    path = wks_config.root() / "wks" / "config.py"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return out
    for name, kind in CRITICAL_SETTINGS.get("wks/config.py", ()):
        m = re.search(rf"^{name}\s*=\s*(.+)$", text, re.M)
        if not m:
            continue
        raw = m.group(1).strip()
        try:
            out[name] = int(raw) if kind == "int" else raw
        except ValueError:
            out[name] = raw
    return out


def _ensure_table(con: sqlite3.Connection) -> None:
    con.execute(f"""
        CREATE TABLE IF NOT EXISTS {FP_TABLE} (
          file        TEXT PRIMARY KEY,
          sha256      TEXT NOT NULL,
          recorded_at TEXT NOT NULL,
          reason      TEXT
        )""")
    con.commit()


def baseline(con: sqlite3.Connection, *, reason: str) -> dict[str, Any]:
    """Record the CURRENT state of the gate files.

    Refuses without a reason, archives the previous fingerprint, and emits an
    event. A guard that can be re-baselined silently is not a guard.
    """
    if not (reason or "").strip():
        raise ValueError("re-baselining the gate requires an explicit reason; "
                         "an unexplained hash change is indistinguishable from "
                         "tampering")
    from . import store
    _ensure_table(con)
    root = wks_config.root()
    archived = []
    for f in GATE_FILES:
        p = root / f
        if not p.exists():
            continue
        old = con.execute(f"SELECT sha256 FROM {FP_TABLE} WHERE file=?",
                          (f,)).fetchone()
        if old and old["sha256"] != _sha(p):
            archived.append({"file": f, "previous_sha256": old["sha256"]})
        con.execute("INSERT OR REPLACE INTO " + FP_TABLE
                    + " (file, sha256, recorded_at, reason) VALUES (?,?,?,?)",
                    (f, _sha(p), _now(), reason))
    con.commit()
    store.emit_event(
        con, f"gate_baseline:{_now()}", "architecture",
        source="orch.gate_guard", severity="warn",
        payload={"reason": reason, "archived": archived,
                 "files": list(GATE_FILES)},
        relevance=0.6)
    return {"baselined": list(GATE_FILES), "archived": archived,
            "reason": reason, "settings": _settings()}


def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def verify(con: sqlite3.Connection) -> dict[str, Any]:
    """Check every gate file against its recorded fingerprint.

    Reports file-level changes AND setting-level changes separately: a
    comment-only edit changes the hash but not a single threshold, and only
    the second kind is a safety incident.
    """
    _ensure_table(con)
    root = wks_config.root()
    recorded = {r["file"]: r["sha256"] for r in
                con.execute(f"SELECT file, sha256 FROM {FP_TABLE}")}

    changed: list[dict[str, Any]] = []
    missing: list[str] = []
    unrecorded: list[str] = []

    for f in GATE_FILES:
        p = root / f
        if not p.exists():
            missing.append(f)
            continue
        digest = _sha(p)
        if f not in recorded:
            unrecorded.append(f)
            continue
        if recorded[f] != digest:
            changed.append({"file": f, "recorded": recorded[f][:16],
                            "current": digest[:16]})

    current_settings = _settings()
    settings_changed = []
    prev = con.execute(
        "SELECT state_json FROM checkpoint WHERE scope='gate' AND label='settings'"
    ).fetchone()
    if prev:
        old_settings = json.loads(prev["state_json"])
        for k, v in old_settings.items():
            if k in current_settings and current_settings[k] != v:
                settings_changed.append({"setting": k, "was": v,
                                         "now": current_settings[k]})

    ok = not changed and not missing
    return {
        "ok": ok,
        "changed_files": changed,
        "missing_files": missing,
        "unrecorded_files": unrecorded,
        "settings_changed": settings_changed,
        "settings": current_settings,
        "recorded": len(recorded),
    }


def remember_settings(con: sqlite3.Connection) -> dict[str, Any]:
    """Store the current settings so a later change can be diffed by NAME."""
    s = _settings()
    store.save_checkpoint(con, "gate", "settings", s)
    return s


def render(result: dict[str, Any]) -> str:
    lines = ["# GATE INTEGRITY", "",
             f"status: **{'OK' if result['ok'] else 'MODIFIED'}**  "
             f"({result['recorded']} file(s) fingerprinted)", ""]
    if result["settings"]:
        lines += ["## Critical settings (read textually, never imported)"]
        for k, v in result["settings"].items():
            lines.append(f"- {k:28} {v}")
        lines.append("")
    if result["settings_changed"]:
        lines.append("## SETTINGS CHANGED — treat as a safety incident")
        for c in result["settings_changed"]:
            lines.append(f"- **{c['setting']}**: {c['was']} -> {c['now']}")
        lines.append("")
    if result["changed_files"]:
        lines.append("## Files modified since baseline")
        for c in result["changed_files"]:
            lines.append(f"- `{c['file']}` {c['recorded']} -> {c['current']}")
        lines.append("")
    if result["missing_files"]:
        lines.append("## MISSING")
        for f in result["missing_files"]:
            lines.append(f"- `{f}`")
        lines.append("")
    if result["unrecorded_files"]:
        lines.append("## Not fingerprinted (run gate:baseline)")
        for f in result["unrecorded_files"]:
            lines.append(f"- `{f}`")
    return "\n".join(lines)
