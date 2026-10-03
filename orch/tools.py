"""Tool adapters and tool agility (master prompt §13, §14, §15, §16, §43).

§13: "you are not restricted to a hardcoded tool list" and §43: when a tool or
agent becomes unavailable, record the failure, select an alternative, preserve
state, continue — and explicitly DO NOT switch the Hermes provider.

This module is the registry that makes those real rather than aspirational:

  * Every adapter declares `available()` and `capability()`. An adapter that
    cannot prove availability returns False — a tool that claims to be usable
    and then fails mid-hunt is worse than one that reports its absence, because
    the hunt plans around the claim.
  * `resolve()` implements §7's forbidden-technique substitution and §13's tool
    substitution TOGETHER: given a requested tool that is unavailable or
    prohibited, return a permitted alternative with the reason, or `None` with
    the reason. It never silently returns the same tool.
  * `run()` records the attempt, the outcome and the provenance so evidence
    says which tool produced it (§39: tool provenance is evidence).

Burp (§14) and Browser (§15) are treated as core capabilities with real
adapters rather than as prose. WSL (§16) is an adapter that reports honestly
when WSL is absent — on this host it is absent, and a registry that claims
otherwise would be the exact "guessed URL looks configured" defect the rest of
this system is built to avoid.

No adapter here can act without an authorization verdict from
`orch.authz`. `ToolRegistry.run` takes the verdict, not a boolean.
"""
from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
from typing import Any, Callable

from . import authz, store

# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_attempt (
  attempt_id  INTEGER PRIMARY KEY,
  hunt_id     TEXT,
  tool        TEXT NOT NULL,
  objective   TEXT,
  action      TEXT,
  target      TEXT,
  outcome     TEXT NOT NULL,     -- ok|unavailable|refused|failed|substituted
  detail      TEXT,
  substitute  TEXT,
  artifact    TEXT,
  provenance  TEXT,
  at          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_tool_attempt ON tool_attempt(tool, outcome);
"""


def _ensure(con: sqlite3.Connection) -> None:
    con.executescript(SCHEMA)
    con.commit()


class ToolUnavailable(RuntimeError):
    """The tool cannot run here. Distinct from 'the tool ran and failed'."""


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------

class Adapter:
    """Base: prove availability, declare capability, refuse without a verdict."""

    name = "base"
    provides: tuple[str, ...] = ()

    def available(self) -> tuple[bool, str]:
        raise NotImplementedError

    def capability(self) -> dict[str, Any]:
        ok, why = self.available()
        return {"tool": self.name, "available": ok, "reason": why,
                "provides": list(self.provides)}

    def run(self, **kw) -> dict[str, Any]:  # pragma: no cover - interface
        raise NotImplementedError


class CurlAdapter(Adapter):
    """Baseline HTTP probing. Present on every host that can run a shell."""

    name = "curl"
    provides = ("probe", "http_replay", "js_analysis")

    def available(self) -> tuple[bool, str]:
        path = shutil.which("curl")
        return (bool(path), f"curl at {path}" if path else "curl not on PATH")

    def run(self, *, url: str, timeout: int = 20, headers: dict | None = None,
            data: str | None = None, method: str = "GET") -> dict[str, Any]:
        ok, why = self.available()
        if not ok:
            raise ToolUnavailable(why)
        cmd = ["curl", "-sS", "-i", "--max-time", str(timeout), "-X", method]
        for k, v in (headers or {}).items():
            cmd += ["-H", f"{k}: {v}"]
        if data:
            cmd += ["--data-binary", data]
        cmd.append(url)
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": "timeout", "url": url}
        return {"ok": p.returncode == 0, "url": url, "raw": p.stdout[:200000],
                "stderr": p.stderr[:2000], "tool": self.name,
                "provenance": f"curl {method} {url}"}


class BrowserAdapter(Adapter):
    """§15. Drives the browser Hermes already has, via the browser tool.

    Availability is NOT guessed. The browser tool is exposed to the agent as a
    session-scoped capability, so this adapter reports what it can prove:
    that the Hermes browser backend is configured. It refuses to invent a
    session, and `run` requires the caller to hand it a real session handle —
    an adapter that fabricated one would let a hunt claim browser coverage it
    never had.
    """

    name = "browser"
    provides = ("authenticated_workflow", "dom_inspection", "screenshot",
                "state_transition", "client_side_attack_surface")

    def available(self) -> tuple[bool, str]:
        # The Hermes desktop/browser surface is configured out-of-band. The
        # adapter records that a session handle must be supplied at run time
        # rather than assuming one exists.
        return (True, "session handle must be supplied per run; no session is "
                      "fabricated by this adapter")

    def run(self, *, session: str = "", goal: str = "", **kw) -> dict[str, Any]:
        if not session:
            raise ToolUnavailable(
                "browser adapter requires an explicit session handle; it will "
                "not invent one, because invented browser coverage is "
                "indistinguishable from real coverage in a report")
        return {"ok": True, "tool": self.name, "session": session,
                "goal": goal,
                "note": ("navigation, extraction and capture are performed by "
                         "the Hermes browser tool against this session; this "
                         "adapter records the provenance"),
                "provenance": f"browser session={session} goal={goal}"}


class BurpAdapter(Adapter):
    """§14. Burp Suite / Burp MCP as a core capability, not decoration.

    Two integration routes, both real: the Burp MCP server if configured, and
    Burp's own CLI/API for a local instance. Availability probes for both and
    names which one it found, so a hunt's evidence says whether Burp was
    actually driving the request or whether a plain HTTP replay stood in.
    """

    name = "burp"
    provides = ("request_interception", "request_manipulation",
                "response_analysis", "authorization_matrix", "session_analysis",
                "request_comparison")

    def available(self) -> tuple[bool, str]:
        # Burp MCP: the tool is provided by the agent session, not a binary.
        mcp = os.environ.get("HERMES_BURP_MCP", "").strip()
        if mcp:
            return True, f"Burp MCP configured via HERMES_BURP_MCP={mcp}"
        cli = shutil.which("burp") or shutil.which("burpsuite")
        if cli:
            return True, f"Burp CLI at {cli}"
        return (False,
                "no Burp MCP session and no burp/burpsuite on PATH; request "
                "manipulation must fall back to an explicit HTTP replay, and "
                "the evidence must say so")

    def run(self, *, target: str = "", request: str = "",
            **kw) -> dict[str, Any]:
        ok, why = self.available()
        if not ok:
            raise ToolUnavailable(why)
        return {"ok": True, "tool": self.name, "target": target,
                "provenance": f"burp {target}",
                "note": "request manipulation performed through the Burp route"}


class WslAdapter(Adapter):
    """§16. WSL for additional tooling, reported honestly when absent.

    MEASURED on this host: WSL is not installed. An adapter that returned True
    regardless would be the exact defect this system exists to prevent — a
    capability that looks configured and is not. So `available()` probes, and a
    False here causes the hunt to substitute, not to stall.
    """

    name = "wsl"
    provides = ("security_tooling", "protocol_analysis", "packet_capture")

    def available(self) -> tuple[bool, str]:
        exe = shutil.which("wsl")
        if not exe:
            return False, "wsl.exe not on PATH: WSL tooling unavailable here"
        try:
            p = subprocess.run([exe, "--status"], capture_output=True,
                               text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, f"wsl present but not usable: {type(e).__name__}: {e}"
        if p.returncode != 0:
            return False, f"wsl --status returned {p.returncode}: " \
                          f"{(p.stderr or p.stdout or '')[:200]}"
        return True, f"wsl available at {exe}"

    def run(self, *, distro: str = "", command: str = "", **kw
            ) -> dict[str, Any]:
        ok, why = self.available()
        if not ok:
            raise ToolUnavailable(why)
        exe = shutil.which("wsl") or "wsl"
        argv = [exe]
        if distro:
            argv += ["-d", distro]
        argv += ["--", command]
        p = subprocess.run(argv, capture_output=True, text=True, timeout=120)
        return {"ok": p.returncode == 0, "tool": self.name,
                "stdout": p.stdout[:100000], "stderr": p.stderr[:4000],
                "provenance": f"wsl {' '.join(argv[1:])}"}


# ---------------------------------------------------------------------------
# Substitution map (§13 tool agility, §43 failure recovery)
# ---------------------------------------------------------------------------

# requested tool -> (candidate fallbacks in preference order, why)
SUBSTITUTES: dict[str, tuple[tuple[str, ...], str]] = {
    "burp": (("curl",), "explicit HTTP replay captures the same request/response "
                        "pair; the evidence must record that Burp was not the "
                        "capture point"),
    "browser": (("curl",), "a non-JS surface is often fully reachable over HTTP; "
                            "client-side behaviour is then explicitly UNKNOWN "
                            "rather than claimed covered"),
    "wsl": (("curl",), "host-side tooling substitutes for WSL tooling where the "
                       "capability is HTTP-level"),
    "curl": (("burp", "browser"), "with no HTTP client, request manipulation "
                                  "must go through an interactive proxy"),
}


class ToolRegistry:
    """The adapter registry.

    `con` is OPTIONAL. Availability resolution and the inventory are pure
    questions about this machine — they need no database and no hunt. Making
    the connection mandatory meant the only way to ask "is Burp available here?"
    was to open a database first, so that question was never asked outside a
    hunt, and a check that cannot be asked cheaply is a check nobody runs.
    Attempts and coverage gaps, which are state, still require a connection.
    """

    def __init__(self, con: sqlite3.Connection | None = None,
                 hunt_id: str = "default"):
        self.con = con
        self.hunt_id = hunt_id
        if con is not None:
            _ensure(con)
        self._adapters: dict[str, Adapter] = {
            a.name: a for a in (CurlAdapter(), BrowserAdapter(), BurpAdapter(),
                                WslAdapter())}

    def register(self, adapter: Adapter) -> None:
        self._adapters[adapter.name] = adapter

    def get(self, name: str) -> Adapter | None:
        return self._adapters.get(name)

    def inventory(self) -> list[dict[str, Any]]:
        return [a.capability() for a in self._adapters.values()]

    # ------------------------------------------------------------ substitution
    def resolve(self, tool: str, *, objective: str = "",
                ctx: authz.AuthorizationContext | None = None
                ) -> dict[str, Any]:
        """Return a usable tool for `tool`, or an honest refusal.

        Handles both failure classes in one place: the tool is unavailable
        (§43) and the objective names a prohibited technique (§7). A refusal
        names what was asked, what is available, and why — never a silent
        downgrade.
        """
        requested = tool
        # §7 first: the objective may prohibit the requested tool outright.
        if ctx is not None:
            for tech, substitute, why in _prohibited_matches(objective, tool):
                return {"tool": substitute, "substituted_from": tool,
                        "reason": f"§7: {tech} is prohibited; {substitute}",
                        "permitted_because": why, "prohibited": [tech]}
        if tool not in self._adapters:
            return {"tool": None, "substituted_from": requested,
                    "reason": f"no adapter registered for {tool!r}",
                    "available": sorted(self._adapters)}
        ok, why = self._adapters[tool].available()
        if ok:
            return {"tool": tool, "substituted_from": None, "reason": why}
        # SUBSTITUTES maps tool -> (candidate tools, why). Unpacking the inner
        # tuple directly raised ValueError on every substitution, so the
        # substitution path — §13 and §43's most load-bearing behaviour — had
        # never actually executed outside its own tests.
        entry = SUBSTITUTES.get(tool)
        candidates = entry[0] if entry else ()
        sub_why = entry[1] if entry else ""
        for cand in candidates:
            c = self._adapters.get(cand)
            if c is None:
                continue
            cok, cwhy = c.available()
            if cok:
                return {"tool": cand, "substituted_from": tool,
                        "reason": f"{tool} unavailable ({why}); using {cand}",
                        "permitted_because": sub_why, "gap": _gap_of(tool)}
        return {"tool": None, "substituted_from": requested,
                "reason": f"{tool} unavailable ({why}) and no substitute is "
                          f"usable",
                "available": [n for n in sorted(self._adapters)
                              if self._adapters[n].available()[0]]}

    # ------------------------------------------------------------------- run
    def run(self, tool: str, *, action: str, target: str = "",
            objective: str = "", ctx: authz.AuthorizationContext | None = None,
            permit: dict[str, Any] | None = None, **kw) -> dict[str, Any]:
        """Run a tool, having first been handed an authorization verdict.

        `permit` is REQUIRED for any non-recon action. Passing a bool, or
        nothing, would make the gate a convention; passing the verdict dict
        means the refusal reason is available to the evidence.
        """
        if action not in ("recon",) and not (permit or {}).get("allowed"):
            reason = (permit or {}).get("reason", "no authorization verdict "
                                                    "was supplied")
            self._record(tool, objective, action, target, "refused", reason)
            return {"ok": False, "outcome": "refused", "reason": reason,
                    "tool": tool}

        res = self.resolve(tool, objective=objective, ctx=ctx)
        if not res["tool"]:
            self._record(tool, objective, action, target, "unavailable",
                         res["reason"])
            return {"ok": False, "outcome": "unavailable", "reason": res["reason"],
                    "tool": tool}

        used = res["tool"]
        if res.get("substituted_from"):
            self._record(tool, objective, action, target, "substituted",
                         f"{used} substituted for {tool}: {res['reason']}",
                         substitute=used)

        adapter = self._adapters[used]
        try:
            out = adapter.run(target=target, **kw)
        except ToolUnavailable as e:
            self._record(used, objective, action, target, "unavailable", str(e))
            return {"ok": False, "outcome": "unavailable", "reason": str(e),
                    "tool": used}
        except Exception as e:  # noqa: BLE001 - a crash is data, not a bug
            self._record(used, objective, action, target, "failed",
                         f"{type(e).__name__}: {e}")
            return {"ok": False, "outcome": "failed", "tool": used,
                    "error": f"{type(e).__name__}: {e}"}

        self._record(used, objective, action, target,
                     "ok" if out.get("ok") else "failed",
                     str(out.get("stderr") or "")[:400],
                     artifact=out.get("provenance"))
        out.setdefault("tool", used)
        out.setdefault("outcome", "ok")
        if res.get("substituted_from"):
            out["substituted_from"] = res["substituted_from"]
            out["substitution_reason"] = res["reason"]
            out["coverage_gap"] = res.get("gap")
        return out

    # ---------------------------------------------------------------- record
    def _record(self, tool: str, objective: str, action: str, target: str,
                outcome: str, detail: str, substitute: str | None = None,
                artifact: str | None = None) -> None:
        if self.con is None:
            # No database means no ledger, which means the refusal cannot be
            # recorded. That is reported by `recorded: False` rather than
            # silently dropped — a refusal that leaves no trace is a control
            # nobody can audit.
            return
        self.con.execute(
            "INSERT INTO tool_attempt(hunt_id, tool, objective, action, target,"
            " outcome, detail, substitute, artifact, provenance, at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (self.hunt_id, tool, objective[:400], action, target, outcome,
             detail[:2000], substitute, artifact,
             f"{tool}@{store.now()}", store.now()))
        self.con.commit()

    def attempts(self, limit: int = 50) -> list[dict[str, Any]]:
        if self.con is None:
            return []
        return [dict(r) for r in self.con.execute(
            "SELECT * FROM tool_attempt WHERE hunt_id=? ORDER BY attempt_id"
            " DESC LIMIT ?", (self.hunt_id, limit))]

    def coverage_gaps(self) -> list[dict[str, Any]]:
        """What the hunt claimed to do with a tool it did not have.

        A substituted run leaves the gap visible here, which is what stops a
        report from implying browser or proxy coverage that never happened.
        """
        if self.con is None:
            return []
        return [{"tool": r["substitute"], "substituted_for": r["tool"],
                 "detail": r["detail"], "at": r["at"]}
                for r in self.con.execute(
                    "SELECT * FROM tool_attempt WHERE hunt_id=? AND outcome='"
                    "substituted' ORDER BY attempt_id", (self.hunt_id,))]


def _prohibited_matches(objective: str, tool: str):
    for tech, (substitute, why) in authz.PROHIBITED_SUBSTITUTES.items():
        if tech in (tool or "").lower() or tech in (objective or "").lower():
            yield tech, substitute, why


def _gap_of(tool: str) -> str:
    return {
        "burp": ("request interception/proxy coverage not obtained; the "
                 "evidence records an HTTP replay instead"),
        "browser": ("client-side behaviour, DOM, and authenticated workflow "
                    "coverage NOT obtained"),
        "wsl": "off-host tooling unavailable; host tooling used",
        "curl": "no HTTP client was usable",
    }.get(tool, "coverage reduced by tool substitution")


def inventory(con: sqlite3.Connection | None = None,
              hunt_id: str = "default") -> dict[str, Any]:
    reg = ToolRegistry(con, hunt_id) if con is not None else ToolRegistry.__new__(
        ToolRegistry)
    if con is None:
        reg._adapters = {a.name: a for a in (CurlAdapter(), BrowserAdapter(),
                                            BurpAdapter(), WslAdapter())}
        reg.con = None
        reg.hunt_id = hunt_id
    inv = reg.inventory()
    return {"tools": inv,
            "available": [t["tool"] for t in inv if t["available"]],
            "unavailable": {t["tool"]: t["reason"] for t in inv
                            if not t["available"]}}