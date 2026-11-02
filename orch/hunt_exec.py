"""ACTIVE HUNT EXECUTION — the missing executor for `hunt.*` task keys.

The measured defect this module exists to close
-----------------------------------------------
`orch/hunt_cli.py` is the documented way to run a hunt, and `orch/executor.py`
is the only component that actually performs work. They never met. MEASURED:

  * `orch/executor.py::pick_handler` routes on task-key SHAPE
    (`orch/executor.py:528-552`). Its research patterns are
    `^(?:research|seed)\\.(?P<cls>...)` (line 47) and the `unknown.research.`
    prefix (line 543).
  * EVERY task key the hunting engine creates starts with `hunt.`
    (`orch/hunting.py:228,241,248,278,290`).
  * Therefore every hunt task fell through to `do_maintenance`
    (line 552) — proven by executing `pick_handler` over all six hunt key
    shapes: ALL SIX returned `do_maintenance`.

So a hunt never probed, never fetched, never produced a finding, and could
never produce one: the handler that ran was the one that re-gates the corpus
and regenerates markdown. Worse, `do_maintenance` returns `ok=True` with a
healthy artifact every time, so a hunt that achieved nothing reported
COMPLETE and exited 0. The self-score read 100/100 throughout, because all 65
checks call the engine directly and never execute a `hunt.*` task.

Second measured defect: `ToolRegistry.run()` — the only method in the whole
codebase that contacts a target (`orch/tools.py:334`) — had ZERO callers
outside its own module (grep over the tree: no `.run("curl"...)` anywhere
outside `eval/`). The tool layer was built, gated, substitution-tested and
never once driven. A browser adapter that says "the Hermes browser tool
performs navigation" (`orch/tools.py:143-156`) makes that worse: the hunt can
record browser coverage it never had.

What this module does
---------------------
It is the ACTIVE half of the executor, and it is deliberately the ONLY place
in the tree that sends a request to a target. It:

  1. Refuses unless a real authorization verdict exists (no default-allow).
  2. Probes through `ToolRegistry.run`, so §13 substitution, §43 unavailability
     and the §6 tool ledger all apply unchanged.
  3. Turns the RESPONSE into structured observations via
     `orch.hypothesis.classify_behaviour` — differential responses, error
     strings, reflected input, CORS/security headers — so the CLASS is derived
     from real evidence instead of asserted by the operator.
  4. Writes a candidate `finding` whenever a differential is actually observed,
     with the raw request/response retained as evidence.

INVARIANT I6 still holds for the knowledge engine: `wks/` performs no active
testing, ever. Active testing lives here, requires an explicit authorization
verdict, respects the AuthorizationContext's forbidden actions and rate limits,
and records every attempt in `tool_attempt`.

Safety rails that are structural, not conventional
--------------------------------------------------
  * No target contact without `permit` carrying `allowed: True`.
  * `forbidden_actions` are refused by name before any socket is opened.
  * Every request is recorded in `tool_attempt` BEFORE the result is judged,
    so a crash still leaves the attempt visible.
  * Destructive actions (DELETE, and any verb in `destructive_write`) are
    refused unless `offensive_allowed` is set on the grant.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from typing import Any
from urllib.parse import quote, urlparse

from . import store
from . import tools as tools_mod
from .hypothesis import classify_behaviour


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# Signals derived from real responses. Each is EVIDENCE, not an assertion:
# `classify_behaviour` refuses a signal it cannot point at a response for.
# A result count, in EITHER order. MEASURED: the original pattern only matched
# a number FOLLOWING the noun ("rows: 7") and returned None for the far more
# common "7 rows", so the boolean-differential probe read every real
# differential as "no count found" and could only ever report a negative.
# Both orders are counted, and a bare integer body counts too.
_COUNT_AFTER = re.compile(r"\b(?:rows?|records?|results?|entries|items|users|"
                          r"found|matching)\b\D{0,20}?(\d{1,9})\b", re.I)
_COUNT_BEFORE = re.compile(r"\b(\d{1,9})\s+(?:rows?|records?|results?|entries|"
                           r"items|users)\b", re.I)
_BARE_COUNT = re.compile(r"^\s*(\d{1,9})\s*$")

_SQL_ERRORS = (
    "sqlstate", "sqlserver", "mysql", "postgres", "sqlite", "ora-", "odbc",
    "unclosed quotation mark", "syntax error", "sintax error",
    "system.data.sqlclient", "you have an error in your sql",
    "warning: mysql", "pg_query", "supplied argument is not a valid",
    "microsoft ole db provider for sql server", "com.mysql.jdbc",
    "javax.sql", "org.postgresql.util",
)

_NO_SQL_ERRORS = (
    "you have an error in your sql syntax",  # caught above too
)

_TEMPLATE_ERRORS = (
    "template syntax error", "jinja2", "undefinedvariable",
    "template not a valid python identifier", "django template",
    "thymeleaf", "expression language", "freemarker",
    "elexception", "could not parse as", "gstring",
)

_XSS_REFLECT = re.compile(r"<script|\bonerror\s*=|\bonload\s*=|javascript:",
                          re.I)


def _split_response(raw: str) -> tuple[str, str]:
    """(headers, body) from a curl -i capture, without inventing either.

    MEASURED: this split on `\\r?\\n\\r?\\n` only in one direction and assumed a
    CRLF pair. The lab server (Python `http.server`) emits BARE `\\n`
    separators, so every header block swallowed the entire body and every probe
    reported `body[0:90]=''` — no signal could ever be derived, and the engine
    reported "nothing observed" with total confidence. Accept either newline
    convention, including a header block that used one and a body after the
    other.
    """
    if not raw:
        return "", ""
    m = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    head = m[0] if m else ""
    body = m[1] if len(m) > 1 else ""
    if not body:
        # Some servers pad with a lone blank line variant; try the other
        # convention before concluding there is no body.
        m2 = re.split(r"\n\n", raw, maxsplit=1)
        if len(m2) > 1:
            head, body = m2[0], m2[1]
    return head, body


def _status(head: str) -> int | None:
    m = re.search(r"^HTTP/[\d.]+\s+(\d{3})", head, re.M)
    return int(m.group(1)) if m else None


def _header(head: str, name: str) -> str | None:
    m = re.search(rf"^{re.escape(name)}\s*:\s*(.+)$", head, re.I | re.M)
    return m.group(1).strip() if m else None


def derive_signals(*, head: str, body: str, status: int | None,
                   probe_pairs: list[tuple[str, int | None, int | None]],
                   payload: str = "") -> list[dict[str, Any]]:
    """Turn response evidence into observation records.

    Every returned record carries the response facts that justify it. A signal
    with no supporting response is not emitted — the engine's own docstring
    makes this non-negotiable ("a generator fed nothing must emit nothing").
    """
    sig: list[dict[str, Any]] = []
    low = body.lower()

    if any(e in low for e in _SQL_ERRORS):
        excerpt = next((e for e in _SQL_ERRORS if e in low), "")
        i = low.find(excerpt)
        sig.append({
            "kind": "sql_error_or_behaviour",
            "statement": (f"HTTP {status} response body contains the database "
                          f"error signature {excerpt!r}: "
                          f"{body[max(0, i-90):i+160]!r}"),
            "signals": ["sql_error_or_behaviour"],
            "evidence": {"status": status, "marker": excerpt},
        })

    if any(e in low for e in _TEMPLATE_ERRORS):
        marker = next((e for e in _TEMPLATE_ERRORS if e in low), "")
        sig.append({
            "kind": "template_rendered",
            "statement": (f"HTTP {status} body contains a template-engine "
                          f"signature {marker!r}"),
            "signals": ["template_rendered"],
            "evidence": {"status": status, "marker": marker},
        })

    # A BOOLEAN DIFFERENTIAL is the highest-value signal the engine accepts:
    # two requests differing only in a predicate, returning different results.
    if len(probe_pairs) >= 2:
        base = probe_pairs[0]
        for variant in probe_pairs[1:]:
            if variant[1] is None or base[1] is None:
                continue
            if variant[1] != base[1]:
                sig.append({
                    "kind": "boolean_differential",
                    "statement": (f"{variant[0]!r} returned {variant[1]} while "
                                  f"{base[0]!r} returned {base[1]}: the "
                                  f"response varies with the injected "
                                  f"predicate"),
                    "signals": ["boolean_differential"],
                    "evidence": {"baseline": base[1], "variant": variant[1],
                                 "payload": variant[0]},
                })

    if payload and payload.lower() in body.lower() and _XSS_REFLECT.search(body):
        sig.append({
            "kind": "user_input_reflected",
            "statement": (f"payload {payload!r} is reflected in the response "
                          f"near an HTML/script sink"),
            "signals": ["user_input_reflected", "unescaped_html"],
            "evidence": {"status": status, "payload": payload},
        })

    if status is not None and 500 <= status < 600:
        sig.append({
            "kind": "server_error",
            "statement": f"HTTP {status} returned for the probed request",
            "signals": [],
            "evidence": {"status": status},
        })

    return sig


def cors_signals(head: str) -> list[dict[str, Any]]:
    acao = _header(head, "access-control-allow-origin")
    acac = _header(head, "access-control-allow-credentials")
    if acao and acao != "null":
        signals = ["cors_header_present", "origin_reflected"]
        if str(acac).lower() == "true":
            signals.append("credentials_with_wildcard")
        return [{
            "kind": "cors_header_present",
            "statement": (f"Access-Control-Allow-Origin: {acao}; "
                          f"Access-Control-Allow-Credentials: {acac}"),
            "signals": signals,
            "evidence": {"acao": acao, "acac": acac},
        }]
    return []


def security_header_signals(head: str) -> list[dict[str, Any]]:
    """Absence of hardening is evidence, but it is NOT a vulnerability class,
    so it is recorded as a contextual observation with no signals."""
    missing = [h for h in ("strict-transport-security", "content-security-policy",
                           "x-content-type-options", "x-frame-options")
               if not _header(head, h)]
    if missing:
        return [{
            "kind": "missing_security_headers",
            "statement": "absent response headers: " + ", ".join(missing),
            "signals": [],
            "evidence": {"missing": missing},
        }]
    return []


def _differential_count(body: str) -> int | None:
    """The result count in a response body, or None when there is no count.

    An EMPTY body and an unrecognisable body are different: the first means
    "no rows rendered", which is a real negative result, and conflating the
    two is how a vulnerable endpoint gets reported as untested.
    """
    if body is None:
        return None
    text = body.strip()
    if not text:
        return 0
    for rx in (_COUNT_BEFORE, _COUNT_AFTER, _BARE_COUNT):
        m = rx.search(text)
        if m:
            try:
                return int(m.group(1))
            except (TypeError, ValueError):
                continue
    return None


class ActiveHuntExecutor:
    """Performs a hunt step against a target, under an authorization verdict.

    Deliberately a CLASS and not a function: the state it needs (target,
    authorization context, tools registry, hunt id) travels together, and a
    hunt that could swap one of those between calls is a hunt whose evidence
    belongs to a different engagement than its report.
    """

    def __init__(self, con: sqlite3.Connection, ctx, *, hunt_id: str,
                 registry: tools_mod.ToolRegistry | None = None):
        self.con = con
        self.ctx = ctx
        self.hunt_id = hunt_id
        self.tools = registry or tools_mod.ToolRegistry(con, hunt_id)
        self.requests_made = 0
        # Trace failures are KEPT, not swallowed: `test_dispatch_reachability`
        # needs to tell "dispatch never ran" apart from "the trace could not be
        # written", and only the hunt itself can distinguish them.
        self.trace_errors: list[str] = []
        self._note = ""

    # -------------------------------------------------------------- gates
    def _permit_for(self, action: str, asset: str | None = None,
                    rate: bool = True) -> dict[str, Any]:
        """Ask the REAL authorization gate: `AuthorizationContext.decision`.

        MEASURED: this originally called a `permit_action` method that does not
        exist — a gate invented by the caller is not a gate, it is a
        convention. `authz.decision` (orch/authz.py:258) evaluates §57's order
        literally: authorization completeness -> NEVER_PERMITTED -> program
        forbidden_actions -> asset scope -> action vocabulary -> offensive
        permission -> rate budget. It never raises. If it is missing, this
        refuses rather than assuming permission.
        """
        dec = getattr(self.ctx, "decision", None)
        if not callable(dec):
            return {"allowed": False,
                    "reason": "authorization context exposes no decision(); "
                              "refusing to proceed on an assumption"}
        return dec(action, asset=asset, rate=rate)

    def _in_scope(self, url: str) -> tuple[bool, str]:
        """Scope is decided by the authorization layer, not re-derived here.

        `authz.decision` already refuses out-of-scope AND undetermined assets,
        so this only extracts the host for that call. Re-implementing the
        comparison here would be a second, weaker copy of a gate that exists.
        """
        host = (urlparse(url).hostname or "").lower()
        return bool(host), host or url

    # ------------------------------------------------------------ probing
    def _ledger_refusal(self, url: str, action: str, code: str,
                        detail: str) -> None:
        """Record a refusal in `tool_attempt` so it is auditable.

        Writes directly rather than going through ToolRegistry, because the
        refusals that reach here are exactly the ones where a tool was never
        selected — routing them through the registry would silently drop them.
        """
        try:
            self.con.execute(
                "INSERT INTO tool_attempt(hunt_id, tool, objective, action,"
                " target, outcome, detail, substitute, artifact, provenance,"
                " at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (self.hunt_id, "authorization", f"authorized check for {url}",
                 action, url, "refused", f"{code}: {detail}"[:2000],
                 None, None, None, f"authorization@{time.strftime('%Y-%m-%dT%H:%M:%S')}"))
            self.con.commit()
        except sqlite3.Error:
            # A ledger that cannot be written must not become a bypass: the
            # refusal still stands, and the failure is visible in the result.
            pass

    def _ledger_note(self, url: str, tool: str, detail: str) -> None:
        """Record a non-HTTP target contact (e.g. DNS) in `tool_attempt`.

        Every contact with a target belongs in the ledger, not only the ones
        that happen to go through curl.
        """
        try:
            self.con.execute(
                "INSERT INTO tool_attempt(hunt_id, tool, objective, action,"
                " target, outcome, detail, substitute, artifact, provenance, at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (self.hunt_id, tool, f"authorized {tool} lookup for {url}",
                 "recon", url, "ok", detail[:2000], None, None, None,
                 f"{tool}@{_now()}"))
            self.con.commit()
        except sqlite3.Error:
            pass

    def probe_url(self, url: str, *, action: str = "recon",
                  method: str = "GET", data: str | None = None,
                  headers: dict | None = None,
                  permit: dict[str, Any] | None = None) -> dict[str, Any]:
        """ONE authorized HTTP request. Every refusal is explicit."""
        # Defense in depth: the scope gate judges HOSTS, so it cannot judge a
        # scheme. `file:///etc/passwd` and `gopher://host:port/_x` both carry a
        # parseable hostname and would satisfy an in-scope host check while
        # reaching something that is not an HTTP service at all. MEASURED: with
        # no scheme allowlist these reached curl. They are refused now, and the
        # refusal is named rather than silently rewritten.
        scheme = (urlparse(url).scheme or "").lower()
        if scheme not in ("http", "https"):
            self._ledger_refusal(url, action, "BAD_SCHEME",
                                 f"scheme {scheme!r} is not http/https")
            return {"ok": False, "outcome": "refused", "code": "BAD_SCHEME",
                    "reason": (f"scheme {scheme!r} is not permitted; this "
                               f"executor performs HTTP(S) reconnaissance "
                               f"only"), "url": url}
        has_host, host = self._in_scope(url)
        if not has_host:
            self._ledger_refusal(url, action, "UNPARSEABLE",
                                 f"cannot determine a host from {url!r}")
            return {"ok": False, "outcome": "refused",
                    "reason": f"cannot determine a host from {url!r}", "url": url}
        permit = permit or self._permit_for(action, asset=host)
        if not permit.get("allowed"):
            # CONTROL.md I32: "a refusal with no ledger is a control nobody can
            # audit". MEASURED: this returned before touching ToolRegistry, so
            # a scope refusal left NO row in tool_attempt — the one refusal that
            # most needs to be auditable was the only one with no trace.
            code = permit.get("reason", "REFUSED")
            detail = permit.get("detail", code)
            self._ledger_refusal(url, action, str(code), str(detail))
            return {"ok": False, "outcome": "refused", "reason": str(detail),
                    "code": str(code), "url": url}
        if str(method).upper() in {"DELETE", "PUT", "PATCH"}:
            reason = (f"{method} is state-changing and this executor performs "
                      f"recognition-grade requests only")
            self._ledger_refusal(url, action, "STATE_CHANGING", reason)
            return {"ok": False, "outcome": "refused", "code": "STATE_CHANGING",
                    "reason": reason, "url": url}

        res = self.tools.run("curl", action=action, target=url,
                             objective=f"authorized probe of {url}",
                             ctx=self.ctx, permit=permit,
                             url=url, method=method, data=data,
                             headers=headers)
        self.requests_made += 1
        # The DURING_TESTING HOOK.
        #
        # MEASURED 2026-11-01: this hook was implemented but had NO non-test
        # caller. It is the hook that scores a live signal against what the
        # corpus has learned before, so wiring it here -- at the single
        # choke point every authorized HTTP request passes through -- means
        # the corpus's prior experience now reaches every probe.
        #
        # The result is attached to the response, so a caller can see how
        # strongly the corpus backs what it just observed. A hook failure
        # must never fail the probe.
        scored = self._during_testing(url, action, res)
        if isinstance(res, dict):
            res["learning_score"] = scored
        return res

    def _during_testing(self, url: str, action: str,
                        res: dict[str, Any]) -> dict[str, Any]:
        """Score this probe against the corpus's prior experience.

        Never raises. The score is an enrichment: it tells the hunt how
        strongly the corpus backs what it just saw, and it is recorded so
        the decision is auditable.
        """
        try:
            from learning_engine import engine as le
            raw = (res or {}).get("raw") or ""
            head, body = _split_response(raw)
            status = _status(head)
            sigs = (derive_signals(head=head, body=body, status=status,
                                   probe_pairs=[])
                    + cors_signals(head) + security_header_signals(head))
            names = sorted({str(s) for o in sigs for s in o.get("signals", [])
                            if s})
            if not names:
                return {"ok": True, "scored": [], "note": "no signals observed"}
            con = le.open_canonical()
            try:
                out = le.during_testing(con, {n: 1 for n in names})
            finally:
                con.close()
            self._trace("learning", "during_testing", status="success",
                        detail=f"scored {len(names)} signal(s) at {url}")
            return out
        except Exception as exc:  # noqa: BLE001 - scoring must not fail a probe
            self._trace("learning", "during_testing", status="failure",
                        detail=f"{type(exc).__name__}: {exc}"[:200])
            return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}

    def probe_differential(self, base_url: str, param: str, *,
                           canary: str = "1") -> dict[str, Any]:
        """The cheapest real test in the class: true vs false predicate.

        Returns a verdict keyed on OBSERVED difference. No difference is a
        real, reportable negative — it is not an error and not a finding.

        MEASURED: the payloads were passed to curl RAW. A single quote in a URL
        is rejected by curl itself (`curl: (3) URL rejected: Malformed input to
        a URL function`), so the two variants that carry the actual predicate
        never reached the target and the probe could only ever report "no
        difference". Percent-encode every value.
        """
        variants = [
            (canary, canary),
            # A TRUE predicate (tautology) and a FALSE one (contradiction) over
            # the SAME column. MEASURED: the first version probed only
            # AND-paired predicates, which a boolean-blind condition answers
            # identically for both rows — so a real vulnerability produced two
            # equal counts and the probe reported "no differential". A tautology
            # and a contradiction are the pair that actually separates.
            (f"{canary}{canary}", f"{canary}' OR '{canary}'='{canary}"),
            (f"{canary}{canary}{canary}",
             f"{canary}' AND '{canary}'x'='{canary}"),
        ]
        probes = []
        for label, value in variants:
            url = f"{base_url}?{quote(param, safe='')}={quote(value, safe='')}"
            r = self.probe_url(url)
            if not r.get("ok"):
                probes.append({"label": label, "url": url,
                               "outcome": r.get("outcome"),
                               "status": None, "count": None})
                continue
            head, body = _split_response(r.get("raw", ""))
            probes.append({"label": label, "url": url, "status": _status(head),
                           "count": _differential_count(body),
                           "len": len(body), "tool": r.get("tool"),
                           "provenance": r.get("provenance"),
                           # The corpus's prior for this response's signals.
                           # `probe_url` attaches it; the verdict reads it.
                           "learning_score": r.get("learning_score")})
        diffs = [x for x in probes if x["count"] is not None]
        vulnerable = False
        if len(diffs) >= 2:
            vals = {x["label"]: x["count"] for x in diffs}
            vulnerable = len(set(vals.values())) > 1 and min(vals.values()) == 0
            evidence = vals
        else:
            evidence = {}
        # THE CORPUS'S PRIOR IS CARRIED INTO THE VERDICT.
        #
        # MEASURED 2026-11-01: `during_testing` was wired and running on
        # every probe -- its score was attached to the response as
        # `learning_score` -- and NO decision consumed it. The hook reported
        # how much verified history backs the signals it saw, and the answer
        # went nowhere. The corpus knew a class was worth attacking and the
        # differential test did not know it.
        #
        # The differential probe is the one place where that prior changes
        # what to do NEXT: a class the corpus has PROVEN exploitable before
        # is worth taking to independent validation, and one it has never
        # seen is worth a second look before it is promoted. So the prior
        # is read from the probes' own `learning_score` and carried in the
        # verdict, as a recommendation and not as a confidence adjustment --
        # the prior says "this class is worth pursuing", and only evidence
        # says how sure we are.
        prior = self._prior_from_probes(probes)
        return {"url": base_url, "param": param, "probes": probes,
                "differential_observed": vulnerable, "evidence": evidence,
                "prior": prior,
                "recommended_next_step": prior.get("recommendation"),
                "note": ("result-count differential across true/false predicates "
                         "is consistent with a boolean-blind SQL condition; it "
                         "is NOT proof — see disproof and independent "
                         "validation before reporting")}

    @staticmethod
    def _prior_from_probes(probes: list[dict[str, Any]]) -> dict[str, Any]:
        """What does the corpus already know about the class these probes hit?

        The probes each carry the `learning_score` that `during_testing`
        attached to them. That score names the signal, how many VERIFIED
        lessons back it, and the average score of those lessons.

        A class with verified prior is a class this system has proven
        exploitable before. The recommendation is to take it to independent
        validation -- the corpus has paid for that research already. A class
        with no prior is not thereby safe; it is simply unfamiliar, so the
        recommendation is to corroborate before promoting.

        The answer is ADVICE, never evidence: it does not change the
        `differential_observed` verdict and it does not move a confidence
        band. A corpus that has been fooled before must not be able to
        promote its own next finding.
        """
        best: dict[str, Any] | None = None
        for p in probes:
            score = p.get("learning_score")
            if not isinstance(score, dict):
                continue
            for s in score.get("signals") or []:
                if not isinstance(s, dict):
                    continue
                n = int(s.get("prior_lessons") or 0)
                if n <= 0:
                    continue
                if best is None or n > int(best.get("prior_lessons") or 0):
                    best = {"signal": s.get("signal"),
                            "prior_lessons": n,
                            "prior_average": s.get("prior_average"),
                            "score": s.get("score")}
        if best is None:
            return {"has_prior": False, "prior_lessons": 0,
                    "recommendation": "no verified prior for this class; "
                                      "corroborate the signal before "
                                      "promoting it"}
        return {"has_prior": True, **best,
                "recommendation": "the corpus has verified lessons for this "
                                  "class; take the differential to independent "
                                  "validation"}

    # --------------------------------------------------------- orchestration
    @staticmethod
    def _confidence_from_evidence(observations: list[dict[str, Any]],
                                  requests: list[dict[str, Any]]) -> float:
        """How sure are we this is real, on the lifecycle's confidence bands?

        The bands are the ones the constitution names for the finding
        states: OBSERVATION 0%, LEAD 10-30%, HIGH-CONFIDENCE LEAD 30-60%,
        CONFIRMED 60-85%, VALIDATED 85-95%, REPORTABLE 95%+.

        This is the OBSERVATION state, so the result is deliberately capped
        below the LEAD band's ceiling. A candidate that looks certain is not
        certain: it has been observed, not validated.

        The score is built from the EVIDENCE, never from the severity:

          * how many distinct signals were observed (breadth)
          * whether more than one signal corroborates (corroboration)
          * whether the signal set matches a known class at all (specificity)

        An unknown or ambiguous classification is the strongest single
        negative signal here: if the behaviour could not be classified, the
        confidence in what it IS must be low.
        """
        sigs = {str(s).lower() for o in observations
                for s in (o.get("signals") or []) if s}
        if not sigs:
            return 0.0

        # Breadth: each distinct signal adds, with diminishing returns.
        score = min(0.12 * len(sigs), 0.36)

        # Corroboration: independent signals agreeing. A single signal is a
        # hypothesis; two agreeing signals are a lead.
        if len(sigs) >= 2:
            score += 0.10

        # Specificity: a signal set the classifier can name is a far better
        # lead than one it cannot.
        try:
            from orch.hypothesis import classify_behaviour as _classify
            verdict = _classify(sigs)
        except Exception:
            verdict = {"classification": "UNKNOWN"}
        if verdict.get("classification") not in (None, "", "UNKNOWN"):
            score += 0.14
            # Support counts how many of the class's signals matched.
            support = int(verdict.get("support") or 0)
            score += min(0.06 * support, 0.18)
        else:
            # Ambiguous or unmatched: the observation is real but its
            # meaning is not, so confidence in the CLASS must stay low.
            score -= 0.08

        # Evidence rows: a claim backed by captured responses is stronger
        # than one whose capture failed. This does not raise confidence past
        # the observation ceiling -- it only distinguishes "observed with
        # proof" from "observed with nothing".
        captured = sum(1 for r in requests if (r.get("raw") or "").strip())
        if captured:
            score += min(0.06 * captured, 0.12)

        # The OBSERVATION ceiling. LEAD starts at 10% and the band's top is
        # 30%; a candidate is below LEAD, so it is capped under 0.10.
        return round(max(0.0, min(score, 0.09)), 4)

    def record_finding(self, *, title: str, class_id: str, severity: str,
                       endpoint: str, observations: list[dict[str, Any]],
                       requests: list[dict[str, Any]],
                       hypothesis: str = "") -> dict[str, Any]:
        """Turn OBSERVED evidence into a candidate finding plus its evidence.

        MEASURED — THE LAST MILE. Before this existed, a hunt derived real
        signals (SQL error, boolean differential, CORS reflection) and then
        stopped: the signals reached the engine's trace and the CLI's summary,
        and no row was ever written to `finding`. A live hunt against a
        deliberately vulnerable lab app reported
        `observed signals: [boolean_differential, sql_error_or_behaviour]`,
        `CLASS SELECTED: sqli`, `candidates gated: 0`, and exited 0. Every
        downstream gate — dedup, final validation, reporting — reads `finding`,
        so a hunt that observed everything and filed nothing was invisible to
        the entire reporting half of the system.

        Two properties are deliberate:
          * The finding is filed as `candidate`, never `validated`. It has
            observed evidence, not proof; the final gate and an independent
            validator still decide whether it is real.
          * Every request/response is stored with a sha256, so the claim can be
            re-derived from the database rather than taken on trust.

        A third, added 2026-11-01: `confidence` is set from the EVIDENCE,
        independently of `severity`. MEASURED: `finding` carried only
        `severity`, so "how sure are we this is real" and "how bad would it
        be" were the same number, which is not true. A critical-severity
        claim resting on one ambiguous response is low confidence; a
        reproduced low-severity leak is high confidence. The scale here is
        the OBSERVATION state's share of the lifecycle's confidence bands
        (OBSERVATION 0%, LEAD 10-30%, ...), so a candidate's confidence is
        deliberately low and must be earned by promotion.
        """
        confidence = self._confidence_from_evidence(observations, requests)
        key = f"{self.hunt_id}.finding.{hashlib.sha256((title + endpoint).encode()).hexdigest()[:10]}"
        # THE FINDING'S PROVENANCE IS SET AT CREATION, FROM THE CONTEXT.
        #
        # MEASURED 2026-11-01: this filed the finding with no provenance,
        # so the column defaulted to UNKNOWN -- and UNKNOWN contributes
        # zero impact and may never be promoted. Every REAL hunt finding
        # would have been excluded from the impact calculation, which is
        # the same defect as the one this column was added to fix, pointed
        # the other way: the quarantine made test output visible, and
        # nothing made real output eligible.
        #
        # The context knows what it is: a hunt against a real target is a
        # PRODUCTION_HUNT, and a hunt against the loopback address or a
        # reserved test domain is an EVAL_TEST. The rule lives in
        # `orch/provenance.py`, so it is defined once.
        #
        # PRODUCTION IMPACT REQUIRES A RECEIPT.
        #
        # MEASURED 2026-11-02: this derived the origin from the hunt id and
        # the target alone, and asserted it. Nothing recorded that the hunt
        # was authorized -- the origin was the system making a claim about
        # itself. The hunt's authorization is now a PERSISTED FACT, written
        # by `AuthorizationContext.validate_and_record` when the
        # authorization gate passed, and this consults that receipt.
        #
        # The outcome is fail-closed in the safe direction: a hunt whose
        # authorization was never validated files its finding with an
        # UNKNOWN origin, which contributes zero impact and can never be
        # promoted -- but the finding is still FILED, because a finding is
        # evidence of an observation regardless of its eligibility.
        from . import provenance as _prov
        backed, auth_reason = _prov.authorization_backs(
            self.con, hunt_id=self.hunt_id, target=self.ctx.target)
        provenance = _prov.classify_from_context(
            hunt_id=self.hunt_id,
            hunt_kind=getattr(self.ctx, "kind", None),
            hunt_target=self.ctx.target,
            authorization_backed=backed,
            authorization_reason=auth_reason)
        try:
            fid = store.add_finding(
                self.con, key, title, target=self.ctx.target,
                asset=urlparse(endpoint).hostname or self.ctx.target,
                endpoint=endpoint, class_id=class_id, hypothesis=hypothesis
                or f"observed: {', '.join(sorted({s for o in observations for s in o.get('signals', [])}))}",
                severity=severity, confidence=confidence,
                hunt_id=self.hunt_id,
                provenance=provenance)
        except sqlite3.Error as e:
            return {"ok": False, "error": f"finding could not be filed: {e}",
                    "handler": "ActiveHuntExecutor.record_finding"}

        stored = 0
        for req in requests:
            raw = (req.get("raw") or "").strip()
            # MEASURED: this guard counted ROWS, not evidence. An empty or
            # absent `raw` still inserted a row and incremented `stored`, with
            # `sha256("")` — the hash of nothing. So a candidate shipped with an
            # empty response body and the `stored == 0` check passed, which is
            # precisely the fabricated-evidence failure this module documents it
            # exists to prevent. A request with no captured response is not
            # evidence.
            if not raw:
                continue
            # Truncate FIRST, then hash what is actually stored.
            # MEASURED: this hashed the untruncated body while storing a
            # 200 000-byte prefix, so any response over the cap produced an
            # evidence row whose sha256 did NOT match its own
            # `response_raw` — 200 000 stored bytes against a digest of the
            # full 250 000. Reproduced exactly. That is the worst shape a
            # tamper-evidence field can take: it condemns honest evidence as
            # forged. `validate.py` selects the digest but never recomputes it,
            # so nothing downstream caught it.
            stored_raw = raw[:200000]
            try:
                self.con.execute(
                    "INSERT INTO evidence(task_key, finding_id, kind, target,"
                    " asset, endpoint, request_raw, response_raw, payload, sha256,"
                    " provenance, captured_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (f"{self.hunt_id}.probe", fid, "request",
                     req.get("url"), self.ctx.target, endpoint, req.get("url"),
                     stored_raw, req.get("payload"),
                     hashlib.sha256(stored_raw.encode()).hexdigest(),
                     req.get("provenance") or "curl", _now()))
                stored += 1
            except sqlite3.Error:
                continue
        self.con.commit()

        # A candidate with no evidence is exactly the fabricated-finding
        # failure this system exists to prevent, so it is deleted, not filed.
        if stored == 0:
            try:
                self.con.execute("DELETE FROM finding WHERE id=?", (fid,))
                self.con.commit()
            except sqlite3.Error:
                pass
            return {"ok": False,
                    "error": ("observations produced no storable evidence; "
                              "refusing to file a finding with none"),
                    "handler": "ActiveHuntExecutor.record_finding"}

        try:
            self.con.execute(
                "INSERT OR IGNORE INTO event(event_key, kind, source, detail,"
                " created_at) VALUES (?,?,?,?,?)",
                (f"{self.hunt_id}.finding.{fid}", "finding", self.ctx.target,
                 title, _now()))
            self.con.commit()
        except sqlite3.Error:
            pass

        # The AFTER_FINDING HOOK.
        #
        # MEASURED 2026-11-01: this hook was implemented in
        # `learning_engine/engine.py` but had NO non-test caller -- it
        # existed only in documentation and tests. A finding filed by a live
        # hunt produced no lesson, so the corpus never learned from the hunt
        # and the learning loop was open at its first link.
        #
        # The hook CAPTURES the outcome as a lesson in state `captured`. That
        # is deliberately not `verified`: a captured lesson is a claim that
        # something was learned, which the verification step later decides.
        # The hook must never fail the filing of a finding.
        learning = self._after_finding(class_id, title, severity, confidence,
                                       observations)

        return {"ok": True, "finding_id": fid, "finding_key": key,
                "class_id": class_id, "severity": severity,
                "confidence": confidence,
                "evidence_rows": stored, "title": title,
                "learning": learning}

    def _after_finding(self, class_id: str, title: str, severity: str,
                       confidence: float,
                       observations: list[dict[str, Any]]) -> dict[str, Any]:
        """Capture this finding as a lesson. Never raises.

        The learning engine is optional: a hunt must still file its finding
        when the engine is unavailable. The failure is reported, not hidden.
        """
        try:
            from learning_engine import engine as le
            from . import provenance as _prov
            con = le.open_canonical()
            try:
                signals = sorted({str(s) for o in observations
                                  for s in (o.get("signals") or []) if s})
                backed, _why = _prov.authorization_backs(
                    con, hunt_id=self.hunt_id, target=self.ctx.target)
                auth_ref = getattr(self.ctx, "authorization_ref", None)
                out = le.after_finding(
                    con, target=self.ctx.target,
                    vulnerability_class=class_id,
                    signals={s: 1 for s in signals},
                    validation_state="candidate",
                    # THE LESSON INHERITS THE FINDING'S ORIGIN.
                    #
                    # MEASURED 2026-11-01: this passed no origin, and
                    # `after_finding` derived one from the TARGET alone --
                    # so a lab hunt against a routable-looking target
                    # would be recorded as PRODUCTION_HUNT even though
                    # the authorization context says `kind="lab"`.
                    # The finding and its lesson must agree.
                    #
                    # MEASURED 2026-11-02: the origin is now derived from
                    # the PERSISTED AUTHORIZATION RECEIPT, on the same rule
                    # the finding used -- so the lesson cannot claim a
                    # stronger origin than the finding it came from.
                    origin=_prov.classify_from_context(
                        hunt_id=self.hunt_id,
                        hunt_kind=getattr(self.ctx, "kind", None),
                        hunt_target=self.ctx.target,
                        authorization_backed=backed),
                    # AND THE RECEIPT ITSELF IS PASSED.
                    #
                    # The origin above is a CLASSIFICATION; the hunt id and
                    # authorization ref are the RECEIPT. `capture_hook`
                    # checks the receipt row before it will accept a
                    # production origin, so without these two arguments a
                    # production finding's lesson was DOWNGRADED to
                    # UNKNOWN -- the finding said PRODUCTION_HUNT and its
                    # lesson said UNKNOWN, and they must agree.
                    hunt_id=self.hunt_id if backed else None,
                    authorization_ref=auth_ref if backed else None,
                    source_provenance={"severity": severity,
                                       "confidence": confidence,
                                       "title": title,
                                       "hunt_id": self.hunt_id})
            finally:
                con.close()
            self._trace("learning", "after_finding", status="success",
                        detail=f"captured lesson for {class_id}")
            return out
        except Exception as exc:  # noqa: BLE001 - capture must not fail a finding
            self._trace("learning", "after_finding", status="failure",
                        detail=f"{type(exc).__name__}: {exc}"[:200])
            return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}

    def can_handle(self, key: str) -> bool:
        """Does this executor have a handler for this task key?

        MEASURED: the CLI dispatched on `key.startswith("hunt.")`, which also
        matched `*.unknown.research.*`, `*-audit` and the decompose-generated
        `*.1-audit`/`*.2-build`/`*.3-test` keys. Every one of those returned
        "no active handler", and because the result was never written back to
        the task they stayed `running` forever — crowding `recon.http`, the only
        step that can produce a finding, out of every wave. Capability, not
        prefix.

        MEASURED 2026-10-31: this method then LOST ITS BODY and returned
        False for every key — the exact total-dispatch regression the
        `eval/test_dispatch_reachability.py` suite exists to catch, present
        in the tree the suite was written for. The symptom was a hunt that
        ran to COMPLETE, exited 0, and gated 14 candidate findings while
        never dispatching a single task to a handler: no trace entry, no
        outcome, no recon. The CLI summary read like a healthy hunt.

        The body is restored to the capability test the docstring above
        describes, and `run_step` dispatches on the SAME predicates, so the
        two cannot disagree. The check that guards this is R3 of
        `eval/test_dispatch_reachability.py`, which injects `return False`
        and asserts the artifact then records ZERO entries — so a
        regression here turns the suite red instead of green.
        """
        k = (key or "").lower()
        if ".recon." in k:
            return True
        return k.endswith((".surface.build", ".hypotheses.generate",
                            ".skill.resolve"))

    # ------------------------------------------------------------- dispatch trace
    #
    # The artifact `eval/test_dispatch_reachability.py` reads. It exists
    # because the scorer proved it could not see a dispatch break: with
    # `can_handle` returning False for everything, `masterprompt_score.py` still
    # printed 100.0/100 (65/65). A check that cannot fail is worse than none.
    #
    # Three properties, from an adversarial review of the design:
    #   1. ENTRY — a row is written BEFORE any handler work, so "handler never
    #      invoked" is distinguishable from "handler invoked and failed".
    #   2. TERMINATION — the outcome row is written in `finally`, so a crash
    #      mid-handler cannot silently skip it.
    #   3. PROVENANCE — each record carries run id and wall-clock mtime, so a
    #      stale artifact from an earlier run can never satisfy the check.
    def _trace_path(self) -> str | None:
        """Where the dispatch trace goes, or None when tracing is off."""
        return os.environ.get("HERMES_DISPATCH_TRACE") or None

    def _trace(self, phase: str, task_key: str, **extra: Any) -> None:
        """Append one dispatch record.

        A trace that cannot be written is reported, NOT swallowed. MEASURED: this
        originally caught OSError and passed, so a trace path the child could
        not open (an MSYS path handed to native python, say) made the hunt run
        perfectly while writing nothing — and the reachability check then
        reported five phantom failures that looked exactly like a dispatch
        regression. An untraceable run now says so loudly in its own summary, so
        the cause is never mistaken for the effect.
        """
        path = self._trace_path()
        if not path:
            return
        try:
            rec = {"phase": phase, "task_key": task_key,
                   "handler": type(self).__name__,
                   "run_id": self.hunt_id, "pid": os.getpid(),
                   "at": time.time(), **extra}
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
        except OSError as e:
            # Recording the failure ON the hunt run means it appears in the CLI
            # summary; swallowing it is what made this undiagnosable.
            self.trace_errors.append(f"{type(e).__name__}: {e}")
            self._note = (f"dispatch trace UNWRITABLE at {path!r} "
                          f"({type(e).__name__}: {e}) - dispatch is unverified")

    def run_step(self, task_row: sqlite3.Row) -> dict[str, Any]:
        """Execute one hunt task row. Returns the executor contract dict.

        The trace bracketing here is what makes a dispatch failure OBSERVABLE
        from outside the process. `entry` is written before any handler work and
        `outcome` in a `finally`, so the four states the check distinguishes are
        all reachable and distinct:
            no entry          -> the dispatcher never selected this handler
            entry + failure   -> invoked, and it failed
            entry, no outcome -> crashed or hung mid-handler
            entry + success   -> invoked and completed
        """
        key = (task_row["task_key"] or "").lower()
        self._trace("entry", key)
        try:
            if ".recon." in key:
                out = self._step_recon(key)
            elif key.endswith(".surface.build"):
                out = self._step_surface()
            elif key.endswith(".hypotheses.generate"):
                out = self._step_hypotheses()
            elif key.endswith(".skill.resolve"):
                out = self._step_skills()
            else:
                out = {"ok": False, "handler": "ActiveHuntExecutor",
                       "error": f"no active handler for {key!r}",
                       "summary": f"refused: no active handler for {key!r}"}
            self._trace("outcome", key, status="success" if out.get("ok")
                        else "failure",
                        detail=str(out.get("summary", out.get("error", "")))[:200])
            return out
        except BaseException as e:  # noqa: BLE001 - the trace must survive
            self._trace("outcome", key, status="failure",
                        detail=f"{type(e).__name__}: {e}"[:200])
            raise

    def _step_recon(self, key: str) -> dict[str, Any]:
        kind = key.rsplit(".", 1)[-1]
        # The BEFORE_RECON HOOK.
        #
        # MEASURED 2026-11-01: all five adaptive hooks were implemented in
        # `learning_engine/engine.py`, but four of them had NO non-test
        # caller -- `before_recon`, `during_testing`, `after_finding` and
        # `before_summary` existed only in documentation and tests. The
        # learning corpus could therefore never influence a hunt: a lesson
        # verified yesterday could not change what today's hunt looks at.
        #
        # The hook's output is the corpus's VERIFIED lessons for the classes
        # already learned on this target. They are returned to the caller AND
        # used to PRIORITISE the recon, so a verified lesson changes what the
        # hunt does, not merely what it prints.
        #
        # A hook failure must never kill the hunt: the lessons are an
        # enrichment, not a precondition.
        # MEASURED — THE PLAN NEVER NAMED A TARGET. A recon task key ends in a
        # CATEGORY, not a host: `hunt.<id>.recon.http`. Reading the target from
        # the key produced `https://recon.http`, which is not a resolvable
        # name, so every probe either refused or silently tested nothing. The
        # targets are the hunt's DECLARED IN-SCOPE ASSETS, which the engine
        # already recorded as surface nodes. Read them from there.
        hosts = self._targets()
        prior = self._before_recon_lessons()
        if not hosts:
            return self._no_target(kind)
        if kind == "dns":
            return self._recon_dns(hosts, prior=prior)
        if kind == "tls":
            return self._recon_tls(hosts, prior=prior)
        if kind == "js":
            return self._recon_js(hosts, prior=prior)
        return self._recon_http(hosts, prior=prior)

    def _no_target(self, kind: str) -> dict[str, Any]:
        return {"ok": False, "handler": "ActiveHuntExecutor.recon",
                "error": f"no in-scope target known for {kind} recon",
                "summary": (f"recon.{kind}: no in-scope host to probe; the "
                            f"surface has no node the authorization layer "
                            f"accepts")}

    def _before_recon_lessons(self) -> list[dict[str, Any]]:
        """The corpus's verified lessons for this target's classes.

        Never raises. A learning failure costs the hunt its prior knowledge,
        which is a degradation, not a stop: the hunt continues without it and
        the reason is recorded.
        """
        try:
            from learning_engine import engine as le
            con = le.open_canonical()
            try:
                out = le.before_recon(con, self.ctx.target)
            finally:
                con.close()
            lessons = out.get("lessons") or []
            if lessons:
                self._trace("learning", "before_recon",
                            status="success",
                            detail=f"{len(lessons)} verified lesson(s) for "
                                   f"{self.ctx.target}")
            return list(lessons)
        except Exception as exc:  # noqa: BLE001 - enrichment must not kill the hunt
            self._trace("learning", "before_recon", status="failure",
                        detail=f"{type(exc).__name__}: {exc}"[:200])
            return []

    def _targets(self) -> list[str]:
        """In-scope host nodes for this hunt, as URLs.

        MEASURED: this first read `surface_node.asset` / `.in_scope`, which do
        not exist — the real columns are `node_key`, `name`, `kind`, `observed`
        (orch/surface.py:37-47). An unknown column raises OperationalError,
        which the `except sqlite3.Error` below swallowed into "no targets",
        so the recon step reported a clean, confident "nothing to probe".
        A blanket except around a wrong query is how a bug becomes a result.
        """
        rows = []
        try:
            rows = self.con.execute(
                "SELECT name, kind, observed FROM surface_node WHERE hunt_id=?"
                " AND kind='host' ORDER BY node_key", (self.hunt_id,)).fetchall()
        except sqlite3.Error as e:
            return [] if "no such column" not in str(e).lower() else [
                f"__schema_error__:{e}"]
        out: list[str] = []
        for r in rows:
            name = str(r["name"] or "").strip()
            if not name:
                continue
            # MEASURED: a surface node recorded as `http://127.0.0.1:8931`
            # came back as `http://127.0.0.1` — the PORT was dropped, so the
            # probe hit :80 and reported `Failed to connect ... after 2033 ms`
            # against a service that was listening and healthy. Prefer the
            # recorded node verbatim over re-normalising it.
            out.append(name if "://" in name else f"http://{name}")
        if out:
            return out
        target = (getattr(self.ctx, "target", "") or "").strip()
        return [target if "://" in target else f"http://{target}"] if target else []

    # ------------------------------------------------------------- recon
    def _recon_http(self, hosts: list[str],
                    prior: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        results, filed, sigs_all = [], [], []
        # The corpus's PRIOR CLASSES. A class the corpus has a VERIFIED lesson
        # for is one this system has seen work before, so it is worth
        # looking for again here. The learned priority is applied to the
        # findings this recon raises -- the lesson changes what the hunt
        # FILES FIRST, not merely what it reports.
        prior_classes = self._prior_classes(prior)
        for host in hosts:
            res = self.probe_url(host)
            if not res.get("ok"):
                results.append({"host": host, "outcome": res.get("outcome"),
                                "reason": res.get("reason", "")[:200]})
                continue
            head, body = _split_response(res.get("raw", ""))
            status = _status(head)
            sigs = (derive_signals(head=head, body=body, status=status,
                                   probe_pairs=[])
                    + cors_signals(head) + security_header_signals(head))
            sigs_all += sigs
            all_signals = sorted({s for o in sigs for s in o.get("signals", [])})
            classified = classify_behaviour(all_signals).get("classification")
            requests = [{"url": host, "raw": res.get("raw", ""),
                         "status": status, "payload": None,
                         "provenance": res.get("provenance")}]
            for sev, cid, title in self._rank(sigs, classified):
                f = self.record_finding(title=title, class_id=cid, severity=sev,
                                        endpoint=host, observations=sigs,
                                        requests=requests)
                if f.get("ok"):
                    filed.append(f)
            # THE LEARNED PRIORITY IS APPLIED HERE. A finding whose class
            # the corpus has a VERIFIED lesson for is filed with a higher
            # PRIORITY, and the findings are ORDERED by that priority.
            #
            # This is the read-back that makes the learning loop a loop: a
            # lesson verified on one hunt changes the priority of a finding
            # raised on a later hunt. MEASURED 2026-11-01: the `lesson`
            # table was read by NOTHING in a production path -- the corpus
            # could not influence a hunt at all.
            for f in filed:
                if str(f.get("class_id") or "").lower() in prior_classes:
                    store.set_finding_axes(self.con, f["finding_key"],
                                           priority=2)
                    f["prior_boosted"] = True
            filed.sort(key=lambda x: (0 if x.get("prior_boosted") else 1,
                                      x.get("finding_key", "")))
            for obs in sigs:
                self.record_observation(obs, phase="recon.http")
            # The response is the attack surface. MEASURED 2026-11-01: before
            # this, a hunt recorded only HOST names (247 host nodes across
            # every hunt in the database, and not one endpoint, service or
            # technology), so nothing downstream — the report, or the skill
            # resolution that governs it — could see the surface that
            # actually answered.
            enriched = self._enrich_surface(host, head, body, status)
            results.append({"host": host, "status": status,
                            "signals": sorted(all_signals),
                            "classified": classified,
                            "len": len(body),
                            "surface_nodes": enriched,
                            "title": (_header(head, "server") or ""),
                            "provenance": res.get("provenance")})
        ok = [r for r in results if "status" in r]
        return {"ok": bool(ok), "handler": "ActiveHuntExecutor.recon.http",
                "probed": len(results), "reachable": len(ok),
                "results": results, "findings_filed": filed,
                "summary": (f"HTTP recon: {len(ok)}/{len(results)} host(s) "
                            f"answered; {len(filed)} candidate finding(s) "
                            f"filed")}

    def _recon_dns(self, hosts: list[str],
                   prior: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        found = []
        for url in hosts:
            h = urlparse(url).hostname or url
            # MEASURED — DNS CONTACTED THE NETWORK OUTSIDE EVERY RAIL. This
            # called `socket.getaddrinfo` directly: no authorization decision, no
            # `tool_attempt` row, no rate charge. So the module's own claim —
            # "this file is the only place requests happen and every attempt is
            # ledgered" — was false for the one recon step that runs before any
            # HTTP probe. Ask the gate and write the ledger row, or refuse.
            permit = self._permit_for("recon", asset=h, rate=True)
            if not permit.get("allowed"):
                found.append({"host": h, "resolved": False,
                              "outcome": "refused",
                              "reason": permit.get("detail",
                                                   permit.get("reason"))})
                self._ledger_refusal(url, "recon", str(permit.get("reason",
                                                                  "REFUSED")),
                                     str(permit.get("detail", "")))
                continue
            try:
                import socket
                infos = socket.getaddrinfo(h, None)
                addrs = sorted({i[4][0] for i in infos})
            except Exception as e:  # noqa: BLE001 - unresolvable is data
                found.append({"host": h, "resolved": False,
                              "error": f"{type(e).__name__}: {e}"})
                self._ledger_note(url, "dns", f"unresolvable: {e}")
                continue
            found.append({"host": h, "resolved": True, "addresses": addrs})
            self._ledger_note(url, "dns", f"resolved to {addrs}")
        return {"ok": any(f["resolved"] for f in found),
                "handler": "ActiveHuntExecutor.recon.dns", "results": found,
                "summary": (f"DNS: {sum(1 for f in found if f['resolved'])}/"
                            f"{len(found)} host(s) resolved")}

    def _recon_tls(self, hosts: list[str],
                   prior: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        out = []
        for url in hosts:
            # MEASURED — THE PORT AND SCHEME WERE DISCARDED. This rebuilt the
            # target as `https://{hostname}/`, dropping both the scheme and the
            # port: a node recorded as `http://app.example.test:8931` was
            # contacted on :443. The host check passed, so the executor reported
            # success against an endpoint nobody authorized. Probe the host as
            # it was recorded and derive the https attempt FROM it.
            parsed = urlparse(url)
            probe = url if url.startswith("https://") else \
                f"https://{parsed.netloc}{parsed.path or '/'}"
            h = parsed.hostname or url
            r = self.probe_url(probe)
            out.append({"host": h, "port": parsed.port,
                        "probed": probe,
                        "https_ok": bool(r.get("ok")),
                        "outcome": r.get("outcome"),
                        "reason": str(r.get("reason", ""))[:200],
                        "note": "TLS certificate collection requires an "
                                "adapter that reads the negotiated "
                                "certificate; reported as UNKNOWN rather "
                                "than claimed"})
        return {"ok": True, "handler": "ActiveHuntExecutor.recon.tls",
                "results": out,
                "summary": f"TLS: probed {len(out)} host(s) over https"}

    def _recon_js(self, hosts: list[str],
                   prior: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        out = []
        for host in hosts:
            h = urlparse(host).hostname or host
            r = self.probe_url(host.rstrip("/") + "/", action="recon")
            head, body = _split_response(r.get("raw", "")) if r.get("ok") else ("", "")
            scripts = sorted(set(re.findall(r'src=["\']([^"\']+\.js[^"\']*)',
                                            body))) if body else []
            out.append({"host": h, "scripts": scripts[:50],
                        "count": len(scripts)})
        return {"ok": True, "handler": "ActiveHuntExecutor.recon.js",
                "results": out,
                "summary": (f"JS: found "
                            f"{sum(o['count'] for o in out)} script reference(s)")}

    @staticmethod
    def _prior_classes(prior: list[dict[str, Any]] | None) -> set[str]:
        """The bug classes the corpus has VERIFIED lessons for.

        This is what makes the learning loop a loop rather than a log: a
        class with a verified lesson is a class this system has PROVEN
        exploitable before, so it is worth looking for again -- and a finding
        in that class is worth filing ahead of one in a class the corpus
        knows nothing about.
        """
        out: set[str] = set()
        for lesson in (prior or []):
            if not isinstance(lesson, dict):
                continue
            cid = str(lesson.get("class_id") or "").strip()
            if cid:
                out.add(cid.lower())
        return out

    @staticmethod
    def _rank(sigs: list[dict[str, Any]],
              classified: str | None) -> list[tuple[str, str, str]]:
        """(severity, class_id, title) for each OBSERVED signal set.

        Severity comes from the evidence class, not from a constant: a
        boolean-blind SQL condition with an error leak is high, an absent
        security header is not a finding at all and is excluded by having no
        signals.
        """
        by_sig = {s for o in sigs for s in o.get("signals", [])}
        out: list[tuple[str, str, str]] = []
        if {"sql_error_or_behaviour"} & by_sig:
            if {"boolean_differential"} & by_sig:
                out.append(("high", "sqli",
                            "Boolean-blind SQL condition with database error "
                            "disclosure"))
            else:
                out.append(("medium", "sqli",
                            "Database error message disclosure on a quoted "
                            "input"))
        if {"boolean_differential"} & by_sig and not {"sql_error_or_behaviour"} & by_sig:
            out.append(("high", "sqli",
                        "Boolean-blind SQL condition (true/false predicate "
                        "yields different result counts)"))
        if {"cors_header_present", "origin_reflected"} <= by_sig:
            if "credentials_with_wildcard" in by_sig:
                out.append(("high", "cors",
                            "Arbitrary Origin reflected with "
                            "Access-Control-Allow-Credentials: true"))
            else:
                out.append(("medium", "cors",
                            "Arbitrary Origin reflected in "
                            "Access-Control-Allow-Origin"))
        if {"user_input_reflected"} & by_sig:
            out.append(("medium", "xss",
                        "User input reflected into an executable HTML context"))
        if not out and classified and classified != "UNKNOWN":
            # MEASURED — THIS FILED A FINDING WITH NOTHING BEHIND IT. The
            # fallback fired on `classified != "UNKNOWN"` alone, so a single
            # classification produced an `info` finding even when `by_sig` was
            # EMPTY. Proven: `_rank([{'signals': []}], 'sqli')` returned
            # `[('info','sqli','Observed behaviour consistent with sqli')]` — a
            # finding whose only "evidence" was a root GET body that said
            # nothing. That is precisely the fabricated-finding failure this
            # module documents it exists to prevent, in the one place where the
            # operator would never notice it.
            #
            # A finding requires at least one OBSERVED signal that supports the
            # class. `classify_behaviour` answers UNKNOWN for an empty signal
            # set, so the guard is belt-and-braces: refuse whenever there is no
            # supporting evidence, whatever the classifier said.
            if not by_sig:
                return []
            out.append(("info", classified,
                        f"Observed behaviour consistent with {classified} "
                        f"(signals: {', '.join(sorted(by_sig))})"))
        return out

    def record_observation(self, obs: dict[str, Any], *,
                           phase: str = "recon") -> None:
        """Persist one observation into `hunt_observation`.

        The engine reads this table to build hypotheses, so an observation that
        lives only in a return value is invisible to the next cycle.
        """
        try:
            self.con.execute(
                "INSERT INTO hunt_observation(obs_key, hunt_id, phase, kind,"
                " statement, source, signals, at) VALUES (?,?,?,?,?,?,?,?)",
                (f"obs.{self.hunt_id}.{abs(hash(json.dumps(obs, sort_keys=True, default=str))) % (10 ** 12)}",
                 self.hunt_id, phase, obs.get("kind", "note"),
                 obs.get("statement", "")[:2000], "active_probe",
                 json.dumps(sorted(obs.get("signals", []))), _now()))
            self.con.commit()
        except sqlite3.Error:
            pass

    def _step_surface(self) -> dict[str, Any]:
        inv = self.tools.inventory()
        return {"ok": True, "handler": "ActiveHuntExecutor.surface",
                "tool_inventory": inv,
                "summary": ("tool inventory resolved: "
                            + ", ".join(f"{t['tool']}="
                                        f"{'yes' if t['available'] else 'no'}"
                                        for t in inv))}

    # ------------------------------------------------------------- surface
    def _enrich_surface(self, url: str, head: str, body: str,
                        status: int) -> list[dict[str, Any]]:
        """Turn a real HTTP response into ATTACK SURFACE nodes.

        MEASURED 2026-11-01: every surface node the project had ever created
        was of kind `host` — 247 of them, across every hunt in the database,
        and not one endpoint, service or technology. The hunt recorded the
        HOSTS it was pointed at and then stopped. Consequences, all real:

          * the attack surface the report claims to contain was a list of
            hostnames;
          * `skill.resolve` (the step added in this same change) had nothing
            to resolve against but a hostname, so it could only ever produce
            a generic reconnaissance skill — MEASURED: the live run resolved
            `domains/web/host_header/skills/SKILL.md` for a host node, on a
            vocabulary overlap of ONE token;
          * no skill could ever be resolved for the thing that actually gets
            tested, which is an ENDPOINT.

        A response carries the surface: the endpoint that answered, the
        service it exposed, the technology it announced, and the headers
        that describe the boundary. Those are OBSERVED facts from the wire,
        so they are recorded with `observed=True` and the request that
        produced them as their evidence.
        """
        from orch import surface as surface_mod

        created: list[dict[str, Any]] = []
        try:
            s = surface_mod.Surface(self.con, self.hunt_id)
        except sqlite3.Error:
            return created

        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "http").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        def _add(kind: str, name: str, **attrs) -> None:
            if not name:
                return
            try:
                key = s.add_node(kind, name, observed=True,
                                 evidence=f"HTTP {status} from {url}", **attrs)
                created.append({"kind": kind, "name": name, "node_key": key})
            except (sqlite3.Error, KeyError):
                pass

        # The endpoint that actually answered. The observed class is
        # recorded on the node so the skill resolution that follows can
        # name the class it derived -- the registry's routes ARE class
        # names, so a scenario that names the class reaches its route
        # exactly instead of falling through to loose metadata matching.
        endpoint_attrs: dict[str, Any] = {"method": "GET", "status": status,
                                          "scheme": scheme, "host": host,
                                          "port": port}
        observed_signals = sorted({
            s for o in derive_signals(head=head, body=body, status=status,
                                      probe_pairs=[])
            for s in o.get("signals", [])})
        classified = classify_behaviour(observed_signals).get("classification")
        if classified:
            endpoint_attrs["class_id"] = classified
        # The observed SIGNALS are recorded on the node. They are what names
        # the relevant class: the registry's class vocabulary is built from
        # them ("reflected", "cors", "differential", ...), so a node that
        # carries them resolves to the class it actually exhibits.
        if observed_signals:
            endpoint_attrs["signals"] = observed_signals[:12]
        _add("endpoint", f"{scheme}://{host}{path}", **endpoint_attrs)

        # The service the port exposes.
        _add("service", f"{host}:{port}", host=host, port=port,
             protocol=scheme, secure=(scheme == "https"))

        # The technology, when the server announced one.
        server = (_header(head, "server") or "").strip()
        if server:
            _add("technology", server.lower(), tech=server, vendor=server)

        # The framework, when it announced itself.
        powered = (_header(head, "x-powered-by") or "").strip()
        if powered:
            _add("technology", powered.lower(), tech=powered)

        # The security boundary, from the headers that describe it.
        boundary_attrs = {
            "cors": bool(_header(head, "access-control-allow-origin")),
            "csp": bool(_header(head, "content-security-policy")),
            "hsts": bool(_header(head, "strict-transport-security")),
            "cookie_flags": (_header(head, "set-cookie") or "")[:200],
        }
        if any(boundary_attrs.values()):
            _add("boundary", f"{host} trust boundary", host=host,
                 **boundary_attrs)

        return created

    def _step_skills(self) -> dict[str, Any]:
        """Resolve, LOAD and RECORD the skills that govern this hunt's surface.

        MEASURED 2026-11-01: this step did not exist. `runtime/registry.json`
        held 474 skills and 62 routes and the resolver worked, but the only
        caller of the registry in the entire tree was
        `scripts/runtime_preflight.py` — so the orchestrator never resolved a
        skill for a surface it had just discovered, and the SKILL GATE that
        AGENTS.md states for every test could not be obeyed by the component
        that performs the tests.

        The step does three things, in this order, because each one can fail
        in a way that must not be hidden:

          1. resolve the scenario for every discovered surface node;
          2. LOAD the skill file, so what is applied is the content and not
             merely the path;
          3. RECORD the resolution in `hunt_skill_resolution`, with the
             content digest, so "which skill governed this test" is auditable
             after the fact.

        A surface with no resolvable skill is recorded as a DEFERRAL with a
        reason. It is not an error and it is not a silent success: the hunt
        continues, and the gap is visible.
        """
        from orch import skill_resolver

        out = skill_resolver.resolve_for_hunt(self.con, self.hunt_id,
                                               mode="hunt")
        applied = out.get("applied") or []
        deferred = out.get("deferred") or []
        classes = out.get("classes") or []

        # Record the resolution in the hunt's own event log, so the run
        # summary can state what guidance applied.
        try:
            self.con.execute(
                "INSERT INTO event(event_key, kind, source, detail, created_at)"
                " VALUES (?,?,?,?,?)",
                (f"{self.hunt_id}.skills.resolved", "skill_resolution",
                 getattr(self.ctx, "target", "unknown"),
                 f"{len(applied)} skill(s) applied across "
                 f"{out.get('surfaces', 0)} surface(s); "
                 f"{len(deferred)} deferral(s)", _now()))
            self.con.commit()
        except sqlite3.Error:
            pass

        names = ", ".join(sorted({str(a.get("class_id") or a.get("name"))
                                  for a in applied})) or "none"
        return {
            "ok": True,
            "handler": "ActiveHuntExecutor.skill.resolve",
            "surfaces": out.get("surfaces", 0),
            "resolved": len(applied),
            "deferred": len(deferred),
            "classes": classes,
            "applied": [{"path": a["path"], "class_id": a.get("class_id"),
                         "matched_by": a.get("matched_by"),
                         "sha256": a.get("sha256"),
                         "bytes": a.get("bytes")} for a in applied],
            "deferrals": deferred,
            "summary": (f"skills resolved for {out.get('surfaces', 0)} "
                        f"surface(s): {len(applied)} loaded "
                        f"({names}); {len(deferred)} deferred"),
        }

    def _step_hypotheses(self) -> dict[str, Any]:
        rows = self.con.execute(
            "SELECT kind, statement, signals FROM hunt_observation "
            "WHERE hunt_id=? ORDER BY at", (self.hunt_id,)).fetchall()
        signals: set[str] = set()
        for r in rows:
            signals |= set(json.loads(r["signals"] or "[]"))
        cls = classify_behaviour(sorted(signals))
        return {"ok": True, "handler": "ActiveHuntExecutor.hypotheses",
                "classified_class": cls.get("classification"),
                "support": cls.get("support"),
                "reason": cls.get("reason", ""),
                "summary": (f"classified {len(signals)} observed signal(s) as "
                            f"{cls.get('classification')}"
                            + (f" ({cls.get('reason')})" if cls.get("reason")
                               else ""))}


def install(con: sqlite3.Connection, ctx, *, hunt_id: str):
    """Bind an ActiveHuntExecutor as an orchestrator-executor callable."""
    ex = ActiveHuntExecutor(con, ctx, hunt_id=hunt_id)

    def _run(row: sqlite3.Row, _ctx: dict[str, Any] | None = None) -> dict[str, Any]:
        return ex.run_step(row)

    _run.__name__ = "active_hunt_executor"
    return _run