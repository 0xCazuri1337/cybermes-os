"""Event helpers: relevance scoring and signal intake (spec §41, §42).

Relevance decides whether a signal is allowed to create work. An event system
with no relevance threshold is a task spammer that eventually stops being read,
which is worse than having no event system at all — the operator learns to
ignore the channel.

The scoring is declared and inspectable so a wrong ranking can be corrected
rather than merely resented.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any

from . import store

# A signal that matches more of the system's live weaknesses scores higher.
# Read from the live corpus rather than a static list, so relevance tracks the
# knowledge base as it grows instead of drifting from it.
DOMAIN_TERMS = {
    "web": ["xss", "csrf", "sqli", "sql injection", "ssrf", "idor", "bola",
            "oauth", "jwt", "session", "cors", "graphql", "xxe", "ssti",
            "deserialization", "race", "open redirect", "prototype pollution"],
    "api": ["api", "graphql", "rest", "grpc", "websocket", "endpoint",
            "authorization", "authentication", "rate limit", "mass assignment"],
    "network": ["smb", "ldap", "kerberos", "ntlm", "dns", "rdp", "smtp",
                "lateral movement", "pivot", "privilege escalation", "ad",
                "active directory", "bloodhound", "kerberoasting", "asrepro"],
    "infra": ["cloud", "s3", "iam", "kubernetes", "container", "vpc",
              "metadata", "bucket", "misconfiguration"],
}

# Signals that must never autonomously become work, whatever their confidence:
# they are exactly the claims that produced fabricated evidence before.
TRUSTED_KINDS = {"cve", "advisory", "vendor", "standard", "taxonomy"}
LEAD_ONLY_KINDS = {"social", "forum", "rumor", "unverified"}

# Just below the default action threshold (0.5). A community lead can rank
# against other leads and inform research, but must never auto-create work.
LEAD_ONLY_CEILING = 0.49


def relevance(signal: dict[str, Any], corpus_terms: set[str] | None = None
              ) -> float:
    """0.0..1.0 relevance of a signal to the system's current work.

    Four factors, each of which can drive the score to zero on its own:
      authority  — is this a source that can be trusted at face value?
      relevance  — does it touch a term the corpus actually cares about?
      novelty    — is it new, or a restatement?
      actionability — can this system act on it, or only note it?
    """
    kind = (signal.get("kind") or "").lower()
    text = " ".join(str(signal.get(k, "")) for k in
                    ("title", "summary", "description", "cve", "topic")).lower()

    # authority
    if kind in LEAD_ONLY_KINDS:
        authority = 0.25
    elif kind in TRUSTED_KINDS:
        authority = 1.0
    else:
        authority = 0.6

    # topical relevance
    terms = corpus_terms if corpus_terms is not None else _corpus_terms()
    hits = sum(1 for t in terms if t and t in text)
    topical = min(1.0, hits / 3.0) if hits else 0.0

    # novelty
    novelty = 1.0 if signal.get("is_new", True) else 0.2

    # actionability — this system researches and validates; it does not patch
    # fleets or deploy. A signal needing an action it cannot take is a lead,
    # not work.
    need = (signal.get("needs_action") or "research").lower()
    actionability = {"research": 1.0, "validate": 1.0, "hunt": 0.8,
                     "remediate": 0.2, "patch": 0.1}.get(need, 0.5)

    score = (0.35 * authority + 0.35 * topical + 0.15 * novelty
             + 0.15 * actionability)

    # A lead-only source can NEVER cross the work threshold on topicality
    # alone. The ceiling lives HERE rather than in the caller, because a caller-
    # side cap means two entry points (ingest, simulate) can disagree about
    # what a signal is worth — and the one that disagrees is the one being read
    # before deciding whether to act.
    if kind in LEAD_ONLY_KINDS:
        score = min(score, LEAD_ONLY_CEILING)
    return round(min(1.0, score), 4)


def _corpus_terms() -> set[str]:
    """Terms the live corpus actually contains, so relevance tracks reality."""
    import sqlite3 as _s
    from wks import config as wc
    p = wc.db_path()
    if not p.exists():
        return set()
    try:
        con = _s.connect(p)
        rows = con.execute("SELECT id, name FROM bug_class").fetchall()
        con.close()
    except _s.Error:
        return set()
    terms: set[str] = set()
    for cid, name in rows:
        for t in DOMAIN_TERMS.values():
            terms.update(t)
        terms.add((name or "").lower())
        terms.add(cid.replace("_", " "))
    return {t for t in terms if t}


def ingest(con: sqlite3.Connection, signals: list[dict[str, Any]]
           ) -> dict[str, Any]:
    """Score, dedupe, and store inbound signals."""
    terms = _corpus_terms()
    accepted, capped, dupes = 0, 0, 0
    for s in signals:
        key = s.get("event_key") or _derive_key(s)
        if not key:
            continue
        kind = (s.get("kind") or "signal").lower()
        rel = relevance(s, terms)
        if kind in LEAD_ONLY_KINDS and rel >= 0.5:
            rel = 0.49
            capped += 1
        if store.emit_event(con, key, kind, source=s.get("source", ""),
                            severity=s.get("severity", "info"),
                            payload=s, relevance=rel):
            accepted += 1
        else:
            dupes += 1
    return {"accepted": accepted, "capped_leads": capped, "duplicates": dupes}


def _derive_key(s: dict[str, Any]) -> str:
    """A stable identity for a signal with no explicit key."""
    import hashlib
    basis = "|".join(str(s.get(k, "")) for k in
                     ("cve", "url", "title", "topic"))
    if not basis.strip("|"):
        return ""
    return "sig." + hashlib.sha256(basis.encode()).hexdigest()[:16]


def pending(con: sqlite3.Connection, threshold: float = 0.5) -> list[dict[str, Any]]:
    return [
        {"event_key": r["event_key"], "kind": r["kind"], "source": r["source"],
         "relevance": r["relevance"], "created_at": r["created_at"],
         "payload": r["payload_json"]}
        for r in store.open_events(con, min_relevance=threshold)
    ]


def simulate(con: sqlite3.Connection, signals: list[dict[str, Any]]
             ) -> list[dict[str, Any]]:
    """Score without writing. Used by tests to prove the scorer can fail."""
    terms = _corpus_terms()
    out = []
    for s in signals:
        out.append({"event_key": s.get("event_key") or _derive_key(s),
                    "kind": s.get("kind", "signal"),
                    "relevance": relevance(s, terms)})
    return sorted(out, key=lambda r: -r["relevance"])