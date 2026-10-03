"""Source access states + polite, bounded HTTP.

Two measured failure modes this module exists to close (audit 2026-10-02):

1. A rate-limited host returned HTTP 429 and the fetch layer had NO branch for
   it. A throttled wave therefore produced items that read as permanently
   unverifiable instead of retryable, and nothing anywhere in the tree honoured
   `Retry-After`. `pipeline.fetch` had no `429`, no backoff, no pacing.

2. The `source` table recorded neither a fetch result nor an access state, so
   the store could not tell a page that was fetched from one that was merely
   declared. `http_status` and `content_hash` were NULL on 473/473 rows, which
   also made staleness undetectable -- `metrics.stale_rate_pct` was reporting
   0.0 for "not measured".

Division of labour, chosen so nothing is parsed twice:

    wks.http      the REQUEST: one exchange, the retry policy, `Retry-After`,
                  per-host pacing, and mapping an exchange to an access state.
    wks.pipeline  the TEXT: entity decoding, tag stripping, sanitising, the
                  JS-shell mirror, and the quote-gated 404 resolver.

`http` never imports `pipeline` and never parses a body into prose. Two
implementations of "the text of a page" is how a genuine quote silently stops
verifying: one side strips entities, the other does not, and the gate reports
fabrication.

Access states -- a closed vocabulary:

    ACTIVE            fetched, prose returned, quotes verifiable
    RATE_LIMITED      host returned 429 after the retry budget was spent
    BLOCKED           401/403/451 or another 4xx -- refused to this client
    PAYWALLED         the response requires a subscription
    BROWSER_REQUIRED  200 with a client-rendered shell and no prose
    STALE             previously ACTIVE, now unreachable or content-changed
    UNVERIFIED        never successfully fetched (the honest default)

A state is a FACT about an exchange, never an assertion. Nothing here writes
`validation_state`; `wks/quality.py` remains the only writer of that column.
"""
from __future__ import annotations

import calendar
import hashlib
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

# --------------------------------------------------------------------------
# Closed vocabulary. `problems()` self-checks it, the way wks/research_sources.py
# does for its tiers, so a typo cannot silently invent a new state.
# --------------------------------------------------------------------------
ACCESS_STATES = {
    "ACTIVE": "fetched, prose returned, quotes verifiable against this page",
    "RATE_LIMITED": "host answered 429 after the retry budget was spent",
    "BLOCKED": "401/403/451 or another 4xx -- refused to this client",
    "PAYWALLED": "the response requires a subscription",
    "BROWSER_REQUIRED": "200 with a client-rendered shell and no prose",
    "STALE": "previously ACTIVE, now unreachable or the content changed",
    "UNVERIFIED": "never successfully fetched (the honest default)",
}

# States that mean "do not retry this cycle without human help".
HARD_BLOCKED = ("BLOCKED", "PAYWALLED", "BROWSER_REQUIRED")

# Retry policy. `Retry-After` wins when the server sends a parsable one;
# otherwise capped exponential backoff. Three attempts survived a real 429
# burst in testing without stalling a wave -- long enough to ride out a short
# window, short enough that an overnight run is not held by a dead host.
MAX_ATTEMPTS = 3
BACKOFF_BASE = 1.5
BACKOFF_CAP = 20.0
MAX_RETRY_AFTER = 60.0

# Per-host politeness floor. The measured incident was 4 concurrent children all
# hitting one host; this makes the second request wait instead of joining the
# stampede. It is a per-host floor, NOT the global concurrency cap -- that is a
# separate control (orch/concurrency.py).
HOST_MIN_INTERVAL = 0.75

_last_hit: dict[str, float] = {}
_rate_state: dict[str, dict[str, Any]] = {}


def reset_throttle() -> None:
    """Clear per-host pacing and rate state. Tests call this between cases."""
    _last_hit.clear()
    _rate_state.clear()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def host_of(url: str) -> str:
    from urllib.parse import urlparse
    h = (urlparse(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def problems() -> list[str]:
    """Self-check: the vocabulary and retry policy stay internally sane."""
    bad: list[str] = []
    for required in ("ACTIVE", "RATE_LIMITED", "BLOCKED", "PAYWALLED",
                     "BROWSER_REQUIRED", "STALE", "UNVERIFIED"):
        if required not in ACCESS_STATES:
            bad.append(f"missing required access state {required!r}")
    if MAX_ATTEMPTS < 1:
        bad.append("MAX_ATTEMPTS must be >= 1")
    if BACKOFF_CAP < BACKOFF_BASE:
        bad.append("BACKOFF_CAP below BACKOFF_BASE")
    if MAX_RETRY_AFTER < 0:
        bad.append("MAX_RETRY_AFTER must be >= 0")
    if HOST_MIN_INTERVAL < 0:
        bad.append("HOST_MIN_INTERVAL must be >= 0")
    return bad


# --------------------------------------------------------------------------
# Retry-After
# --------------------------------------------------------------------------
_RETRY_AFTER_INT = re.compile(r"^\s*(\d+)\s*$")
_RETRY_AFTER_HTTP = re.compile(
    r"^\s*(?:[A-Za-z]{3},\s*)?(\d{2})\s+([A-Za-z]{3})\s+(\d{4})\s+"
    r"(\d{2}):(\d{2}):(\d{2})\s+GMT\s*$")
_MONTHS = {m: i + 1 for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"))}


def parse_retry_after(value: str | None, *, now: float | None = None) -> float | None:
    """Seconds to wait, from a `Retry-After` header.

    Both documented forms: delta-seconds (`120`) and HTTP-date
    (`Wed, 21 Oct 2026 07:28:00 GMT`). Returns None when absent or
    unparseable, so the caller falls back to its own backoff rather than
    treating a malformed value as "retry immediately" -- which is how a
    throttling host turns one bad header into a ban.
    """
    if not value:
        return None
    m = _RETRY_AFTER_INT.match(value)
    if m:
        return max(0.0, min(float(m.group(1)), MAX_RETRY_AFTER))
    m = _RETRY_AFTER_HTTP.match(value)
    if m:
        # Groups are (day, month, year, hour, minute, second); timegm wants
        # (year, month, day, hour, minute, second). These were transposed, so
        # every HTTP-date raised ValueError and degraded to "no Retry-After" --
        # caught by T24 rather than by reading the code.
        # The month is a NAME in an HTTP-date ("Wed, 21 Oct 2026 07:28:00 GMT"),
        # not a number. `int()` on it raised ValueError, which the except below
        # turned into None -- so every dated Retry-After silently degraded to
        # "no Retry-After given" and used the wrong backoff on precisely the
        # hosts that told us when to return. The `_MONTHS` table existed for
        # this and was unused.
        month = _MONTHS.get(m.group(2))
        if month is None:
            return None
        try:
            when = calendar.timegm((
                int(m.group(3)), month, int(m.group(1)),
                int(m.group(4)), int(m.group(5)), int(m.group(6)), 0, 0, 0))
        except (ValueError, OverflowError, IndexError):
            return None
        delta = when - (time.time() if now is None else now)
        return max(0.0, min(delta, MAX_RETRY_AFTER))
    return None


# --------------------------------------------------------------------------
# Per-host pacing + rate bookkeeping
# --------------------------------------------------------------------------
def _throttle(host: str) -> None:
    if not host:
        return
    last = _last_hit.get(host)
    if last is not None:
        gap = time.monotonic() - last
        if gap < HOST_MIN_INTERVAL:
            time.sleep(HOST_MIN_INTERVAL - gap)
    _last_hit[host] = time.monotonic()


def note_rate_limited(host: str, wait: float | None) -> None:
    st = _rate_state.setdefault(host, {"count": 0, "last_at": None, "last_wait": None})
    st["count"] += 1
    st["last_at"] = now_iso()
    st["last_wait"] = wait


def rate_limited_hosts() -> dict[str, dict[str, Any]]:
    """Hosts that answered 429 in this process. The audit and health checks read
    this; it is the observable half of the rate-limit control."""
    return {h: dict(v) for h, v in _rate_state.items()}


# --------------------------------------------------------------------------
# State classification
# --------------------------------------------------------------------------
_PAYWALL = re.compile(
    r"(subscribe\s+to\s+(continue|read)|sign\s+in\s+to\s+(continue|read)"
    r"|this\s+content\s+is\s+for\s+(subscribers|members)"
    r"|become\s+a\s+(member|subscriber)\s+to\s+read"
    r"|you\s+have\s+reached\s+your\s+(article|free)\s+limit)", re.I)


def classify(status: int | None, body: str = "", *, had_shell: bool = False) -> str:
    """Map a completed exchange onto the closed vocabulary.

    A 200 is not proof of content: that is the HackerOne lesson this tree
    already records (`browser-not-supported.html` returned with HTTP 200), so a
    shell response is BROWSER_REQUIRED rather than ACTIVE.
    """
    if status == 429:
        return "RATE_LIMITED"
    if status is not None and 400 <= status < 500:
        return "BLOCKED"
    if status is not None and status >= 500:
        return "UNVERIFIED"
    if had_shell:
        return "BROWSER_REQUIRED"
    if body and _PAYWALL.search(body[:8000]):
        return "PAYWALLED"
    if status is not None and 200 <= status < 300:
        return "ACTIVE"
    return "UNVERIFIED"


def content_hash(text: str) -> str:
    """Stable hash of prose, for staleness detection.

    Hashing a raw body would mark every page stale on any CDN rotation, so this
    hashes the extracted text -- the same bytes a quote is matched against.
    """
    if not text:
        return None
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:32]


# --------------------------------------------------------------------------
# One exchange
# --------------------------------------------------------------------------
def _header(headers, name: str) -> str | None:
    try:
        return headers.get(name)
    except AttributeError:
        return None


def request_once(url: str, *, limit: int, timeout: int,
                 user_agent: str) -> dict[str, Any]:
    """Exactly one HTTP request. Never raises; a dead source is data.

    Returns the RAW exchange. It does not parse prose -- `wks.pipeline` owns
    that -- but it does carry the body, because a 4xx error page and a paywall
    notice are classified FROM the body.
    """
    host = host_of(url)
    _throttle(host)
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read(limit)
            return {"url": url, "host": host, "status": int(r.status),
                    "raw": raw, "content_type": r.headers.get("Content-Type", ""),
                    "retry_after": _header(r.headers, "Retry-After"),
                    "error": None, "retrieved_at": now_iso()}
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(limit)
        except Exception:
            raw = b""
        return {"url": url, "host": host, "status": int(e.code), "raw": raw,
                "content_type": _header(e.headers, "Content-Type") or "",
                "retry_after": _header(e.headers, "Retry-After"),
                "error": str(e), "retrieved_at": now_iso()}
    except Exception as e:  # network, TLS, timeout, DNS, bad status line
        return {"url": url, "host": host, "status": None, "raw": b"",
                "content_type": "", "retry_after": None,
                "error": f"{type(e).__name__}: {e}", "retrieved_at": now_iso()}


def fetch_raw(url: str, *, limit: int = 400_000, timeout: int = 25,
              user_agent: str = "WKS-Research/2.0 (knowledge curation; contact: local)",
              max_attempts: int = MAX_ATTEMPTS) -> dict[str, Any]:
    """`request_once` wrapped in the retry policy.

    Contract relied on by `wks.pipeline.fetch`, `wks.verify_quotes` and
    `wks.ingest`:

      * never raises;
      * `rate_limited` is True ONLY when the retry budget was spent against
        429, so a throttled host is retryable rather than fabricated;
      * `attempts` / `waited_seconds` / `retry_after_honoured` say what was spent;
      * `access_state` is always a member of ACCESS_STATES.
    """
    host = host_of(url)
    attempts = 0
    waited = 0.0
    honoured = False
    got: dict[str, Any] = {}

    while attempts < max_attempts:
        attempts += 1
        got = request_once(url, limit=limit, timeout=timeout, user_agent=user_agent)
        if got.get("status") != 429:
            break
        if attempts >= max_attempts:
            # Budget spent against a throttling host. Record it as such.
            note_rate_limited(host, parse_retry_after(got.get("retry_after")))
            break
        wait = parse_retry_after(got.get("retry_after"))
        if wait is None:
            wait = min(BACKOFF_CAP, BACKOFF_BASE ** attempts)
        else:
            honoured = True
        time.sleep(wait)
        waited += wait

    status = got.get("status")
    return {
        "url": url, "host": host, "status": status,
        "raw": got.get("raw", b""),
        "content_type": got.get("content_type", ""),
        "error": got.get("error"),
        "retrieved_at": got.get("retrieved_at", now_iso()),
        "attempts": attempts,
        "waited_seconds": round(waited, 2),
        "retry_after_honoured": honoured,
        "rate_limited": status == 429,
        "access_state": classify(status),
    }


def describe() -> str:
    """Machine-readable policy, so an audit can print what the host enforces
    instead of asserting it."""
    import json
    return json.dumps({
        "states": ACCESS_STATES,
        "hard_blocked": list(HARD_BLOCKED),
        "max_attempts": MAX_ATTEMPTS,
        "backoff": {"base": BACKOFF_BASE, "cap": BACKOFF_CAP,
                    "honours_retry_after": True,
                    "max_retry_after": MAX_RETRY_AFTER},
        "host_min_interval_seconds": HOST_MIN_INTERVAL,
        "rate_limited_hosts": rate_limited_hosts(),
    }, indent=1)


if __name__ == "__main__":  # pragma: no cover - operator convenience
    import json as _json
    bad = problems()
    print(_json.dumps({"problems": bad, "policy": _json.loads(describe())}, indent=1))
    raise SystemExit(1 if bad else 0)