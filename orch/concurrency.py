"""The 2-child concurrency cap, as code.

MEASURED (audit 2026-10-02): a 4-child research wave lost 3 of 4 children to
`HTTP 429: exceeded the rate limit on your API key`. The recovery was written
down -- `CONTROL/OPERATOR.md` says "Waves of 2" -- and `grep -rn "waves of 2"
--include=*.py` returned ZERO hits. A rule that exists only in prose is not a
control: any agent, plugin or cron prompt that did not read the doc violates it
silently, and nothing fails.

So the cap lives here, and it lives in the PATH, not in the documentation:

  * `orchestrator.run` truncates every wave to the cap before executing;
  * `orch/executor.py` asserts it at the single point tasks are dispatched;
  * `plan_wave()` (the function that hands research work to a child) refuses to
    emit more than the cap;
  * `budget()` is the one number, so the docs and the code cannot drift.

Deliberately NOT a global semaphore over threads. The orchestrator executes a
wave sequentially by design; what it lacked was a bound on how many TASKS (and
therefore how many potential children) one wave could contain. Capping the wave
is the honest fix; a lock would have added machinery without changing the
failure.

Override: `WKS_MAX_RESEARCH_CHILDREN` exists for a deliberate wider wave, and
it is recorded, so an override is visible rather than silent.
"""
from __future__ import annotations

import os
from typing import Iterable, Sequence

# The measured number. 4 lost 3 of 4 children; 2 survived.
DEFAULT_MAX_CHILDREN = 2
ENV_VAR = "WKS_MAX_RESEARCH_CHILDREN"


def budget() -> int:
    """The cap for one wave, as an int >= 1.

    An env override is honoured but never allowed below 1: a zero or negative
    cap would silently disable the wave entirely, which is the failure mode a
    "safety limit" must not have.
    """
    raw = os.environ.get(ENV_VAR)
    if not raw:
        return DEFAULT_MAX_CHILDREN
    try:
        val = int(raw)
    except ValueError:
        return DEFAULT_MAX_CHILDREN
    return val if val >= 1 else DEFAULT_MAX_CHILDREN


def is_overridden() -> bool:
    return bool(os.environ.get(ENV_VAR))


def cap(wave: Sequence, limit: int | None = None) -> list:
    """Truncate a wave to the cap, preserving order.

    Order matters: `priority.rank` already sorted this list, so truncating is
    taking the highest-priority work and DROPPING the rest into the next wave,
    not choosing arbitrarily.
    """
    n = limit if limit is not None else budget()
    return list(wave)[:max(1, n)]


def dropped(wave: Sequence, limit: int | None = None) -> list:
    """The tasks a cap pushed to the next wave. Returned, never silently lost."""
    n = limit if limit is not None else budget()
    return list(wave)[max(1, n):]


def problems() -> list[str]:
    """Self-check. A cap that can be disabled to 0 is not a cap."""
    bad = []
    if DEFAULT_MAX_CHILDREN < 1:
        bad.append("DEFAULT_MAX_CHILDREN must be >= 1")
    n = budget()
    if n < 1:
        bad.append(f"budget() returned {n}; a cap must allow at least one task")
    return bad


def describe() -> dict:
    return {
        "max_children_per_wave": budget(),
        "default": DEFAULT_MAX_CHILDREN,
        "env_var": ENV_VAR,
        "overridden": is_overridden(),
        "evidence": ("MEASURED 2026-10-02: a 4-child wave lost 3 of 4 to "
                     "HTTP 429; a single-route model.yaml means there is no "
                     "fallback provider to absorb it"),
    }


def describe_text() -> str:
    import json
    return json.dumps(describe(), indent=1)


if __name__ == "__main__":  # pragma: no cover - operator convenience
    import json
    print(json.dumps({"problems": problems(), "policy": describe()}, indent=1))
    raise SystemExit(1 if problems() else 0)