"""Cyber OS learning engine — the adaptive-memory hooks.

The public surface is `LearningEngine`, which the loaded skill documents as:

    from learning_engine import LearningEngine
    engine = LearningEngine()

The engine writes to the CANONICAL database (`db/wks.db`), not to a private
one. See `learning_engine/engine.py` for why the former second database was
retired.
"""
from .engine import (  # noqa: F401
    LearningEngine,
    analyze_hook,
    after_finding,
    after_triage,
    before_recon,
    before_summary,
    capture_hook,
    during_testing,
    migrate_legacy,
    open_canonical,
    research_hook,
    update_hook,
    verify_hook,
)

__all__ = [
    "LearningEngine",
    "capture_hook", "analyze_hook", "research_hook", "verify_hook",
    "update_hook",
    "before_recon", "during_testing", "after_finding", "after_triage",
    "before_summary",
    "migrate_legacy", "open_canonical",
]
