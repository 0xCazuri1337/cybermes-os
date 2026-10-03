"""Orchestration layer.

Separated from wks/ on purpose. wks/ is the knowledge engine and carries
invariant I6 (research, not intrusion) plus CONTROL's layer ownership;
orchestration owns WORK, not knowledge, and must stay removable without
touching the quality gate. Same database file, two schemas, two owners.

Order of dependency:
    store -> dag -> priority -> validate -> events -> agents -> orchestrator
                              \\-> scope/capability --------------------^
"""
from __future__ import annotations

__all__ = ["store", "dag", "priority", "validate", "events", "agents",
           "scope", "orchestrator", "selfaudit", "workers"]