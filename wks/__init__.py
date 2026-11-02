"""WKS — Web & API Knowledge System.

Research, curation, retrieval and self-evaluation for practical web/API hunting
knowledge. Research and knowledge only: this package performs no active testing
against any target (brief §4).

Layering (each module may import only from those above it):
    config -> store -> quality -> retrieval -> pipeline -> cli
"""
__all__ = ["config", "store", "quality", "retrieval", "pipeline"]
VERSION = "1.0.0"
