"""Write-up processing pipeline for Cyber OS.

MEASURED DEFECT THIS REPAIRS: `.opencode/commands/update.md` documents a
four-stage write-up pipeline (fetch into `writeups/raw/`, process into
`writeups/processed/` with triple-layer dedup, rebuild `writeups/index.md` as a
table, distil lessons into `memory/report-lessons.md`), but no Python module
anywhere in the repository implemented it. Measured on 2026-10-31:
`writeups/raw/`, `writeups/processed/`, `writeups/metadata/` and
`writeups/feeds/` were ALL empty, `writeups/index.md` contained only the
header line, and nothing wrote to `writeups/raw` or `writeups/processed`.

SOURCE OF TRUTH: `.opencode/commands/update.md` (the `/update` command
specification). The pipeline implements exactly the raw -> processed -> index
-> lessons stages that specification describes; the later stages of that
command (methodology/patterns/targets refresh) belong to other components and
are NOT implemented here.

The package sits at the top level because it writes KNOWLEDGE artifacts
(`writeups/`) and calls the `wks/` knowledge layer plus the
`learning_engine/` capture hook; it owns no database and no second source of
truth. The canonical database remains `db/wks.db`, opened through
`wks.store.open_db()`.
"""

from .pipeline import (  # noqa: F401
    all_stages,
    classify,
    extract_all_lessons,
    extract_lessons,
    ingest_raw,
    process_all,
    process_one,
    propose_research,
    rebuild_index,
    write_lessons_markdown,
)

__all__ = [
    "ingest_raw",
    "classify",
    "process_one",
    "process_all",
    "rebuild_index",
    "extract_lessons",
    "extract_all_lessons",
    "write_lessons_markdown",
    "propose_research",
    "all_stages",
]
