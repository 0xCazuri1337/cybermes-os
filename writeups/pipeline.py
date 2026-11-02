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

DESIGN NOTES
------------
Dedup is the triple layer the `/update` spec names:

  1. exact URL            -- the same write-up fetched twice from two feeds
  2. normalized title     -- the same write-up with different whitespace/case
  3. content hash         -- SHA256 of the first 300 characters, which
                             catches a re-fetch whose title drifted

A write-up is skipped if ANY layer matches an already-processed write-up.
The layer that matched is recorded, because "skipped: duplicate" is only
useful if you can tell WHICH layer said so.

The `processed/` file is the durable artefact. The `metadata/` sidecar is
the durable DEDUP INDEX: it holds the three keys so the next run can decide
without re-reading every processed file. Both are read back on a later run,
so dedup survives a restart.

`classify()` maps a write-up to a bug class using the SAME taxonomy the rest
of the system uses (`wks.taxonomy_ext.CATALOG`), by matching the class's
name and aliases against the title and body. It does NOT invent a second
vocabulary. A write-up that matches nothing is `unclassified`, and that is
recorded rather than forced into a class.

Lessons extracted from a write-up are recorded through
`learning_engine.capture_hook`, which is IDEMPOTENT -- the same lesson
body yields the same `lesson_key` and does not create a second row. That is
what makes re-running the pipeline safe.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

# The project root is the parent of this package.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

RAW_DIR = ROOT / "writeups" / "raw"
PROCESSED_DIR = ROOT / "writeups" / "processed"
METADATA_DIR = ROOT / "writeups" / "metadata"
INDEX_PATH = ROOT / "writeups" / "index.md"
LESSONS_PATH = ROOT / "memory" / "report-lessons.md"

# The generated section of `memory/report-lessons.md`.
#
# MEASURED 2026-10-31: the generator used to rewrite the WHOLE file, which
# silently destroyed four hand-curated lessons on the first run. The
# markers are the contract that makes the generation non-destructive:
# everything above `BEGIN GENERATED` is the operator's, everything between
# the markers is the generator's.
BEGIN_GENERATED = "<!-- BEGIN GENERATED -->"
END_GENERATED = "<!-- END GENERATED -->"

# The `/update` spec names these sources as the layout of `writeups/raw/`.
SOURCES = (
    "github", "hackerone", "medium", "yeswehack", "bugboard",
    "projectzero", "vickieli", "nahamsec", "cobalt", "cloudflare",
)

# The first 300 characters are the content-hash window the spec names.
HASH_WINDOW = 300

# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------

_WS = re.compile(r"\s+")
_PUNCT = re.compile(r"[^\w\s]")
_FENCE = re.compile(r"^```.*?^```", re.DOTALL | re.MULTILINE)
_INLINE_CODE = re.compile(r"`[^`]*`")
_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
_HTML = re.compile(r"<[^>]+>")


def normalize_title(title: str) -> str:
    """Normalize a title for the dedup layer.

    Lowercased, punctuation stripped, whitespace collapsed. So "SQL Injection
    in Acme!" and "sql injection in acme" are the same title.
    """
    t = unicodedata.normalize("NFKD", title or "")
    t = t.replace("’", "'").replace("‘", "'")
    t = _PUNCT.sub(" ", t.lower())
    return _WS.sub(" ", t).strip()


def content_hash(text: str) -> str:
    """SHA256 of the first 300 characters of the normalised body.

    The spec says "content hash SHA256 of first 300 chars". The body is
    stripped of code fences and markup first, because a write-up that
    differs only in its markdown formatting is the same write-up.
    """
    t = _FENCE.sub(" ", text or "")
    t = _INLINE_CODE.sub(" ", t)
    t = _LINK.sub(r"\1", t)
    t = _HTML.sub(" ", t)
    t = _WS.sub(" ", t).strip()
    return hashlib.sha256(t[:HASH_WINDOW].encode("utf-8")).hexdigest()


def extract_url(text: str, default: str = "") -> str:
    """Find the canonical URL of a write-up in its body.

    Looks for the first bare URL that is not obviously a repository asset
    (an image, a badge, a stylesheet). Falls back to `default`.
    """
    best = ""
    for m in re.finditer(r"https?://[^\s<>\"')\]]+", text or ""):
        url = m.group(0).rstrip(".,;:")
        low = url.lower()
        if any(low.endswith(ext) for ext in (
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico",
                ".woff", ".woff2", ".ttf")):
            continue
        if "shields.io" in low or "badge" in low:
            continue
        best = url
        break
    return best or default


def slugify(text: str, maxlen: int = 60) -> str:
    """A filesystem-safe slug."""
    t = unicodedata.normalize("NFKD", text or "")
    t = t.encode("ascii", "ignore").decode("ascii")
    t = re.sub(r"[^A-Za-z0-9]+", "-", t).strip("-").lower()
    return (t[:maxlen].rstrip("-") or "untitled")


# ---------------------------------------------------------------------------
# classification
# ---------------------------------------------------------------------------

def _taxonomy_patterns() -> list[tuple[str, list[str]]]:
    """The class_id -> match-terms map, derived from the system taxonomy.

    Built lazily from `wks.taxonomy_ext.CATALOG` so the pipeline cannot
    drift from the taxonomy the rest of the system uses. Each class
    contributes its name and its aliases.
    """
    from wks.taxonomy_ext import CATALOG
    out: list[tuple[str, list[str]]] = []
    for entry in CATALOG:
        class_id = entry[0]
        name = entry[1]
        aliases = list(entry[6]) if len(entry) > 6 else []
        terms = [name] + list(aliases)
        # The bare class_id is a term too, but only as a WORD -- "xss" must
        # not match inside "xssx" or "crosssite".
        terms.append(r"\b" + re.escape(class_id) + r"\b")
        out.append((class_id, terms))
    return out


def classify(title: str, body: str = "") -> dict[str, Any]:
    """Classify a write-up into a bug class.

    Returns `{"class_id": ..., "confidence": ..., "matched": [...]}`. A
    write-up that matches no class gets `class_id="unclassified"` and
    `confidence=0.0` -- it is NOT forced into the nearest class, because a
    wrong class sends the lesson to the wrong destination and teaches the
    system the wrong thing.

    Scoring: a term found in the TITLE is worth 3, a term in the first 2000
    characters of the body is worth 1. The class with the highest score
    wins; a tie is broken by class_id for determinism.
    """
    title_l = (title or "").lower()
    body_l = (body or "")[:2000].lower()
    scores: dict[str, int] = {}
    matched: dict[str, list[str]] = {}
    for class_id, terms in _taxonomy_patterns():
        score = 0
        hits: list[str] = []
        for term in terms:
            pattern = term if term.startswith(r"\b") else re.escape(term)
            if re.search(pattern, title_l, re.IGNORECASE):
                score += 3
                hits.append(term)
            elif re.search(pattern, body_l, re.IGNORECASE):
                score += 1
                hits.append(term)
        if score:
            scores[class_id] = score
            matched[class_id] = hits
    if not scores:
        return {"class_id": "unclassified", "confidence": 0.0, "matched": []}
    best = max(sorted(scores), key=lambda c: scores[c])
    total = sum(scores.values())
    return {"class_id": best,
            "confidence": round(scores[best] / total, 3),
            "matched": matched[best]}


# ---------------------------------------------------------------------------
# dedup index
# ---------------------------------------------------------------------------

def _meta_path(processed_path: Path) -> Path:
    """The dedup sidecar for a processed write-up.

    Named after the PROCESSED artifact, not the raw source, so the sidecar
    and the file it describes travel together: one processed write-up, one
    sidecar, same stem.
    """
    return METADATA_DIR / (processed_path.stem + ".json")


def load_index() -> dict[str, dict[str, str]]:
    """Load the dedup index from `writeups/metadata/`.

    Returns `{key: {"layer": ..., "path": ..., "title": ...}}` where `key`
    is one of `url:...`, `title:...`, `hash:...`.
    """
    index: dict[str, dict[str, str]] = {}
    if not METADATA_DIR.is_dir():
        return index
    for p in sorted(METADATA_DIR.glob("*.json")):
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        for layer in ("url", "title", "hash"):
            key = data.get(f"{layer}_key")
            if key:
                index[key] = {"layer": layer, "path": data.get("path", ""),
                              "title": data.get("title", "")}
    return index


def _write_meta(processed_path: Path, source_path: Path, title: str,
                url: str, chash: str, class_id: str) -> Path:
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    path = _meta_path(processed_path)
    path.write_text(json.dumps({
        "path": str(processed_path.relative_to(ROOT)),
        "source_path": (str(source_path.relative_to(ROOT))
                        if source_path.is_relative_to(ROOT)
                        else str(source_path)),
        "title": title,
        "url": url,
        "url_key": f"url:{url}",
        "title_key": f"title:{normalize_title(title)}",
        "hash_key": f"hash:{chash}",
        "content_hash": chash,
        "class_id": class_id,
        "processed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# stages
# ---------------------------------------------------------------------------

def ingest_raw(source: str, title: str, body: str, *,
               url: str = "", when: str | None = None,
               filename: str | None = None) -> Path:
    """Stage 1: write a write-up into `writeups/raw/<source>/`.

    The `/update` spec names the filename shape
    `writeups/raw/[source]/[topic]_[timestamp].md`. `timestamp` is
    `%Y%m%dT%H%M%SZ`.

    Returns the path written.
    """
    source = (source or "unknown").strip().lower()
    if source not in SOURCES:
        # An unknown source is still a valid directory -- the spec's list is
        # "etc." -- but it is normalised so `HackerOne` and `hackerone` are
        # one directory.
        source = slugify(source) or "unknown"
    ts = when or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    stem = filename or f"{slugify(title)}_{ts}"
    if not stem.endswith(".md"):
        stem += ".md"
    d = RAW_DIR / source
    d.mkdir(parents=True, exist_ok=True)
    path = d / stem
    front = [f"title: {title}", f"source: {source}"]
    if url:
        front.append(f"url: {url}")
    front.append(f"ingested_at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    path.write_text("---\n" + "\n".join(front) + "\n---\n\n" + (body or ""),
                    encoding="utf-8")
    return path


def _split_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Parse the simple `key: value` frontmatter this pipeline writes."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    head = text[3:end].strip("\n")
    rest = text[end + 4:].lstrip("\n")
    meta: dict[str, str] = {}
    for line in head.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            meta[k.strip()] = v.strip()
    return meta, rest


def _extract_title(meta: dict[str, str], body: str, fallback: str) -> str:
    if meta.get("title"):
        return meta["title"]
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("#"):
            return line.lstrip("#").strip()
        if line:
            break
    return fallback.replace("_", " ").replace("-", " ").strip() or fallback


def process_one(source_path: str | Path, *,
                index: dict[str, dict[str, str]] | None = None,
                write_index: bool = True) -> dict[str, Any]:
    """Stage 2: process one raw write-up into `writeups/processed/`.

    Applies the triple-layer dedup. On a duplicate, the write-up is
    SKIPPED -- the processed file is not rewritten and no lesson is
    extracted again.

    On a new write-up, it writes:
      * `writeups/processed/<slug>.md`  -- the normalised write-up
      * `writeups/metadata/<slug>.json` -- the dedup keys

    Returns a result dict: `{"status": ..., "reason": ..., "path": ...}`.
    `status` is one of `processed`, `skipped`, `error`.
    """
    src = Path(source_path)
    if not src.is_absolute():
        src = ROOT / src
    if not src.is_file():
        return {"status": "error", "reason": "source file not found",
                "path": str(src)}
    try:
        text = src.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return {"status": "error", "reason": f"unreadable: {e}",
                "path": str(src)}

    meta, body = _split_frontmatter(text)
    title = _extract_title(meta, body, src.stem)
    url = meta.get("url") or extract_url(body)
    chash = content_hash(body)

    url_key = f"url:{url}" if url else ""
    title_key = f"title:{normalize_title(title)}"
    hash_key = f"hash:{chash}"

    if index is None:
        index = load_index()
    for layer, key in (("url", url_key), ("title", title_key),
                       ("hash", hash_key)):
        if key and key in index:
            # The spec's triple-layer dedup: ANY layer matching means
            # duplicate. The layer is reported so the operator can see
            # which rule fired.
            return {"status": "skipped", "reason": f"duplicate:{layer}",
                    "layer": layer, "duplicate_of": index[key].get("path", ""),
                    "path": str(src), "title": title}

    cls = classify(title, body)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    out_name = f"{slugify(title)}.md"
    out = PROCESSED_DIR / out_name
    front = [
        f"title: {title}",
        f"class_id: {cls['class_id']}",
        f"confidence: {cls['confidence']}",
    ]
    if url:
        front.append(f"url: {url}")
    front.append(f"content_hash: {chash}")
    front.append(f"source_path: {src.relative_to(ROOT) if src.is_relative_to(ROOT) else src}")
    front.append(f"processed_at: {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    out.write_text("---\n" + "\n".join(front) + "\n---\n\n" + body,
                   encoding="utf-8")

    if write_index:
        _write_meta(out, src, title, url, chash, cls["class_id"])
        index[url_key] = {"layer": "url", "path": str(out), "title": title}
        index[title_key] = {"layer": "title", "path": str(out), "title": title}
        index[hash_key] = {"layer": "hash", "path": str(out), "title": title}

    return {"status": "processed", "reason": "new", "path": str(out),
            "title": title, "class_id": cls["class_id"],
            "confidence": cls["confidence"], "url": url,
            "content_hash": chash, "source_path": str(src)}


def process_all(raw_dir: str | Path | None = None, *,
                write_index: bool = True) -> dict[str, Any]:
    """Stage 2 for every raw write-up.

    Returns `{"processed": n, "skipped": n, "errors": n, "results": [...]}`.
    """
    raw = Path(raw_dir) if raw_dir else RAW_DIR
    if not raw.is_absolute():
        raw = ROOT / raw
    index = load_index()
    results: list[dict[str, Any]] = []
    if raw.is_dir():
        for p in sorted(raw.rglob("*.md")):
            results.append(process_one(p, index=index, write_index=write_index))
    counts = {"processed": 0, "skipped": 0, "error": 0}
    for r in results:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {**counts, "results": results}


def rebuild_index() -> dict[str, Any]:
    """Stage 3: rebuild `writeups/index.md` as a TABLE.

    The spec names the columns: Title, Vuln Type, Target, Source. `Target`
    is the host the write-up was against, which is not always stated; when
    it is absent the cell says `n/a` rather than being left blank, so a
    reader can tell "not stated" from "not processed yet".

    The table is generated from `writeups/processed/`. The header line is
    preserved (the spec says the index is a table; the existing file's
    title is kept so the artifact still reads as the write-up index).
    """
    rows: list[dict[str, str]] = []
    if PROCESSED_DIR.is_dir():
        for p in sorted(PROCESSED_DIR.glob("*.md")):
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            meta, body = _split_frontmatter(text)
            title = meta.get("title") or p.stem
            class_id = meta.get("class_id") or "unclassified"
            url = meta.get("url", "")
            target = "n/a"
            if url:
                m = re.match(r"https?://([^/]+)", url)
                if m:
                    target = m.group(1)
            src = meta.get("source_path", "")
            source = Path(src).parent.name if src else "unknown"
            rows.append({"title": title, "class_id": class_id,
                         "target": target, "source": source,
                         "path": str(p.relative_to(ROOT))})

    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Write-up Index",
        "",
        f"_Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
        f" — {len(rows)} write-ups._",
        "",
        "| Title | Vuln Type | Target | Source |",
        "|---|---|---|---|",
    ]
    for r in rows:
        lines.append(f"| {r['title']} | {r['class_id']} | {r['target']} "
                     f"| {r['source']} |")
    INDEX_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"total": len(rows), "path": str(INDEX_PATH)}


# ---------------------------------------------------------------------------
# stage 4: lessons
# ---------------------------------------------------------------------------

# The lesson kinds the `/update` spec routes to. `memory/report-lessons.md`
# is the lessons destination; the `memory/targets/<class>.md` checklists are
# generated only for classes appearing 3+ times, per the spec.
LESSON_KINDS = ("methodology", "pattern", "lesson", "target")

# The number of appearances at which a class earns a target checklist.
TARGET_CHECKLIST_THRESHOLD = 3

# A write-up must be at least this long to yield a lesson. A stub with no
# body produces an empty lesson, which teaches nothing and pollutes the
# corpus.
MIN_LESSON_BODY = 80


def _lesson_candidates(title: str, body: str) -> list[dict[str, str]]:
    """Pull candidate lessons out of a processed write-up.

    A lesson is a sentence that states a METHOD or an OBSERVATION, not a
    description of the write-up. Heuristics, in order of preference:

      * a fenced block preceded by a line containing "rule", "lesson",
        "note", "important", "always", "never", "must", "should"
      * a bullet that begins with a capitalised imperative or contains a
        method cue
      * the first substantive paragraph, as a fallback

    Every candidate is marked with the `kind` it routes to.
    """
    out: list[dict[str, str]] = []
    seen: set[str] = set()

    cues = ("rule", "lesson", "note", "important", "always", "never",
            "must", "should", "remember", "takeaway", "key insight")

    # 1. A cue line, plus the paragraph or bullet that follows it.
    lines = body.splitlines()
    for i, line in enumerate(lines):
        low = line.lower()
        if any(c in low for c in cues) and len(line.strip()) > 20:
            text = line.strip().lstrip("#>*- ").strip()
            if len(text) >= MIN_LESSON_BODY:
                k = text.lower()
                if k not in seen:
                    seen.add(k)
                    out.append({"text": text, "kind": "lesson"})

    # 2. Bullets that look like a method.
    for line in lines:
        s = line.strip()
        if not s.startswith(("- ", "* ")):
            continue
        text = s[2:].strip()
        if len(text) < MIN_LESSON_BODY:
            continue
        low = text.lower()
        if any(c in low for c in cues) or re.match(
                r"(check|test|verify|look|try|use|compare|confirm|note)\b",
                low):
            k = text.lower()
            if k not in seen:
                seen.add(k)
                out.append({"text": text, "kind": "pattern"})

    # 3. The first substantive paragraph, as a fallback.
    if not out:
        for para in re.split(r"\n\s*\n", body):
            text = _WS.sub(" ", para).strip()
            if len(text) >= MIN_LESSON_BODY and not text.startswith("#"):
                out.append({"text": text[:600], "kind": "methodology"})
                break

    return out


def extract_lessons(processed_path: str | Path, *,
                    con: Any = None,
                    record: bool = True,
                    verify: bool = True) -> dict[str, Any]:
    """Stage 4: extract lessons from a processed write-up.

    Returns `{"lessons": [...], "recorded": n, "path": ...}`.

    When `con` is given, each lesson is recorded through
    `learning_engine.capture_hook` -- the idempotent capture path -- and
    its `writeup_lesson` row is written so the routing is durable and
    queryable. `capture_hook` is idempotent, so re-running the pipeline
    does not create duplicate lessons.

    VERIFICATION (the `verify` flag).
    --------------------------------
    MEASURED 2026-11-01: the write-up pipeline was the DEAD END of the
    learning workflow. `extract_lessons` captured lessons into the
    canonical `lesson` table in state `captured`, and nothing ever moved
    them on: `verify_hook` was never called from this path. Every reader
    that matters -- `before_recon`, `before_summary`, `_prior_for_signal`
    -- filters on `state='verified'`. So a lesson distilled from a
    published write-up could NEVER influence a hunt. The live database
    showed exactly that: 48 lessons, all `captured`, 0 verified, 0
    `writeup_lesson` rows.

    Worse, the whole function was unreachable from the pipeline: the
    `/update` "all" path ran `write_lessons_markdown()` -- which only
    RENDERS the table -- and never called `extract_lessons` at all. The
    stage that was supposed to capture lessons was never run.

    A PROCESSED WRITE-UP IS THE EVIDENCE. It is a public, published
    account of a vulnerability that was found, reproduced and reported. So
    a lesson distilled from one is verified on the strength of the
    write-up itself, PROVIDED the write-up carries a source URL -- an
    unattributed blob has no provenance to verify against and stays
    `captured`. The class must also be known: a lesson filed under
    `unclassified` cannot be routed to a class skill and so cannot be
    promoted either.

    This does not weaken the gate. `verify_hook` still refuses a lesson
    with no evidence, and the evidence recorded here is the write-up's
    URL, path, title and source -- which is what a reader can go and
    check.
    """
    p = Path(processed_path)
    if not p.is_absolute():
        p = ROOT / p
    if not p.is_file():
        return {"lessons": [], "recorded": 0, "path": str(p),
                "reason": "processed file not found"}
    text = p.read_text(encoding="utf-8", errors="replace")
    meta, body = _split_frontmatter(text)
    title = meta.get("title") or p.stem
    class_id = meta.get("class_id") or "unclassified"
    url = meta.get("url", "")

    # THE VERIFICATION GATE FOR WRITE-UPS.
    #
    # A lesson is promoted only when the write-up it came from names a
    # class and names a source. Without a URL there is nothing a reader
    # can check, so the lesson stays `captured` and stays out of the
    # corpus -- exactly as `verify_hook` intends for an unevidenced claim.
    verifiable = bool(verify and class_id != "unclassified" and url)
    verify_reason = None
    if not verifiable:
        if verify and class_id == "unclassified":
            verify_reason = "the write-up names no class, so the lesson " \
                            "cannot be routed to a class skill"
        elif verify and not url:
            verify_reason = ("the write-up names no source URL, so there is "
                             "no evidence a reader can check")
        else:
            verify_reason = "verification was not requested"

    candidates = _lesson_candidates(title, body)
    lessons: list[dict[str, Any]] = []
    recorded = 0
    verified = 0

    owns = False
    if con is None and record:
        from orch import store as orch_store
        con = orch_store.open_db()
        owns = True
    try:
        if con is not None:
            from learning_engine import engine as le
            le.ensure_schema(con)
            from wks import ownership as _ownership
            with _ownership.owner_write(con, _ownership.WKS):
                for c in candidates:
                    topic = f"{class_id}: {title}"[:200]
                    try:
                        res = le.capture_hook(
                            con, topic=topic, body=c["text"],
                            class_id=None if class_id == "unclassified"
                            else class_id,
                            score=0.3,
                            # A PUBLISHED WRITE-UP IS IMPORTED RESEARCH.
                            #
                            # MEASURED 2026-11-01: this captured the
                            # lesson with no origin, so it defaulted to
                            # UNKNOWN -- and `verify_hook` refuses an
                            # UNKNOWN lesson, so the promotion below
                            # ALWAYS failed. The write-up pipeline
                            # stopped one step short of the corpus.
                            #
                            # A write-up is not a hunt: it did not
                            # produce an impact, so it is not
                            # PRODUCTION_HUNT. But it IS eligible to
                            # become experience -- it is published
                            # research, verified by its own provenance.
                            origin="IMPORTED_RESEARCH",
                            provenance={"source": "writeup",
                                        "path": str(p),
                                        "kind": c["kind"]})
                    except sqlite3_error():
                        continue
                    lesson_key = res.get("lesson_key")
                    if lesson_key:
                        recorded += 1
                    # PROMOTE THE LESSON, IF THE WRITE-UP EARNS IT.
                    promoted = False
                    if lesson_key and verifiable:
                        vres = le.verify_hook(
                            con, lesson_key=lesson_key,
                            evidence={"kind": "published_writeup",
                                      "url": url,
                                      "path": str(p),
                                      "title": title,
                                      "source_path": meta.get("source_path",
                                                              ""),
                                      "content_hash": meta.get(
                                          "content_hash", "")},
                            provenance={"source": "writeup",
                                        "path": str(p),
                                        "kind": c["kind"],
                                        "class_id": class_id})
                        promoted = bool(vres.get("verified"))
                        if promoted:
                            verified += 1
                            # A verified lesson is WORTH MORE. The score is
                            # the corpus's confidence in the lesson, and a
                            # lesson backed by a published write-up starts
                            # above the 0.3 floor that an unverified
                            # capture gets.
                            con.execute(
                                "UPDATE lesson SET score=MAX(score, ?) "
                                "WHERE lesson_key=?", (0.6, lesson_key))
                    wl_key = hashlib.sha256(
                        f"{p}:{c['text']}".encode("utf-8")).hexdigest()[:16]
                    con.execute(
                        "INSERT INTO writeup_lesson(wl_key, source_path,"
                        " class_id, lesson_key, kind, summary, created_at)"
                        " VALUES (?,?,?,?,?,?,?)"
                        " ON CONFLICT(wl_key) DO NOTHING",
                        (wl_key, str(p), class_id, lesson_key, c["kind"],
                         c["text"][:600],
                         datetime.now(timezone.utc).isoformat(timespec="seconds")))
                    lessons.append({"text": c["text"], "kind": c["kind"],
                                    "lesson_key": lesson_key,
                                    "verified": promoted,
                                    "recorded": bool(res.get("created"))})
            # COMMIT THE ROUTING ROWS.
            #
            # MEASURED 2026-11-01: `writeup_lesson` had NO row after a
            # successful extraction, even though the function reported
            # `recorded: 1` and the `lesson` row WAS present. The cause was
            # a missing commit: `capture_hook` commits its own `lesson`
            # insert, so the lesson persisted, but the `writeup_lesson`
            # INSERT that followed it was never committed and was rolled
            # back when the connection closed. The pipeline reported
            # success while the durable routing -- the record that says
            # WHICH write-up produced WHICH lesson -- was silently lost.
            #
            # The routing row is what makes the lesson traceable back to its
            # source, so losing it breaks the provenance chain the learning
            # engine depends on.
            con.commit()
    finally:
        if owns and con is not None:
            con.close()
    return {"lessons": lessons, "recorded": recorded, "verified": verified,
            "verifiable": verifiable, "verify_reason": verify_reason,
            "path": str(p), "class_id": class_id, "title": title,
            "url": url}


def sqlite3_error() -> tuple[type[BaseException], ...]:
    """The exception types a SQLite write can raise.

    Kept as a helper so the except clause above reads cleanly and stays
    correct if the import ever moves.
    """
    import sqlite3
    return (sqlite3.Error,)


def write_lessons_markdown() -> dict[str, Any]:
    """Stage 4b: render the GENERATED section of `memory/report-lessons.md`.

    The `/update` spec says lessons are distilled into
    `memory/report-lessons.md`.

    MEASURED 2026-10-31: the first version of this function REWROTE the
    whole file from the canonical `lesson` table. The table held 10
    `captured` lessons and 0 verified ones, so the generator wrote a file
    saying "0 lessons" -- and DESTROYED the four curated lessons that were
    in the file, which had been distilled by hand from an actual hunt.

    That is the worst kind of generator bug: it is silent, it runs on
    every `/update`, and it deletes hand-curated knowledge that exists
    nowhere else. The curated lessons were recovered from the pre-audit
    backup.

    So the file now has TWO halves:

      * the CURATED half -- hand-written, above the markers. Never
        touched by the generator.
      * the GENERATED half -- between `<!-- BEGIN GENERATED -->` and
        `<!-- END GENERATED -->`. Rewritten from the canonical table.

    A file with no markers gets them added, and nothing is lost: the
    existing content becomes the curated half. The markers are the
    contract that makes the generation non-destructive.

    Only lessons whose state has advanced past `captured` are included:
    a `captured` lesson is an unverified claim, and `AGENTS.md` §11 makes
    `memory/report-lessons.md` a source that must not be polluted with
    unverified material.
    """
    from orch import store as orch_store
    from learning_engine import engine as le
    con = orch_store.open_db()
    try:
        le.ensure_schema(con)
        rows = con.execute(
            "SELECT topic, body, class_id, score, state FROM lesson"
            " WHERE state != 'captured' ORDER BY class_id, score DESC"
        ).fetchall()
        groups: dict[str, list[Any]] = {}
        for r in rows:
            groups.setdefault(r["class_id"] or "general", []).append(r)
    finally:
        con.close()

    LESSONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    existing = (LESSONS_PATH.read_text(encoding="utf-8")
                if LESSONS_PATH.is_file() else "")

    block_lines = [
        f"_Generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}"
        f" — {len(rows)} lessons from the canonical store._",
        "",
    ]
    if not rows:
        block_lines.append(
            "_No lessons have been promoted past `captured` yet._")
    else:
        for class_id in sorted(groups):
            block_lines.append(f"## {class_id}")
            block_lines.append("")
            for r in groups[class_id]:
                body = _WS.sub(" ", r["body"]).strip()
                block_lines.append(f"- **{r['topic']}** — {body}")
                block_lines.append(f"  - state: `{r['state']}`, score: {r['score']}")
            block_lines.append("")
    block = "\n".join(block_lines).rstrip()

    if BEGIN_GENERATED in existing and END_GENERATED in existing:
        pattern = re.compile(
            re.escape(BEGIN_GENERATED) + r".*?" + re.escape(END_GENERATED),
            re.DOTALL)
        new = pattern.sub(
            lambda _m: f"{BEGIN_GENERATED}\n{block}\n{END_GENERATED}",
            existing, count=1)
    else:
        # No markers: ADD them below the existing content, so nothing that
        # is already in the file is lost.
        head = existing.rstrip()
        new = (head + "\n\n" if head else "") + \
            f"{BEGIN_GENERATED}\n{block}\n{END_GENERATED}\n"
    LESSONS_PATH.write_text(new, encoding="utf-8")
    return {"lessons": len(rows), "classes": len(groups),
            "path": str(LESSONS_PATH),
            "note": ("the generated section is rewritten; the curated "
                     "section above the markers is preserved")}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def propose_research(con: Any = None) -> dict[str, Any]:
    """Turn the corpus's open gaps into concrete research proposals.

    MEASURED 2026-11-01: `research_hook` -- the step that turns a gap
    into a persisted research task -- had no production caller. The
    learning workflow's chain was: capture (wired), analyze (wired at the
    close of a hunt), and then STOP. A gap was named and never turned into
    work.

    The `/update` pipeline is where research is scheduled: it already
    fetches public sources and processes them into lessons. A gap that has
    been named by a hunt is exactly the thing an update run should try to
    close.

    Only OPEN gaps are proposed. A gap that already has a proposal stays
    proposed: `research_hook` is idempotent, so re-running the pipeline
    does not create a second task for the same gap.

    Best-effort: the pipeline's other stages do not depend on this one.
    """
    owns = False
    if con is None:
        from orch import store as orch_store
        con = orch_store.open_db()
        owns = True
    try:
        from learning_engine import engine as le
        from wks import ownership as _ownership
        le.ensure_schema(con)
        gaps = con.execute(
            "SELECT gap_key, class_id, kind, detail FROM learning_gap"
            " WHERE status='open' ORDER BY created_at").fetchall()
        proposed = []
        # `learning_gap` and `learning_research` are KNOWLEDGE tables, so
        # the writes go through the owner's context. The read above does
        # not need it.
        with _ownership.owner_write(con, _ownership.WKS):
            for g in gaps:
                if not g["class_id"]:
                    # A gap with no class cannot be routed to a class skill,
                    # so a research task for it would have no destination.
                    continue
                r = le.research_hook(
                    con, gap_key=g["gap_key"], class_id=g["class_id"],
                    objective=(f"Close the {g['kind']} gap for class "
                               f"{g['class_id']}: {g['detail']}. Gather cited, "
                               f"quoted evidence and record the lesson with "
                               f"that evidence."))
                proposed.append({"gap_key": g["gap_key"],
                                 "class_id": g["class_id"],
                                 "research_key": r.get("research_key"),
                                 "created": bool(r.get("created")),
                                 "status": r.get("status")})
        return {"open_gaps": len(gaps), "proposed": len(proposed),
                "created": sum(1 for p in proposed if p["created"]),
                "results": proposed}
    finally:
        if owns and con is not None:
            con.close()


def all_stages() -> dict[str, Any]:
    """Run the whole pipeline: process -> index -> lessons -> briefing.

    The briefing refresh is LAST because it reports the knowledge counts
    the previous stages produced. If it ran first, the briefing would
    describe the corpus as it was BEFORE the pipeline ran, which is the
    staleness this stage exists to remove.

    MEASURED 2026-10-31: the `/update` spec's stage (g) -- "Update
    timestamp + knowledge count in agent-briefing.md -- static sections
    PRESERVED, never overwritten" -- had no implementation. `writeups/
    briefing.py` is it.

    STAGE 4 CAPTURES; STAGE 4b RENDERS.
    -----------------------------------
    MEASURED 2026-11-01: this function ran `write_lessons_markdown()` --
    which RENDERS the `lesson` table into `memory/report-lessons.md` --
    but never called `extract_lessons()`, which CAPTURES lessons into
    that table. So the stage that was supposed to learn from write-ups
    never ran: `/update` regenerated the report from whatever was already
    in the table and added nothing to it. The live database confirmed it:
    48 lessons, all `captured`, 0 verified, 0 `writeup_lesson` rows, and
    not one processed write-up behind any of them.

    The order matters and is now explicit: capture FIRST, then render.
    Rendering before capturing would write a file that omits the lessons
    the same run just extracted.
    """
    proc = process_all()
    idx = rebuild_index()
    ext = extract_all_lessons()
    les = write_lessons_markdown()
    research = propose_research()
    from writeups import briefing as briefing_mod
    brief = briefing_mod.refresh(apply=True)
    return {"process": {k: v for k, v in proc.items() if k != "results"},
            "index": idx, "extract": ext, "lessons": les,
            "research": research, "briefing": brief}


def extract_all_lessons(processed_dir: str | Path | None = None, *,
                        con: Any = None) -> dict[str, Any]:
    """Run `extract_lessons` over every processed write-up.

    This is the stage that actually feeds the corpus. `all_stages` calls
    it after `process_all` has produced the processed files, so a write-up
    that was just processed has its lessons captured in the same run.

    A file that fails to yield a lesson is reported, not swallowed: a
    write-up that produced nothing is either empty or has no extractable
    lesson, and the operator should be able to tell which.
    """
    d = Path(processed_dir) if processed_dir else PROCESSED_DIR
    if not d.is_absolute():
        d = ROOT / d
    owns = False
    if con is None:
        from orch import store as orch_store
        con = orch_store.open_db()
        owns = True
    results: list[dict[str, Any]] = []
    try:
        if d.is_dir():
            for p in sorted(d.glob("*.md")):
                r = extract_lessons(p, con=con)
                results.append({"path": r.get("path"),
                                "title": r.get("title"),
                                "class_id": r.get("class_id"),
                                "recorded": r.get("recorded", 0),
                                "verified": r.get("verified", 0),
                                "verifiable": r.get("verifiable"),
                                "verify_reason": r.get("verify_reason")})
    finally:
        if owns and con is not None:
            con.close()
    return {"files": len(results),
            "recorded": sum(r["recorded"] for r in results),
            "verified": sum(r["verified"] for r in results),
            "results": results}


def main(argv: Iterable[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(
        description="Process write-ups: raw -> processed -> index -> lessons.")
    ap.add_argument("stage", nargs="?", default="all",
                    choices=("all", "process", "index", "extract", "lessons",
                             "research"),
                    help="which stage to run")
    ap.add_argument("--path", help="a single file (for `process`)")
    ap.add_argument("--json", action="store_true",
                    help="print the result as JSON")
    args = ap.parse_args(list(argv) if argv is not None else None)

    if args.stage == "process":
        if args.path:
            result = process_one(args.path)
        else:
            result = process_all()
    elif args.stage == "index":
        result = rebuild_index()
    elif args.stage == "extract":
        # CAPTURE: move the processed write-ups into the lesson table.
        result = extract_all_lessons()
    elif args.stage == "lessons":
        # RENDER: write the lesson table into `memory/report-lessons.md`.
        result = write_lessons_markdown()
    elif args.stage == "research":
        # PROPOSE: turn the corpus's open gaps into research tasks.
        result = propose_research()
    else:
        result = all_stages()

    if args.json:
        print(json.dumps(result, indent=2, default=str))
    else:
        for k, v in result.items():
            if k == "results":
                for r in v:
                    # The process stage reports `status`/`reason`; the
                    # extract stage reports `verified`/`verify_reason`; the
                    # research stage reports `class_id`/`status`. Print
                    # whichever the row actually carries rather than
                    # assuming one shape.
                    if "status" in r and "title" in r:
                        print(f"  {r['status']:9s} {r.get('reason',''):18s} "
                              f"{r.get('title') or r.get('path','')}")
                    elif "verified" in r:
                        print(f"  {'ok' if r.get('verified') else 'held':9s} "
                              f"{r.get('verify_reason') or '':18s} "
                              f"{r.get('title') or r.get('path','')} "
                              f"(recorded={r.get('recorded', 0)} "
                              f"verified={r.get('verified', 0)})")
                    elif "class_id" in r:
                        print(f"  {r.get('status','proposed'):9s} "
                              f"{r.get('class_id',''):18s} "
                              f"gap={r.get('gap_key','')}")
                    else:
                        print(f"  {r}")
            elif isinstance(v, dict):
                print(f"{k}: {v}")
            else:
                print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
