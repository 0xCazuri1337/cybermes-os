"""Research → validation → curation pipeline.

Security posture (brief §26): external text is DATA, never INSTRUCTIONS.
`sanitize()` strips anything shaped like an instruction to an agent, and the
ingest path only ever stores extracted claims that a curator passed in
explicitly. This module performs no target testing; it fetches documentation.

Canonical host diversity is enforced at the seed level (see verify_seed), because
that is the cheapest place to prevent an unpassable gate.
"""
from __future__ import annotations

import hashlib
import html as html_mod
import json
import re
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

from . import config, quality, store

USER_AGENT = "WKS-Research/1.0 (knowledge curation; contact: local)"
FETCH_TIMEOUT = 25

# Text that tries to steer an agent. Quarantined on sight, never executed.
_INJECTION = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+instructions"
    r"|disregard\s+(the\s+)?(system|previous)\s+prompt"
    r"|you\s+are\s+now\s+a\b"
    r"|new\s+instructions?\s*:"
    r"|reveal\s+your\s+system\s+prompt"
    r"|<\s*/?\s*(system|instructions?)\s*>"
    r"|\{\{\s*(system|instructions?)\s*\}\}"
    r"|do\s+not\s+tell\s+the\s+user)",
    re.IGNORECASE,
)

# Sources whose published page is a client-rendered SPA: the served HTML is a
# shell and the prose only exists after JavaScript runs. WSTG (owasp.org
# www-project-web-security-testing-guide) is the case that bit us — the
# rendered page looks empty to a plain HTTP fetch, so a research agent using a
# rendering fetcher sees the text while `pipeline.fetch` does not, and every
# quote from that page is then unverifiable.
#
# For these, quote verification falls back to the upstream source of truth: the
# file the site is built from. Same words, no JavaScript, stable URL.
_JS_RENDERED = (
    ("owasp.org/www-project-web-security-testing-guide",
     "https://raw.githubusercontent.com/OWASP/wstg/master/document/"),
)

_TAG = re.compile(r"<[^>]+>")
_WS = re.compile(r"[ \t\r\f\v]+")
_NL = re.compile(r"\n{3,}")


def _mirror_for(url: str) -> str | None:
    """A non-JS mirror of a client-rendered page, if one exists."""
    for marker, base in _JS_RENDERED:
        if marker not in url:
            continue
        tail = url.split(marker, 1)[1].lstrip("/")
        tail = re.sub(r"/index\.html?$", "/", tail)
        tail = re.sub(r"^(stable|latest)/", "", tail)
        # The upstream tree stores these as .md. Strip whatever extension the
        # site URL carries and append .md exactly once. An earlier version did
        # `.md` -> `.html` -> `.md`, which round-tripped a missing extension
        # back to nothing and 404'd on the mirror.
        tail = re.sub(r"\.(html?|md)$", "", tail)
        if tail and not tail.startswith("http"):
            return base + tail + ".md"
    return None



def extract_text(raw: bytes, ctype: str) -> str:
    """Bytes + content-type -> the prose a quote is matched against.

    Extracted as its own function because the retry layer (`wks.http`) must
    parse a response body with the SAME rules the verifier matches quotes
    against. Two implementations of "the text of a page" is how a genuine quote
    silently stops verifying: one side strips entities, the other does not, and
    the gate reports fabrication.

    Order matters and is preserved from the original inline code: decode
    entities BEFORE stripping tags (`&#x27;` and `&quot;` survive tag-stripping
    as literal escapes, so a quote containing an apostrophe copied from a
    rendered page would never match its own source), then unescape again
    because entities also appear inside attributes.
    """
    ctype_l = (ctype or "").lower()
    # PDFs are not prose in the byte stream, but standards and vendor
    # advisories are frequently published only as PDFs. Treating every PDF as
    # binary made a legitimate standard impossible to quote even when the exact
    # sentence is on the page. Extract text with a bounded, non-executing parser
    # before the binary guard; a malformed or image-only PDF still degrades to
    # the honest "no prose" result.
    if "application/pdf" in ctype_l or raw[:5] == b"%PDF-":
        try:
            import io as _io
            from pypdf import PdfReader
            reader = PdfReader(_io.BytesIO(raw))
            chunks: list[str] = []
            total = 0
            for page in reader.pages[:80]:
                part = page.extract_text() or ""
                chunks.append(part)
                total += len(part)
                if total > 2_000_000:
                    break
            text = html_mod.unescape("\n".join(chunks))
            return _NL.sub("\n\n", _WS.sub(" ", text)).strip()
        except Exception:
            return ""
    # Decode everything that is not explicitly binary. The old guard only
    # decoded when the type contained "html"/"text" or was empty, so
    # `application/x-txt` (and json/csv/yaml) silently yielded an EMPTY
    # string and every quote taken from it failed as "no evidence".
    _BINARY = ("image/", "video/", "audio/", "font/", "application/octet-stream",
               "application/zip", "application/gzip",
               "application/x-tar", "application/x-7z", "application/x-rar")
    is_binary = any(b in ctype_l for b in _BINARY)
    if is_binary:
        # MEASURED 2026-10-03: this branch did not exist, so `text` was left
        # unbound and line 109 raised `UnboundLocalError` for EVERY pdf, zip,
        # image and font URL. `fetch()` is documented to never raise -- a dead
        # source is data, not an exception -- and instead of returning a dead
        # source it took down the caller. It surfaced while probing NIST SP
        # 800-40 (a .pdf), so two normative sources were scored UNUSABLE for a
        # reason that had nothing to do with them.
        #
        # A binary body has no prose to quote. Returning "" makes the item
        # unreadable rather than unverifiable, which is the honest outcome and
        # keeps the "no evidence" signal distinct from "evidence was rejected".
        return ""
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    text = html_mod.unescape(text)
    # Tag-stripping is decided by the CONTENT TYPE, not by the document's own
    # characters. A markdown/plain source can legitimately contain literal
    # tags as CONTENT -- an XSS cheat sheet is mostly
    # `<script>alert(1)</script>` inside backticks -- and stripping those
    # destroys the very span a quote needs to match, so a verbatim quote was
    # reported as FABRICATED. Only HTML is stripped.
    is_markdown = any(m in ctype_l for m in (
        "markdown", "text/plain", "plain", "x-txt", "x-markdown",
        "text/x-", "x-sh", "csv", "json", "yaml", "xml-plain"))
    looks_markdown = not is_markdown and any(
        s in text[:4000] for s in ("```", "|---", "](", "**", "\n#"))
    if not is_markdown and not looks_markdown \
            and "<" in text[:2000] and ">" in text[:2000]:
        text = _TAG.sub(" ", text)
        text = html_mod.unescape(text)
    return _NL.sub("\n\n", _WS.sub(" ", text)).strip()


def _looks_like_shell(text: str) -> bool:
    """True when a page fetched fine but contains no prose.

    Threshold is deliberately crude: an SPA shell is typically well under 20KB
    of de-tagged text and is dominated by script/style residue. The check only
    decides whether to ALSO try a mirror — a false positive costs one extra
    request, and a false negative is caught downstream as a failed quote.
    """
    if len(text) > 20_000:
        return False
    if "localStorage" in text or "matchMedia" in text or "<script" in text:
        return True
    # Little text and none of it sentence-shaped.
    words = text.split()
    return len(words) > 40 and sum(1 for w in words if w.endswith(".")) < 5


def _fetch_plain(url: str, limit: int) -> dict[str, Any]:
    """Fetch a non-HTML (markdown/plain) source. No tag-stripping."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            raw = r.read(limit)
            status = int(r.status)
    except Exception as e:
        return {"ok": False, "status": None, "text": "",
                "error": f"{type(e).__name__}: {e}"}
    text = raw.decode("utf-8", errors="replace")
    return {"ok": status < 400, "status": status, "text": text}



def fetch_json(url: str) -> Any:
    """Fetch and parse a JSON document. Returns None on any failure."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as r:
            return json.loads(r.read().decode("utf-8", errors="replace"))
    except Exception:
        return None


def sanitize(text: str) -> tuple[str, list[str]]:
    """Return (clean_text, findings). Data is stripped of steering attempts."""
    findings: list[str] = []
    for m in _INJECTION.finditer(text or ""):
        findings.append(f"INJECTION:{m.group(0)[:60]}")
    clean = _INJECTION.sub("[removed-prompt-injection]", text or "")
    return clean, findings


def host_of(url: str) -> str:
    h = (urlparse(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def fetch(url: str, *, limit: int = 400_000, quote: str | None = None,
          resolve_moved: bool = True) -> dict[str, Any]:
    """Fetch a documentation page. Returns text plus integrity signals.

    Never raises on network failure -- a dead source is data (`http_status`),
    and recording it is more useful than an exception.

    MEASURED 2026-10-02: this function had no 429 branch, no `Retry-After`, no
    backoff and no per-host pacing, so a throttled host produced items that read
    as permanently unverifiable. The request/retry/state half now lives in
    `wks.http`; this function owns the TEXT half -- entity decoding, tag
    stripping, sanitising, the JS-shell mirror and the quote-gated 404 resolver
    -- because a quote is matched against exactly these bytes.

    `access_state` is one of `wks.http.ACCESS_STATES` and is persisted to the
    store on ingest, so a walled or rate-limited source becomes a recorded fact
    rather than an undocumented surprise.

    `resolve_moved=False` is for the resolver's own candidate probes. Without
    it, a 404 candidate calls the resolver again, which probes more candidates,
    each of which can recurse: a dead section became an unbounded fetch loop.
    """
    from wks import transport as _http

    got = _http.fetch_raw(url, limit=limit)

    # A 404 is not evidence that content is gone -- documentation gets
    # reorganised. The resolver finds the successor and only accepts one that
    # ACTUALLY CONTAINS the span being verified, so this can never launder a
    # citation onto an unrelated live page. `moved_from` records the URL that
    # was cited, so provenance shows "verified here, cited there".
    if got.get("status") == 404 and resolve_moved:
        moved = _resolve_moved(url, quote, limit)
        if moved is not None:
            got.update(moved)
            got["access_state"] = "ACTIVE"
            return got

    text = extract_text(got.get("raw", b""), got.get("content_type", ""))
    text, findings = sanitize(text)

    # A rendered page can be a shell: HTTP 200, nav chrome, no prose. For those,
    # quote verification falls back to the upstream source file. `mirror`
    # records which URL actually supplied the text, because the cited URL and
    # the URL that answered then differ and the difference must be auditable.
    mirror = None
    if got.get("status") is not None and 200 <= got["status"] < 300:
        if _looks_like_shell(text):
            alt = _mirror_for(url)
            if alt and alt != url:
                m = _fetch_plain(alt, limit)
                if m["ok"] and len(m["text"]) > 2000:
                    mtext, mfind = sanitize(m["text"])
                    mirror = alt
                    text = mtext
                    findings = findings + mfind
                    got["access_state"] = "ACTIVE"
                    got["cited_access_state"] = "BROWSER_REQUIRED"

    got["text"] = text
    got["ok"] = got.get("access_state") == "ACTIVE"
    got["mirror"] = mirror
    got["moved_from"] = got.get("moved_from")
    got["injection_findings"] = findings
    got["content_hash"] = (hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]
                           if text else None)
    return got


def _resolve_moved(url: str, quote: str | None, limit: int) -> dict[str, Any] | None:
    """Quote-gated successor lookup for a 404, or None if nothing verifies."""
    try:
        from wks import resolver as _resolver
        moved = _resolver.resolve(url, quote)
        if not moved.get("resolved"):
            return None
        mirror = moved["resolved"]
        got = fetch_raw_guarded(mirror, limit)
        if got.get("access_state") != "ACTIVE":
            return None
        text = extract_text(got.get("raw", b""), got.get("content_type", ""))
        text, findings = sanitize(text)
        if len(text) <= 2000:
            return None
        return {"url": url, "text": text, "mirror": mirror, "moved_from": url,
                "cited_status": 404, "content_type": "",
                "access_state": "ACTIVE", "injection_findings": findings,
                "content_hash": hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]}
    except Exception:
        # The resolver being unavailable is not a reason to lose the page; the
        # caller falls back to reporting the 404 honestly.
        return None


def fetch_raw_guarded(url: str, limit: int) -> dict[str, Any]:
    from wks import transport as _http
    return _http.fetch_raw(url, limit=limit)



def probe(url: str, *, method: str = "GET", timeout: int = 15) -> dict[str, Any]:
    """Liveness probe for a source URL.

    Uses GET, never HEAD: portswigger.net answers HEAD with 404 on pages that
    return 200 to GET, so a HEAD-based check reports ~20 dead seeds that are
    all alive and would send the research loop chasing the wrong URLs. The GET
    body is discarded immediately — this checks existence, not content.
    """
    req = urllib.request.Request(
        url, method=method, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            if method == "GET":
                r.read(2048)  # confirm a body follows, then drop the connection
            return {"url": url, "status": int(r.status), "ok": int(r.status) < 400}
    except urllib.error.HTTPError as e:
        return {"url": url, "status": int(e.code), "ok": False,
                "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"url": url, "status": None, "ok": False,
                "error": f"{type(e).__name__}: {e}"}


def verify_seed(seeds: dict[str, list[str]]) -> dict[str, Any]:
    """Audit a seed set before spending research time on it.

    Two failure modes are worth catching up front, both learned the hard way:
      * fewer than 2 publisher hosts per class -> the corroboration gate can
        never pass for that class, no matter how much research follows;
      * URLs that 404 -> a dead seed is worse than none, because it looks
        configured.
    """
    report: dict[str, Any] = {"classes": {}, "ok": True}
    for cid, urls in seeds.items():
        hosts = {host_of(u) for u in urls}
        dead = []
        for u in urls:
            if not probe(u)["ok"]:
                dead.append(u)
        entry = {
            "n_urls": len(urls), "hosts": sorted(hosts),
            "n_hosts": len(hosts), "dead": dead,
            "corroboration_possible": len(hosts) >= config.MIN_PUBLISHER_HOSTS,
        }
        report["classes"][cid] = entry
        if not entry["corroboration_possible"]:
            report["ok"] = False
    report["n_dead"] = sum(len(e["dead"]) for e in report["classes"].values())
    return report


def ingest_claim(
    con: sqlite3.Connection,
    *,
    item_key: str,
    class_id: str,
    claim: str,
    kind: str,
    sources: list[dict[str, Any]],
    body: str | None = None,
    disproof: str | None = None,
    surface: str | None = None,
    severity_hint: str | None = None,
    hunting_value: int = 3,
    origin: str | None = None,
) -> dict[str, Any]:
    """Store one researched claim with its provenance, then gate it.

    `sources` entries: {url, source_type, title?, publisher?, quote?, locator?, http_status?}
    """
    if store.get_class(con, class_id) is None:
        raise LookupError(f"unknown class {class_id}; register it first")

    body_clean, findings = sanitize(body or "")
    claim_clean, cf = sanitize(claim)
    findings += cf

    item_id = store.add_item(
        con, item_key, class_id, claim_clean, kind,
        surface=surface, severity_hint=severity_hint,
        hunting_value=hunting_value, body=body_clean or None, disproof=disproof,
        origin=origin,
    )
    for s in sources:
        url = s.get("url")
        if not url:
            continue
        sid = store.upsert_source(
            con, url, host_of(url),
            title=s.get("title"), publisher=s.get("publisher") or host_of(url),
            source_type=s.get("source_type", "writeup"),
            http_status=s.get("http_status"),
            content_hash=s.get("content_hash"),
            notes=("; ".join(findings) or None),
        )
        store.link_source(con, item_id, sid,
                          quote=sanitize(s.get("quote") or "")[0] or None,
                          locator=s.get("locator"))
    con.commit()
    verdict = quality.assess(con, item_id)
    store.set_state(con, item_id, verdict["state"], verdict["score"], verdict["reasons"])
    con.commit()
    verdict["injection_findings"] = findings
    return verdict


def markdown_report(con: sqlite3.Connection, class_id: str) -> str:
    """Human-readable projection of one class. Markdown is the readable layer;
    the DB stays canonical (§13)."""
    from .retrieval import class_digest
    d = class_digest(con, class_id)
    m = d["maturity"]
    lines = [
        f"# {d['name']}",
        "",
        f"> surface: `{d['surface']}` · CWE: {d['cwe'] or '—'} · "
        f"OWASP: {d['owasp'] or '—'}",
        f"> maturity: **{m['state']}** — {m['n_items']} items, "
        f"{m['n_supported']} supported, {m['n_fp']} FP rules, "
        f"{m['n_chains']} chains",
        "",
        d["summary"] or "",
        "",
    ]
    if d["aliases"]:
        lines += ["**Aliases:** " + ", ".join(d["aliases"]), ""]
    order = ["prerequisite", "signal", "technique", "test", "validation",
             "fp_rule", "evidence", "impact", "variant", "bypass", "chain_link"]
    kinds = [k for k in order if k in d["by_kind"]] + \
            [k for k in d["by_kind"] if k not in order]
    for k in kinds:
        lines.append(f"## {k.replace('_', ' ').title()}")
        lines.append("")
        for it in d["by_kind"][k]:
            lines.append(f"- **{it['claim']}**  ")
            lines.append(f"  `{it['state']}` · score {it['score']}"
                         + (f" · disproved by: {it['disproof']}"
                            if it.get("disproof") else ""))
            if it["sources"]:
                lines.append("  sources: " +
                             " · ".join(f"<{u}>" for u in it["sources"]))
        lines.append("")
    if d["false_positives"]:
        lines += ["## False-positive rules", ""]
        for f in d["false_positives"]:
            lines += [
                f"- **Hypothesis:** {f['hypothesis']}",
                f"  - **Invalidated by:** {f['invalidated_by']}",
                f"  - **Rule:** {f['rejection_rule']}",
                "",
            ]
    if d["related_classes"]:
        lines += ["## Related classes (via chains)", ""]
        lines += [f"- `{r['class_id']}` {r['name']} ({r['chains']} chains)"
                  for r in d["related_classes"]]
        lines.append("")
    if m["missing"]:
        lines += ["## Known gaps", "",
                  "Not yet satisfied: " + ", ".join("`" + x + "`" for x in m["missing"]), ""]
    _marker = "<!-- GENERATED from db/wks.db — do not edit -->"
    body = "\n".join(lines)
    if not body.lstrip().startswith(_marker):
        body = _marker + chr(10) + body
    return body


def write_class_markdown(con: sqlite3.Connection, class_id: str) -> Path | None:
    """Write the readable projection. Returns the path, or None if unchanged.

    The digest is the db's evidence rendered as prose, so it belongs beside the
    canonical class page in the class's own `knowledge/` directory. It is a
    PROJECTION: R11 forbids hand-editing it, and deleting it costs nothing but
    a regeneration.
    """
    from . import domains as _domains
    # Output path comes from `config.root()`, content from `con`. A mismatched
    # connection would project a foreign corpus onto the canonical tree --
    # MEASURED 2026-10-31, see wks.project.assert_canonical_connection.
    from .project import assert_canonical_connection
    assert_canonical_connection(con)
    out = _domains.class_dir(class_id, con) / "DIGEST.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    content = markdown_report(con, class_id)
    # Idempotent by design: a projection that rewrites identical bytes every
    # cycle makes "regenerated N documents" meaningless as a change signal.
    if out.exists() and out.read_text(encoding="utf-8") == content:
        return None
    out.write_text(content, encoding="utf-8")
    # BUG FIXED (measured by wks.project T22): this wrote the DIGEST path into
    # `bug_class.skill_path`. Two writers, two different files, ONE column -- so
    # whichever ran last won, and the two clobbered each other on every cycle.
    # The visible symptom was a non-idempotent projection: refreshing the digest
    # made `skill_path` point at the digest, which then made skillgen re-render
    # and rewrite `skill_path`, so an UNCHANGED corpus reported `knowledge` and
    # `skill` as changed on every single call.
    #
    # It also corrupted the column the auditors read: `quality.maturity` treats
    # a non-empty `skill_path` as "the class HAS a skill", so a class whose
    # digest had been written but whose skill had never been generated would
    # report `skill` as satisfied. Existence of a digest was standing in for
    # existence of a skill.
    #
    # `skill_path` belongs to skillgen alone. The digest needs no column: it is
    # deterministic from class_rel(), so nothing needs to remember where it is.
    return out


def next_tasks(con: sqlite3.Connection, limit: int = 10) -> list[dict[str, Any]]:
    """Generate follow-up work from measured gaps (§19, §30)."""
    created: list[dict[str, Any]] = []
    for g in quality.gap_report(con):
        cid = g["class_id"]
        if g["n_items"] == 0:
            tasks = [(f"seed.{cid}.research", "Research and gate the first "
                      f"evidence-backed items for {cid}",
                      ">=5 items with >=2 publisher hosts each", 1)]
        else:
            tasks = []
            if not g["checks"]["supported_items"]:
                tasks.append((f"{cid}.corroborate",
                              f"Add independent corroboration for {cid} items "
                              f"currently blocked on publisher hosts",
                              "no INSUFFICIENT_PUBLISHER_HOSTS in gate_reasons", 2))
            if not g["checks"]["fp_rules"]:
                tasks.append((f"{cid}.fp",
                              f"Capture false-positive rules for {cid}",
                              ">=2 fp_case rows with rejection_rule", 4))
            if not g["checks"]["chain"]:
                tasks.append((f"{cid}.chain",
                              f"Research and justify a chain involving {cid}",
                              "chain_step rows with non-empty `why`", 5))
            if not g["checks"]["methodology"]:
                tasks.append((f"{cid}.methodology",
                              f"Write the hunting methodology for {cid}",
                              "methodology md with a disproof clause per step", 3))
            if not g["checks"]["skill"]:
                tasks.append((f"{cid}.skill",
                              f"Generate the independent skill for {cid}",
                              "skill dir with SKILL.md + version history", 3))
        for key, objective, artifact, prio in tasks:
            store.add_task(con, key, objective, artifact,
                           class_id=cid, priority=prio)
            created.append({"task_key": key, "class_id": cid,
                            "priority": prio, "objective": objective})
    con.commit()
    return created[:limit]
